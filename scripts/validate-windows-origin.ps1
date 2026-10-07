param(
    [string]$Cli = "",
    [string]$WorkRoot = "",
    [string]$ReportPath = ""
)

# Windows-origin gate. Where validate-windows-vhd.ps1 judges StarConverter's output from pinned
# StarConverter-built sources, this script starts from volumes that Windows itself formatted and
# populated on this host, converts them with the CLI, and asks the Windows filesystem drivers
# whether the result (and the escrow-restored round trip) serves the same files, bytes, and NTFS
# security descriptors. Nothing here is pinned by hash: Windows chooses serials, GUIDs, and
# timestamps at run time, so each case records what it saw and the report verifier checks the
# invariants rather than fixed bytes.
#
# Only regular fixed-VHD files under the work root are attached. Writable attachment is used
# solely to populate the freshly formatted source volumes; every candidate is attached read-only
# without a drive letter and is re-hashed after detach. No physical disk is discovered, selected,
# or touched.

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-One {
    param(
        [Parameter(Mandatory = $true)][object[]]$Values,
        [Parameter(Mandatory = $true)][string]$Description
    )
    if ($Values.Count -ne 1) {
        throw "Expected exactly one $Description, found $($Values.Count)"
    }
    return $Values[0]
}

function Test-HasDriveLetter {
    param([AllowNull()][object]$Letter)
    if ($null -eq $Letter) {
        return $false
    }
    $text = ([string]$Letter).Trim([char]0)
    return -not [string]::IsNullOrWhiteSpace($text)
}

function Write-Line {
    param([string]$Text)
    Write-Host "[ORIGIN] $Text"
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Get-BytesSha256 {
    param([byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString("X2") }) -join "")
    }
    finally {
        $sha.Dispose()
    }
}

if (-not (Test-IsAdministrator)) {
    throw "Windows-origin validation requires an elevated PowerShell 5.1 prompt."
}
if ([string]::IsNullOrWhiteSpace($env:windir) -and -not [string]::IsNullOrWhiteSpace($env:SystemRoot)) {
    $env:windir = $env:SystemRoot
}
Import-Module Storage -ErrorAction Stop

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($Cli)) {
    $Cli = Join-Path $repoRoot "target\debug\starconverter.exe"
}
$cliPath = (Resolve-Path -LiteralPath $Cli).Path
if ([string]::IsNullOrWhiteSpace($WorkRoot)) {
    $WorkRoot = Join-Path $repoRoot "target\windows-origin"
}
$null = New-Item -ItemType Directory -Path $WorkRoot -Force
$workDirectory = (Resolve-Path -LiteralPath $WorkRoot).Path
if ($workDirectory.StartsWith("\\")) {
    throw "Network work paths are refused: $workDirectory"
}

$reportFullPath = $null
if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
    if ($ReportPath.StartsWith("\\")) {
        throw "Network report paths are refused: $ReportPath"
    }
    $reportFullPath = [IO.Path]::GetFullPath($ReportPath)
    if ([IO.Path]::GetExtension($reportFullPath) -ine ".json") {
        throw "The machine-readable report path must end in .json: $reportFullPath"
    }
    $reportParent = [IO.Path]::GetDirectoryName($reportFullPath)
    if ([string]::IsNullOrWhiteSpace($reportParent) -or -not [IO.Directory]::Exists($reportParent)) {
        throw "The report parent directory must already exist: $reportParent"
    }
    if ([IO.File]::Exists($reportFullPath)) {
        throw "Refusing to replace an existing machine-readable report: $reportFullPath"
    }
}

# 40 MiB fixed VHD: 512-byte footer after the disk bytes, one MBR partition at 1 MiB running to
# the end of the disk. These are the same numbers the windows-vhd probe's control VHDs use.
$vhdMaximumMiB = 40
$diskBytes = [long]$vhdMaximumMiB * 1MB
$vhdBytes = $diskBytes + 512
$partitionOffset = [long]1MB
$partitionBytes = $diskBytes - $partitionOffset

# Payload corpus: bytes are (seed + offset) % 251 so every stream is reproducible from the
# manifest alone. Names are spelled from code points so this script stays ASCII.
$omega = [char]0x03A9
$depth = "$([char]0x6DF1)$([char]0x5EA6)"
$rocket = [char]::ConvertFromUtf32(0x1F680)
$sharpS = [char]0x00DF
$payloadSpecs = @(
    [pscustomobject]@{ Path = "readme.txt"; Length = 14; Seed = 1 },
    [pscustomobject]@{ Path = "alpha\empty.dat"; Length = 0; Seed = 2 },
    [pscustomobject]@{ Path = "alpha\${omega}mega\fragmented.bin"; Length = 6000; Seed = 3 },
    [pscustomobject]@{ Path = "alpha\${omega}mega\sector.bin"; Length = 4096; Seed = 4 },
    [pscustomobject]@{ Path = "alpha\${omega}mega\cluster-plus-one.bin"; Length = 4097; Seed = 5 },
    [pscustomobject]@{ Path = "deep\$depth\two-cluster-minus-one.bin"; Length = 8191; Seed = 6 },
    [pscustomobject]@{ Path = "deep\$depth\rocket-$rocket.bin"; Length = 33; Seed = 7 },
    [pscustomobject]@{ Path = "Stra${sharpS}e.txt"; Length = 65; Seed = 8 },
    [pscustomobject]@{ Path = "secured\denied.bin"; Length = 512; Seed = 9 }
)
# Objects whose NTFS security descriptor is deliberately not the inherited default, so the round
# trip must carry a descriptor Windows allocated at run time rather than one `format` wrote.
$explicitAclPaths = @("secured", "secured\denied.bin")
$guestsSid = New-Object Security.Principal.SecurityIdentifier("S-1-5-32-546")

function New-PayloadBytes {
    param([int]$Length, [int]$Seed)
    $bytes = New-Object byte[] $Length
    for ($index = 0; $index -lt $Length; $index++) {
        $bytes[$index] = [byte](($Seed + $index) % 251)
    }
    # The unary comma keeps the pipeline from unrolling a zero-length array into $null.
    return , $bytes
}

function Invoke-Diskpart {
    param([string[]]$Script, [string]$Label)
    $scriptPath = Join-Path $workDirectory "$Label.diskpart.txt"
    $Script | Set-Content -LiteralPath $scriptPath -Encoding ASCII
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = @(& "$env:SystemRoot\System32\diskpart.exe" /s $scriptPath 2>&1 | ForEach-Object { $_.ToString() })
        $exit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previous
    }
    foreach ($line in $output) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            Write-Line "diskpart($Label): $line"
        }
    }
    if ($exit -ne 0) {
        throw "diskpart $Label failed with exit code $exit"
    }
}

function New-WindowsFormattedVhd {
    param([string]$FileSystem)
    $path = Join-Path $workDirectory "source-$FileSystem.vhd"
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Force
    }
    Invoke-Diskpart -Label "format-$FileSystem" -Script @(
        "create vdisk file=`"$path`" maximum=$vhdMaximumMiB type=fixed",
        "select vdisk file=`"$path`"",
        "attach vdisk",
        "convert mbr",
        "create partition primary offset=1024",
        "format fs=$FileSystem quick label=ORIGIN",
        "detach vdisk",
        "exit"
    )
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Length -ne $vhdBytes) {
        throw "Windows produced a $($item.Length)-byte VHD, expected $vhdBytes"
    }
    if ((Get-DiskImage -ImagePath $path -StorageType VHD).Attached) {
        throw "diskpart left the source VHD attached: $path"
    }
    return $path
}

function Mount-VhdToDirectory {
    param([string]$VhdPath, [string]$MountDirectory, [bool]$ReadOnly)
    if (Test-Path -LiteralPath $MountDirectory) {
        Remove-Item -LiteralPath $MountDirectory -Recurse -Force
    }
    $null = New-Item -ItemType Directory -Path $MountDirectory -Force
    if ($ReadOnly) {
        $null = Mount-DiskImage -ImagePath $VhdPath -StorageType VHD -Access ReadOnly -NoDriveLetter -PassThru
    }
    else {
        $null = Mount-DiskImage -ImagePath $VhdPath -StorageType VHD -Access ReadWrite -NoDriveLetter -PassThru
    }
    $image = Get-DiskImage -ImagePath $VhdPath -StorageType VHD
    if (-not $image.Attached) {
        throw "Storage provider did not report the VHD as attached: $VhdPath"
    }
    $disk = Assert-One -Values @($image | Get-Disk) -Description "associated virtual disk"
    if ($disk.IsBoot -or $disk.IsSystem) {
        throw "Boot or system disks are categorically refused."
    }
    if ($ReadOnly -and -not $disk.IsReadOnly) {
        throw "Associated virtual disk is not read-only."
    }
    if ($disk.PartitionStyle -ne "MBR") {
        throw "Expected an MBR disk, found $($disk.PartitionStyle)."
    }
    $partition = Assert-One -Values @($disk | Get-Partition) -Description "associated partition"
    if ($partition.Offset -ne $partitionOffset) {
        throw "Expected a 1 MiB partition offset, found $($partition.Offset) bytes."
    }
    if (Test-HasDriveLetter -Letter $partition.DriveLetter) {
        throw "No drive letter may be assigned (partition letter $($partition.DriveLetter))."
    }
    $volume = Assert-One -Values @($partition | Get-Volume) -Description "associated volume"
    if ($volume.Path -notmatch '^\\\\\?\\Volume\{[0-9A-Fa-f-]+\}\\$') {
        throw "Expected a volume GUID path, found '$($volume.Path)'."
    }
    # A directory mount point is not a drive letter; it only lets ordinary Win32 paths reach the
    # volume. If the mount manager refuses one (read-only disks sometimes do), the volume GUID
    # path addresses the same letterless volume directly.
    $accessPath = $MountDirectory.TrimEnd('\') + '\'
    $mountPointAdded = $false
    try {
        Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath $accessPath -ErrorAction Stop
        $mountPointAdded = $true
    }
    catch {
        Write-Line "directory mount point refused ($($_.Exception.Message)); using $($volume.Path)"
        $accessPath = $volume.Path
    }
    $attempt = 0
    while ([string]::IsNullOrWhiteSpace($volume.FileSystem) -and $attempt -lt 5) {
        $attempt++
        try {
            $null = [IO.Directory]::GetFileSystemEntries($accessPath)
        }
        catch {
            Write-Line "mount-trigger listing attempt $attempt failed: $($_.Exception.Message)"
        }
        Start-Sleep -Milliseconds 500
        $volume = Assert-One -Values @($partition | Get-Volume) -Description "associated volume"
    }
    if (Test-HasDriveLetter -Letter $volume.DriveLetter) {
        throw "No drive letter may be assigned (volume letter $($volume.DriveLetter))."
    }
    return [pscustomobject]@{
        Disk = $disk
        Partition = $partition
        Volume = $volume
        AccessPath = $accessPath
        MountPointAdded = $mountPointAdded
    }
}

function Dismount-Vhd {
    param([string]$VhdPath, $Mounted)
    if ($null -ne $Mounted -and $Mounted.MountPointAdded) {
        $previous = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            Remove-PartitionAccessPath -DiskNumber $Mounted.Disk.Number -PartitionNumber $Mounted.Partition.PartitionNumber -AccessPath $Mounted.AccessPath -ErrorAction Continue
        }
        finally {
            $ErrorActionPreference = $previous
        }
    }
    $null = Dismount-DiskImage -ImagePath $VhdPath -StorageType VHD -ErrorAction Continue
    $image = Get-DiskImage -ImagePath $VhdPath -StorageType VHD
    if ($image.Attached) {
        throw "VHD remained attached after dismount: $VhdPath"
    }
}

function Test-IsDirectoryPath {
    param([string]$Path)
    if ([IO.Directory]::Exists($Path)) {
        return $true
    }
    if ([IO.File]::Exists($Path)) {
        return $false
    }
    throw "Path does not exist on the mounted volume: $Path"
}

# Owner, group, and DACL as SDDL, read through .NET so volume GUID paths and directory mount
# points are handled identically. The SACL needs a privilege and is not part of the comparison.
$sddlSections = [Security.AccessControl.AccessControlSections]::Owner -bor
    [Security.AccessControl.AccessControlSections]::Group -bor
    [Security.AccessControl.AccessControlSections]::Access

function Get-Sddl {
    param([string]$Path)
    if (Test-IsDirectoryPath -Path $Path) {
        $security = [IO.Directory]::GetAccessControl($Path, $sddlSections)
    }
    else {
        $security = [IO.File]::GetAccessControl($Path, $sddlSections)
    }
    return $security.GetSecurityDescriptorSddlForm($sddlSections)
}

function Set-ExplicitDenyAcl {
    param([string]$Path)
    if (Test-IsDirectoryPath -Path $Path) {
        $security = [IO.Directory]::GetAccessControl($Path, $sddlSections)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $guestsSid, [Security.AccessControl.FileSystemRights]::Write,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Deny)
        $security.AddAccessRule($rule)
        [IO.Directory]::SetAccessControl($Path, $security)
    }
    else {
        $security = [IO.File]::GetAccessControl($Path, $sddlSections)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $guestsSid, [Security.AccessControl.FileSystemRights]::Read,
            [Security.AccessControl.AccessControlType]::Deny)
        $security.AddAccessRule($rule)
        [IO.File]::SetAccessControl($Path, $security)
    }
    $sddl = Get-Sddl -Path $Path
    if ($sddl -notmatch '\(D;[^)]*;BG\)') {
        throw "Explicit Guests deny ACE did not land on $Path`: $sddl"
    }
}

function Initialize-SourceVolume {
    param([string]$VhdPath, [string]$FileSystem)
    $mountDirectory = Join-Path $workDirectory "mount-source-$FileSystem"
    $mounted = $null
    $payloads = @()
    $security = @()
    try {
        $mounted = Mount-VhdToDirectory -VhdPath $VhdPath -MountDirectory $mountDirectory -ReadOnly $false
        if ($mounted.Volume.FileSystem -ine $FileSystem) {
            throw "Windows formatted '$($mounted.Volume.FileSystem)', expected $FileSystem."
        }
        foreach ($spec in $payloadSpecs) {
            $target = $mounted.AccessPath + $spec.Path
            $parent = [IO.Path]::GetDirectoryName($target)
            if (-not [IO.Directory]::Exists($parent)) {
                $null = [IO.Directory]::CreateDirectory($parent)
            }
            $bytes = New-PayloadBytes -Length $spec.Length -Seed $spec.Seed
            [IO.File]::WriteAllBytes($target, $bytes)
            $payloads += [pscustomobject]@{
                Path = $spec.Path
                Length = $spec.Length
                Sha256 = (Get-BytesSha256 -Bytes $bytes)
            }
        }
        if ($FileSystem -ieq "NTFS") {
            foreach ($relative in $explicitAclPaths) {
                Set-ExplicitDenyAcl -Path ($mounted.AccessPath + $relative)
            }
            $security += [pscustomobject]@{ Path = ""; Sddl = (Get-Sddl -Path $mounted.AccessPath) }
            foreach ($spec in $payloadSpecs) {
                $security += [pscustomobject]@{
                    Path = $spec.Path
                    Sddl = (Get-Sddl -Path ($mounted.AccessPath + $spec.Path))
                }
            }
            foreach ($relative in @("secured")) {
                $security += [pscustomobject]@{
                    Path = $relative
                    Sddl = (Get-Sddl -Path ($mounted.AccessPath + $relative))
                }
            }
        }
        Write-Line "populated $FileSystem source with $($payloads.Count) payload(s) and $($security.Count) descriptor(s)"
    }
    finally {
        Dismount-Vhd -VhdPath $VhdPath -Mounted $mounted
    }
    $root = Get-Item -LiteralPath $mountDirectory -Force -ErrorAction SilentlyContinue
    if ($null -ne $root) {
        Remove-Item -LiteralPath $mountDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
    return [pscustomobject]@{
        Payloads = $payloads
        Security = $security
    }
}

function Copy-FileRange {
    param([IO.FileStream]$Source, [long]$Offset, [long]$Length, [IO.FileStream]$Destination)
    $null = $Source.Seek($Offset, [IO.SeekOrigin]::Begin)
    $buffer = New-Object byte[] (1MB)
    $remaining = $Length
    while ($remaining -gt 0) {
        $chunk = [int][Math]::Min($remaining, $buffer.Length)
        $read = $Source.Read($buffer, 0, $chunk)
        if ($read -le 0) {
            throw "Unexpected end of file while copying $Length bytes from offset $Offset"
        }
        $Destination.Write($buffer, 0, $read)
        $remaining -= $read
    }
}

function Export-PartitionImage {
    param([string]$VhdPath, [string]$ImagePath)
    if (Test-Path -LiteralPath $ImagePath) {
        Remove-Item -LiteralPath $ImagePath -Force
    }
    $source = [IO.File]::Open($VhdPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $destination = [IO.File]::Open($ImagePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            Copy-FileRange -Source $source -Offset $partitionOffset -Length $partitionBytes -Destination $destination
            $destination.Flush($true)
        }
        finally {
            $destination.Dispose()
        }
    }
    finally {
        $source.Dispose()
    }
    $item = Get-Item -LiteralPath $ImagePath -Force
    if ($item.Length -ne $partitionBytes) {
        throw "Carved partition image is $($item.Length) bytes, expected $partitionBytes"
    }
}

# Splices a converted partition image back between the exact MBR region and VHD footer Windows
# wrote for the source. The partition geometry is unchanged, so Windows' own partition table and
# footer describe the candidate exactly; StarConverter's VHD writer is deliberately not involved.
function New-CandidateVhd {
    param([string]$SourceVhdPath, [string]$ImagePath, [string]$CandidateVhdPath)
    if (Test-Path -LiteralPath $CandidateVhdPath) {
        Remove-Item -LiteralPath $CandidateVhdPath -Force
    }
    $imageItem = Get-Item -LiteralPath $ImagePath -Force
    if ($imageItem.Length -ne $partitionBytes) {
        throw "Candidate image is $($imageItem.Length) bytes, expected $partitionBytes"
    }
    $vhd = [IO.File]::Open($SourceVhdPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $image = [IO.File]::Open($ImagePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            $destination = [IO.File]::Open($CandidateVhdPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                Copy-FileRange -Source $vhd -Offset 0 -Length $partitionOffset -Destination $destination
                Copy-FileRange -Source $image -Offset 0 -Length $partitionBytes -Destination $destination
                Copy-FileRange -Source $vhd -Offset $diskBytes -Length 512 -Destination $destination
                $destination.Flush($true)
            }
            finally {
                $destination.Dispose()
            }
        }
        finally {
            $image.Dispose()
        }
    }
    finally {
        $vhd.Dispose()
    }
    $item = Get-Item -LiteralPath $CandidateVhdPath -Force
    if ($item.Length -ne $vhdBytes) {
        throw "Candidate VHD is $($item.Length) bytes, expected $vhdBytes"
    }
}

function Invoke-Cli {
    param([string[]]$Arguments, [string]$Label)
    Write-Line "cli($Label): starconverter $($Arguments -join ' ')"
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = @(& $cliPath @Arguments 2>&1 | ForEach-Object { $_.ToString() })
        $exit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previous
    }
    foreach ($line in $output) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            Write-Line "cli($Label): $line"
        }
    }
    if ($exit -ne 0) {
        throw "starconverter $Label failed with exit code $exit"
    }
    return $output
}

function Invoke-DriverJudgment {
    param(
        [string]$Name,
        [string]$CandidateVhdPath,
        [string]$FileSystem,
        [object[]]$Payloads,
        [object[]]$Security
    )
    $beforeHash = Get-Sha256 -Path $CandidateVhdPath
    $mountDirectory = Join-Path $workDirectory "mount-judge"
    $mounted = $null
    $payloadResults = @()
    $securityResults = @()
    $chkdskOutput = @()
    $chkdskExit = $null
    $volumePath = $null
    try {
        $mounted = Mount-VhdToDirectory -VhdPath $CandidateVhdPath -MountDirectory $mountDirectory -ReadOnly $true
        $volume = $mounted.Volume
        if ($volume.FileSystem -ine $FileSystem) {
            throw "Expected $FileSystem, found '$($volume.FileSystem)' (FileSystemType $($volume.FileSystemType))."
        }
        if ($volume.Path -notmatch '^\\\\\?\\Volume\{[0-9A-Fa-f-]+\}\\$') {
            throw "Expected a volume GUID path, found $($volume.Path)."
        }
        $volumePath = $volume.Path
        foreach ($payload in $Payloads) {
            $payloadPath = $mounted.AccessPath + $payload.Path
            $payloadItem = Get-Item -LiteralPath $payloadPath -Force
            if (-not ($payloadItem -is [IO.FileInfo]) -or $payloadItem.Length -ne $payload.Length) {
                throw "Payload type or length mismatch: $($payload.Path)"
            }
            $payloadHash = Get-Sha256 -Path $payloadPath
            if ($payloadHash -ne $payload.Sha256) {
                throw "Payload hash mismatch: $($payload.Path)"
            }
            $payloadResults += [pscustomobject]@{
                Path = $payload.Path
                Length = $payloadItem.Length
                Sha256 = $payloadHash
            }
        }
        foreach ($expected in $Security) {
            $target = if ([string]::IsNullOrEmpty($expected.Path)) { $mounted.AccessPath } else { $mounted.AccessPath + $expected.Path }
            $actual = Get-Sddl -Path $target
            if (-not [string]::Equals($actual, $expected.Sddl, [StringComparison]::Ordinal)) {
                throw "Security descriptor mismatch at '$($expected.Path)': expected $($expected.Sddl) found $actual"
            }
            $securityResults += [pscustomobject]@{
                Path = $expected.Path
                Sddl = $actual
            }
        }
        Write-Line "$Name served $($payloadResults.Count) payload(s) and $($securityResults.Count) descriptor(s) at $volumePath"
        $chkdskTarget = $volume.Path.TrimEnd('\')
        $previous = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $chkdskOutput = @(& "$env:SystemRoot\System32\chkdsk.exe" $chkdskTarget 2>&1 | ForEach-Object {
                Write-Host $_
                $_.ToString()
            })
            $chkdskExit = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $previous
        }
        if ($chkdskExit -ne 0) {
            throw "CHKDSK reported exit code $chkdskExit; no repair was attempted."
        }
    }
    finally {
        Dismount-Vhd -VhdPath $CandidateVhdPath -Mounted $mounted
        Remove-Item -LiteralPath $mountDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
    $afterHash = Get-Sha256 -Path $CandidateVhdPath
    if ($afterHash -ne $beforeHash) {
        throw "Read-only Windows validation changed candidate VHD bytes: $CandidateVhdPath"
    }
    return [pscustomobject]@{
        FileSystem = $FileSystem
        VhdPath = $CandidateVhdPath
        VhdBytes = (Get-Item -LiteralPath $CandidateVhdPath -Force).Length
        Sha256Before = $beforeHash
        Sha256After = $afterHash
        ReadOnlyAttached = $true
        NoDriveLetter = $true
        DetachedAfter = $true
        PartitionOffsetBytes = $partitionOffset
        VolumeGuidPath = $volumePath
        Payloads = $payloadResults
        Security = $securityResults
        ChkdskExitCode = $chkdskExit
        ChkdskOutput = $chkdskOutput
    }
}

function Get-ConvertedSha256 {
    param([string[]]$Output, [string]$Tag)
    foreach ($line in $Output) {
        if ($line -match "^\[$Tag\]\s+sha256\s+([0-9a-f]{64})") {
            return $Matches[1].ToUpperInvariant()
        }
    }
    throw "CLI output did not report a [$Tag] sha256 line"
}

$results = @()
$failures = @()
Write-Line "host $([Environment]::OSVersion.VersionString) powershell $($PSVersionTable.PSVersion) ntfs.sys $((Get-Item "$env:SystemRoot\System32\drivers\ntfs.sys").VersionInfo.FileVersion) exfat.sys $((Get-Item "$env:SystemRoot\System32\drivers\exfat.sys").VersionInfo.FileVersion)"

foreach ($origin in @("NTFS", "exFAT")) {
    $other = if ($origin -ieq "NTFS") { "exFAT" } else { "NTFS" }
    $lower = $origin.ToLowerInvariant()
    $otherLower = $other.ToLowerInvariant()
    $forwardName = "Windows $origin to $other"
    $roundTripName = "Windows $origin round trip"
    try {
        $sourceVhd = New-WindowsFormattedVhd -FileSystem $lower
        $populated = Initialize-SourceVolume -VhdPath $sourceVhd -FileSystem $origin
        $sourceVhdHash = Get-Sha256 -Path $sourceVhd
        $sourceImage = Join-Path $workDirectory "source-$lower.img"
        Export-PartitionImage -VhdPath $sourceVhd -ImagePath $sourceImage
        $sourceImageHash = Get-Sha256 -Path $sourceImage

        $forwardImage = Join-Path $workDirectory "forward-$lower-to-$otherLower.img"
        $forwardEscrow = "$forwardImage.starconverter-escrow"
        foreach ($stale in @($forwardImage, $forwardEscrow)) {
            if (Test-Path -LiteralPath $stale) { Remove-Item -LiteralPath $stale -Force }
        }
        $forwardOutput = Invoke-Cli -Label "forward-$lower" -Arguments @("convert-image", $sourceImage, $forwardImage, "--to", $otherLower)
        $forwardSourceHash = Get-ConvertedSha256 -Output $forwardOutput -Tag "SOURCE UNCHANGED"
        if ($forwardSourceHash -ne $sourceImageHash) {
            throw "CLI reported source sha256 $forwardSourceHash, carved image is $sourceImageHash"
        }
        Invoke-Cli -Label "verify-forward-$lower" -Arguments @("verify-export", $forwardImage, $forwardEscrow, "--source", $sourceImage) | Out-Null
        $forwardVhd = Join-Path $workDirectory "forward-$lower-to-$otherLower.vhd"
        New-CandidateVhd -SourceVhdPath $sourceVhd -ImagePath $forwardImage -CandidateVhdPath $forwardVhd
        # Descriptor equality is only meaningful when both ends are NTFS, so the forward
        # conversion (which always changes filesystem) records payloads only.
        $forward = Invoke-DriverJudgment -Name $forwardName -CandidateVhdPath $forwardVhd -FileSystem $other -Payloads $populated.Payloads -Security @()
        $results += [pscustomobject]@{
            Name = $forwardName
            Origin = $origin
            SourceVhdPath = $sourceVhd
            SourceVhdSha256 = $sourceVhdHash
            SourceImageSha256 = $sourceImageHash
            Candidate = $forward
        }
        Write-Host "[PASS] $forwardName / SHA256 $($forward.Sha256After)"

        $backImage = Join-Path $workDirectory "roundtrip-$lower.img"
        $backEscrow = "$backImage.starconverter-escrow"
        foreach ($stale in @($backImage, $backEscrow)) {
            if (Test-Path -LiteralPath $stale) { Remove-Item -LiteralPath $stale -Force }
        }
        $backOutput = Invoke-Cli -Label "roundtrip-$lower" -Arguments @("convert-image", $forwardImage, $backImage, "--to", $lower, "--restore-escrow", $forwardEscrow)
        Invoke-Cli -Label "verify-roundtrip-$lower" -Arguments @("verify-export", $backImage, $backEscrow, "--source", $forwardImage) | Out-Null
        $backVhd = Join-Path $workDirectory "roundtrip-$lower.vhd"
        New-CandidateVhd -SourceVhdPath $sourceVhd -ImagePath $backImage -CandidateVhdPath $backVhd
        $back = Invoke-DriverJudgment -Name $roundTripName -CandidateVhdPath $backVhd -FileSystem $origin -Payloads $populated.Payloads -Security $populated.Security
        $results += [pscustomobject]@{
            Name = $roundTripName
            Origin = $origin
            SourceVhdPath = $sourceVhd
            SourceVhdSha256 = $sourceVhdHash
            SourceImageSha256 = $sourceImageHash
            Candidate = $back
        }
        Write-Host "[PASS] $roundTripName / SHA256 $($back.Sha256After)"
    }
    catch {
        Write-Host "[FAIL] $origin origin: $($_.Exception.Message)"
        $failures += "$origin origin: $($_.Exception.Message)"
    }
}

if ($failures.Count -gt 0) {
    throw "Windows-origin validation failed for $($failures.Count) origin(s): $($failures -join ' | ')"
}

if ($null -ne $reportFullPath) {
    $report = [ordered]@{
        Schema = "starconverter.windows-origin-validation"
        Version = 1
        Complete = $true
        GeneratedUtc = [DateTime]::UtcNow.ToString("o")
        WindowsVersion = [Environment]::OSVersion.VersionString
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        ChkdskVersion = (Get-Item -LiteralPath "$env:SystemRoot\System32\chkdsk.exe").VersionInfo.FileVersion
        NtfsDriverVersion = (Get-Item -LiteralPath "$env:SystemRoot\System32\drivers\ntfs.sys").VersionInfo.FileVersion
        ExfatDriverVersion = (Get-Item -LiteralPath "$env:SystemRoot\System32\drivers\exfat.sys").VersionInfo.FileVersion
        Cases = $results
    }
    $json = $report | ConvertTo-Json -Depth 10
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $stream = New-Object System.IO.FileStream(
        $reportFullPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    try {
        $writer = New-Object System.IO.StreamWriter($stream, $encoding)
        try {
            $writer.Write($json)
            $writer.Flush()
            $stream.Flush($true)
        }
        finally {
            $writer.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
    Write-Host "[REPORT] $reportFullPath"
}
