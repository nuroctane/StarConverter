param(
    [string]$Cli = "",
    [string]$WorkRoot = "",
    [string]$ReportPath = ""
)

# Windows-origin gate. Where validate-windows-vhd.ps1 judges StarConverter's output from pinned
# StarConverter-built sources, this script starts from volumes that Windows itself formatted and
# populated on this host, converts them with the CLI, and asks the Windows filesystem drivers
# whether the result (and the escrow-restored round trip) serves the same files, bytes, label,
# NTFS security descriptors, and, after an escrow restore in either direction, the same volume
# serial and per-file creation and last-write instants. Nothing here is pinned by hash: Windows
# chooses serials, GUIDs, and timestamps at run time, so each case records what it saw and the
# report verifier checks the invariants rather than fixed bytes.
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

# 40 MiB fixed VHD: 512-byte footer after the disk bytes, one MBR partition at 1 MiB. diskpart
# chooses the partition length itself (it keeps about 1 MiB of slack at the end of the disk), so
# the length is read back from the MBR Windows wrote rather than assumed; carving more than the
# partition would hand StarConverter a volume larger than the one the drivers can see.
$vhdMaximumMiB = 40
$diskBytes = [long]$vhdMaximumMiB * 1MB
$vhdBytes = $diskBytes + 512
$partitionOffset = [long]1MB
$partitionBytes = [long]0
# Label Windows writes at format time; every candidate must serve it back verbatim.
$sourceLabel = "ORIGIN"

function Read-MbrPartitionBytes {
    param([string]$VhdPath)
    $stream = [IO.File]::Open($VhdPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $mbr = New-Object byte[] 512
        if ($stream.Read($mbr, 0, 512) -ne 512) { throw "Short read of the source MBR" }
    }
    finally {
        $stream.Dispose()
    }
    if ($mbr[510] -ne 0x55 -or $mbr[511] -ne 0xAA) {
        throw "Source MBR lacks the 0x55AA boot signature"
    }
    $entries = @()
    for ($i = 0; $i -lt 4; $i++) {
        $entry = 0x1BE + 16 * $i
        if ($mbr[$entry + 4] -ne 0) {
            $entries += [pscustomobject]@{
                Type = $mbr[$entry + 4]
                StartBytes = [long][BitConverter]::ToUInt32($mbr, $entry + 8) * 512
                LengthBytes = [long][BitConverter]::ToUInt32($mbr, $entry + 12) * 512
            }
        }
    }
    if ($entries.Count -ne 1) {
        throw "Expected exactly one MBR partition, found $($entries.Count)"
    }
    $partition = $entries[0]
    if ($partition.Type -ne 0x07) {
        throw ("Expected MBR partition type 0x07, found 0x{0:X2}" -f $partition.Type)
    }
    if ($partition.StartBytes -ne $partitionOffset) {
        throw "Expected the partition at $partitionOffset bytes, found $($partition.StartBytes)"
    }
    if ($partition.LengthBytes -le 0 -or ($partition.StartBytes + $partition.LengthBytes) -gt $diskBytes) {
        throw "MBR partition of $($partition.LengthBytes) bytes does not fit the $diskBytes-byte disk"
    }
    return [long]$partition.LengthBytes
}

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
        "format fs=$FileSystem quick label=$sourceLabel",
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
    $length = Read-MbrPartitionBytes -VhdPath $path
    if ($script:partitionBytes -ne 0 -and $script:partitionBytes -ne $length) {
        throw "diskpart produced a $length-byte partition for $FileSystem, earlier origin had $($script:partitionBytes)"
    }
    $script:partitionBytes = $length
    Write-Line "$FileSystem source partition: offset $partitionOffset bytes, length $length bytes ($($length / 1MB) MiB)"
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

function Get-VolumeSerialNumber {
    param($Volume)
    # Win32_Volume keys letterless volumes by their GUID path and reports the 32-bit serial the
    # driver serves through GetVolumeInformation, for NTFS and exFAT alike.
    $volumes = @(Get-CimInstance -ClassName Win32_Volume | Where-Object { $_.DeviceID -ieq $Volume.Path })
    if ($volumes.Count -ne 1) {
        throw "Expected exactly one Win32_Volume for $($Volume.Path), found $($volumes.Count)"
    }
    if ($null -eq $volumes[0].SerialNumber) {
        throw "Win32_Volume reported no serial number for $($Volume.Path)"
    }
    return [uint32]$volumes[0].SerialNumber
}

function Get-PayloadTimestamps {
    param([IO.FileInfo]$Item)
    # Access time is excluded on purpose: both drivers may refresh it on a read, so it is not a
    # property either conversion promises to carry.
    return @{
        CreationTimeUtc = $Item.CreationTimeUtc.ToString("o")
        LastWriteTimeUtc = $Item.LastWriteTimeUtc.ToString("o")
    }
}

function Read-SourceIdentity {
    param([string]$VhdPath, [string]$FileSystem, [object[]]$Payloads)
    # A fresh read-only attach reads the identities Windows actually committed to disk rather
    # than values still cached from the populating handle (exFAT, for one, only rounds timestamps
    # to its on-disk precision when it writes the directory entry).
    $mountDirectory = Join-Path $workDirectory "mount-identity-$FileSystem"
    $mounted = $null
    try {
        $mounted = Mount-VhdToDirectory -VhdPath $VhdPath -MountDirectory $mountDirectory -ReadOnly $true
        if ($mounted.Volume.FileSystem -ine $FileSystem) {
            throw "Expected $FileSystem source, found '$($mounted.Volume.FileSystem)'."
        }
        $timestamps = @()
        foreach ($payload in $Payloads) {
            $item = Get-Item -LiteralPath ($mounted.AccessPath + $payload.Path) -Force
            $stamps = Get-PayloadTimestamps -Item $item
            $timestamps += [pscustomobject]@{
                Path = $payload.Path
                CreationTimeUtc = $stamps.CreationTimeUtc
                LastWriteTimeUtc = $stamps.LastWriteTimeUtc
            }
        }
        $identity = [pscustomobject]@{
            VolumeLabel = [string]$mounted.Volume.FileSystemLabel
            VolumeSerialNumber = (Get-VolumeSerialNumber -Volume $mounted.Volume)
            Timestamps = $timestamps
        }
        Write-Line "$FileSystem source identity: label '$($identity.VolumeLabel)' serial $($identity.VolumeSerialNumber.ToString('X8')) with $($timestamps.Count) payload timestamp pair(s)"
        return $identity
    }
    finally {
        Dismount-Vhd -VhdPath $VhdPath -Mounted $mounted
        Remove-Item -LiteralPath $mountDirectory -Recurse -Force -ErrorAction SilentlyContinue
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

# VHD footer layout (fixed disks): the 512-byte footer trails the disk bytes; its checksum at
# +0x40 is the big-endian one's complement of the byte sum with the checksum field zeroed, and
# the 16-byte UniqueId lives at +0x44.
$vhdFooterChecksumOffset = 0x40
$vhdFooterUniqueIdOffset = 0x44
$mbrDiskSignatureOffset = 0x1B8

function Get-VhdFooterChecksum {
    param([byte[]]$Footer)
    [long]$sum = 0
    for ($i = 0; $i -lt $Footer.Length; $i++) {
        if ($i -ge $vhdFooterChecksumOffset -and $i -lt ($vhdFooterChecksumOffset + 4)) { continue }
        $sum += [long]$Footer[$i]
    }
    return [uint32]((-bnot $sum) -band [long][uint32]::MaxValue)
}

function Read-BigEndianUInt32 {
    param([byte[]]$Buffer, [int]$Offset)
    [long]$value = 0
    for ($i = 0; $i -lt 4; $i++) {
        $value = ($value * 256) + [long]$Buffer[$Offset + $i]
    }
    return [uint32]$value
}

function Write-BigEndianUInt32 {
    param([byte[]]$Buffer, [int]$Offset, [uint32]$Value)
    [long]$remaining = $Value
    for ($i = 3; $i -ge 0; $i--) {
        $Buffer[$Offset + $i] = [byte]($remaining % 256)
        $remaining = [long][Math]::Floor($remaining / 256)
    }
}

function New-RandomBytes {
    param([int]$Count)
    $bytes = New-Object byte[] $Count
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    return , $bytes
}

# Splices a converted partition image back between the exact MBR region and VHD footer Windows
# wrote for the source. The partition geometry is unchanged, so Windows' own partition table and
# footer describe the candidate exactly; StarConverter's VHD writer is deliberately not involved.
# The MBR disk signature and the footer UniqueId are replaced with fresh random values so the
# mount manager cannot reuse the source disk's cached volume identity (and with it the source
# filesystem's view) for the candidate.
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
                $partitionEnd = $partitionOffset + $partitionBytes
                if ($partitionEnd -lt $diskBytes) {
                    # Unpartitioned slack diskpart left after the partition travels unchanged.
                    Copy-FileRange -Source $vhd -Offset $partitionEnd -Length ($diskBytes - $partitionEnd) -Destination $destination
                }
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

    $candidate = [IO.File]::Open($CandidateVhdPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $mbr = New-Object byte[] 512
        $null = $candidate.Seek(0, [IO.SeekOrigin]::Begin)
        if ($candidate.Read($mbr, 0, 512) -ne 512) { throw "Short read of candidate MBR" }
        if ($mbr[510] -ne 0x55 -or $mbr[511] -ne 0xAA) {
            throw "Candidate MBR lacks the 0x55AA boot signature"
        }
        $oldSignature = [BitConverter]::ToUInt32($mbr, $mbrDiskSignatureOffset)
        do {
            $signatureBytes = New-RandomBytes -Count 4
            $newSignature = [BitConverter]::ToUInt32($signatureBytes, 0)
        } while ($newSignature -eq 0 -or $newSignature -eq $oldSignature)
        [Array]::Copy($signatureBytes, 0, $mbr, $mbrDiskSignatureOffset, 4)
        $null = $candidate.Seek(0, [IO.SeekOrigin]::Begin)
        $candidate.Write($mbr, 0, 512)

        $footer = New-Object byte[] 512
        $null = $candidate.Seek($diskBytes, [IO.SeekOrigin]::Begin)
        if ($candidate.Read($footer, 0, 512) -ne 512) { throw "Short read of candidate VHD footer" }
        if ([Text.Encoding]::ASCII.GetString($footer, 0, 8) -ne "conectix") {
            throw "Candidate VHD footer lacks the conectix cookie"
        }
        $storedChecksum = Read-BigEndianUInt32 -Buffer $footer -Offset $vhdFooterChecksumOffset
        $computedChecksum = Get-VhdFooterChecksum -Footer $footer
        if ($storedChecksum -ne $computedChecksum) {
            throw ("Source VHD footer checksum mismatch: stored 0x{0:X8}, computed 0x{1:X8}" -f $storedChecksum, $computedChecksum)
        }
        $oldUniqueId = [Guid]::new([byte[]]$footer[$vhdFooterUniqueIdOffset..($vhdFooterUniqueIdOffset + 15)])
        $newUniqueId = [Guid]::NewGuid()
        [Array]::Copy($newUniqueId.ToByteArray(), 0, $footer, $vhdFooterUniqueIdOffset, 16)
        Write-BigEndianUInt32 -Buffer $footer -Offset $vhdFooterChecksumOffset -Value (Get-VhdFooterChecksum -Footer $footer)
        $null = $candidate.Seek($diskBytes, [IO.SeekOrigin]::Begin)
        $candidate.Write($footer, 0, 512)
        $candidate.Flush($true)
        Write-Line ("candidate identity: disk signature 0x{0:X8} -> 0x{1:X8}, vhd id {2} -> {3}" -f $oldSignature, $newSignature, $oldUniqueId, $newUniqueId)
    }
    finally {
        $candidate.Dispose()
    }
    $item = Get-Item -LiteralPath $CandidateVhdPath -Force
    if ($item.Length -ne $vhdBytes) {
        throw "Candidate VHD is $($item.Length) bytes after identity rewrite, expected $vhdBytes"
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
        [object[]]$Security,
        [string]$ExpectedLabel,
        [AllowNull()]$RestoredIdentity
    )
    $beforeHash = Get-Sha256 -Path $CandidateVhdPath
    $mountDirectory = Join-Path $workDirectory "mount-judge"
    $mounted = $null
    $payloadResults = @()
    $securityResults = @()
    $chkdskOutput = @()
    $chkdskExit = $null
    $volumePath = $null
    $volumeLabel = $null
    $volumeSerial = $null
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
        $volumeLabel = [string]$volume.FileSystemLabel
        if (-not [string]::Equals($volumeLabel, $ExpectedLabel, [StringComparison]::Ordinal)) {
            throw "Volume label mismatch: expected '$ExpectedLabel' found '$volumeLabel'"
        }
        $volumeSerial = Get-VolumeSerialNumber -Volume $volume
        if ($null -ne $RestoredIdentity -and $volumeSerial -ne $RestoredIdentity.VolumeSerialNumber) {
            throw ("Volume serial mismatch after escrow restore: expected {0:X8} found {1:X8}" -f $RestoredIdentity.VolumeSerialNumber, $volumeSerial)
        }
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
            $stamps = Get-PayloadTimestamps -Item $payloadItem
            if ($null -ne $RestoredIdentity) {
                $expectedStamps = @($RestoredIdentity.Timestamps | Where-Object { $_.Path -eq $payload.Path })
                if ($expectedStamps.Count -ne 1) {
                    throw "Source identity has $($expectedStamps.Count) timestamp record(s) for $($payload.Path)"
                }
                foreach ($field in @("CreationTimeUtc", "LastWriteTimeUtc")) {
                    if (-not [string]::Equals($stamps[$field], $expectedStamps[0].$field, [StringComparison]::Ordinal)) {
                        throw "$field mismatch after escrow restore at '$($payload.Path)': expected $($expectedStamps[0].$field) found $($stamps[$field])"
                    }
                }
            }
            $payloadResults += [pscustomobject]@{
                Path = $payload.Path
                Length = $payloadItem.Length
                Sha256 = $payloadHash
                CreationTimeUtc = $stamps.CreationTimeUtc
                LastWriteTimeUtc = $stamps.LastWriteTimeUtc
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
        Write-Line "$Name served $($payloadResults.Count) payload(s) and $($securityResults.Count) descriptor(s) at $volumePath (label '$volumeLabel', serial $($volumeSerial.ToString('X8')))"
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
        # CHKDSK names the filesystem it actually examined; a mismatch means it judged some other
        # volume view (for example a stale identity), and its verdict would be meaningless either way.
        $reportedType = $null
        foreach ($line in $chkdskOutput) {
            if ($line -match '^The type of the file system is (\S+)\.') {
                $reportedType = $Matches[1]
                break
            }
        }
        if ($null -eq $reportedType) {
            throw "CHKDSK did not report the file system type it examined."
        }
        if ($reportedType -ine $FileSystem) {
            throw "CHKDSK examined a $reportedType volume, expected $FileSystem."
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
        PartitionBytes = $partitionBytes
        VolumeGuidPath = $volumePath
        VolumeLabel = $volumeLabel
        VolumeSerialNumber = $volumeSerial
        Payloads = $payloadResults
        Security = $securityResults
        ChkdskExitCode = $chkdskExit
        ChkdskOutput = $chkdskOutput
    }
}

function Get-ConvertedSha256 {
    param([string[]]$Output, [string]$Tag)
    # `[SOURCE UNCHANGED] <bytes> bytes / sha256 <hex>` and `[CANDIDATE] sha256 <hex>`.
    foreach ($line in $Output) {
        if ($line -match "^\[$Tag\]\s+(?:\d+ bytes / )?sha256\s+([0-9a-f]{64})\s*$") {
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
        $sourceIdentity = Read-SourceIdentity -VhdPath $sourceVhd -FileSystem $origin -Payloads $populated.Payloads
        if ($sourceIdentity.VolumeLabel -cne $sourceLabel) {
            throw "Windows formatted the $origin source with label '$($sourceIdentity.VolumeLabel)', expected '$sourceLabel'"
        }
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
        # conversion (which always changes filesystem) records payloads only. The label crosses
        # in both directions; serial and timestamps are only promised back by an escrow restore.
        $forward = Invoke-DriverJudgment -Name $forwardName -CandidateVhdPath $forwardVhd -FileSystem $other -Payloads $populated.Payloads -Security @() -ExpectedLabel $sourceLabel -RestoredIdentity $null
        $results += [pscustomobject]@{
            Name = $forwardName
            Origin = $origin
            RestoreEscrow = $false
            SourceVhdPath = $sourceVhd
            SourceVhdSha256 = $sourceVhdHash
            SourceImageSha256 = $sourceImageHash
            SourceVolumeLabel = $sourceIdentity.VolumeLabel
            SourceVolumeSerialNumber = $sourceIdentity.VolumeSerialNumber
            SourceTimestamps = $sourceIdentity.Timestamps
            Candidate = $forward
        }
        Write-Host "[PASS] $forwardName / SHA256 $($forward.Sha256After)"

        $backImage = Join-Path $workDirectory "roundtrip-$lower.img"
        $backEscrow = "$backImage.starconverter-escrow"
        foreach ($stale in @($backImage, $backEscrow)) {
            if (Test-Path -LiteralPath $stale) { Remove-Item -LiteralPath $stale -Force }
        }
        # Both round trips replay the forward escrow, so the Windows driver must hand back the
        # source serial and every payload's creation and last-write instants exactly; the NTFS
        # origin additionally must reproduce the exact SDDL of every descriptor.
        $backOutput = Invoke-Cli -Label "roundtrip-$lower" -Arguments @("convert-image", $forwardImage, $backImage, "--to", $lower, "--restore-escrow", $forwardEscrow)
        Invoke-Cli -Label "verify-roundtrip-$lower" -Arguments @("verify-export", $backImage, $backEscrow, "--source", $forwardImage) | Out-Null
        $backVhd = Join-Path $workDirectory "roundtrip-$lower.vhd"
        New-CandidateVhd -SourceVhdPath $sourceVhd -ImagePath $backImage -CandidateVhdPath $backVhd
        $back = Invoke-DriverJudgment -Name $roundTripName -CandidateVhdPath $backVhd -FileSystem $origin -Payloads $populated.Payloads -Security $populated.Security -ExpectedLabel $sourceLabel -RestoredIdentity $sourceIdentity
        $results += [pscustomobject]@{
            Name = $roundTripName
            Origin = $origin
            RestoreEscrow = $true
            SourceVhdPath = $sourceVhd
            SourceVhdSha256 = $sourceVhdHash
            SourceImageSha256 = $sourceImageHash
            SourceVolumeLabel = $sourceIdentity.VolumeLabel
            SourceVolumeSerialNumber = $sourceIdentity.VolumeSerialNumber
            SourceTimestamps = $sourceIdentity.Timestamps
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
        Version = 2
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
