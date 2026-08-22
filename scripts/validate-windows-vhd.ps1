param(
    [string]$FixtureRoot = "",
    [switch]$PreflightOnly,
    [string]$ReportPath = ""
)

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

if (-not $PreflightOnly -and -not (Test-IsAdministrator)) {
    throw "Windows VHD validation requires an elevated PowerShell 5.1 prompt."
}

if ([string]::IsNullOrWhiteSpace($env:windir) -and -not [string]::IsNullOrWhiteSpace($env:SystemRoot)) {
    $env:windir = $env:SystemRoot
}
Import-Module Storage -ErrorAction Stop

try {
    $cluster = Get-CimInstance -Namespace "root/MSCluster" -ClassName "MSCluster_Cluster" -ErrorAction Stop
    if ($null -ne $cluster) {
        throw "Clustered hosts are outside this validator's safety envelope."
    }
}
catch [Microsoft.Management.Infrastructure.CimException] {
    # The cluster namespace is absent on ordinary non-clustered Windows hosts.
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($FixtureRoot)) {
    $FixtureRoot = Join-Path $repoRoot "target\external-validator-fixtures"
}
$fixtureDirectory = (Resolve-Path -LiteralPath $FixtureRoot).Path
if ($fixtureDirectory.StartsWith("\\")) {
    throw "Network fixture paths are refused: $fixtureDirectory"
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

$cases = @(
    [pscustomobject]@{
        Name = "exFAT-to-NTFS rich conversion"
        File = "converted-rich-exfat-to-ntfs-windows.vhd"
        FileSystem = "NTFS"
        Sha256 = "4D1CDDB7676FE60A541A432B38E32880621B88B5CA6404097FAAC357A8291E2F"
    },
    [pscustomobject]@{
        Name = "NTFS-to-exFAT rich conversion"
        File = "converted-rich-ntfs-to-exfat-windows.vhd"
        FileSystem = "exFAT"
        Sha256 = "EE905BAEE3EEFD654F15EF5514110C2DCF9E6E58DB28751B8833D79FAF8F5B7A"
    }
)
$payloads = @(
    [pscustomobject]@{
        Path = "readme.txt"
        Length = 14
        Sha256 = "DEEE70659646C5B4F25155E113967DB5AAEE6F9616232A85DEE3AFB1159D6FFB"
    },
    [pscustomobject]@{
        Path = "alpha\empty.dat"
        Length = 0
        Sha256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    },
    [pscustomobject]@{
        Path = "alpha\$([char]0x03A9)mega\fragmented.bin"
        Length = 6000
        Sha256 = "6F5B3BEF759FFD6505BEB8112B023A869B1B771946F88BAEC7F016CCFB1035D6"
    }
)
$results = @()

foreach ($case in $cases) {
    $candidatePath = Join-Path $fixtureDirectory $case.File
    $item = Get-Item -LiteralPath $candidatePath -Force
    if (-not ($item -is [System.IO.FileInfo])) {
        throw "VHD candidate is not a regular file: $candidatePath"
    }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Reparse-point VHD candidates are refused: $candidatePath"
    }
    $vhdPath = $item.FullName
    $expectedPrefix = $fixtureDirectory.TrimEnd('\') + '\'
    if (-not $vhdPath.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "VHD candidate escaped the exact fixture directory: $vhdPath"
    }
    if ([IO.Path]::GetExtension($vhdPath) -ine ".vhd") {
        throw "Only fixed .vhd fixture files are accepted: $vhdPath"
    }

    $beforeLength = $item.Length
    $beforeHash = (Get-FileHash -LiteralPath $vhdPath -Algorithm SHA256).Hash
    if ($beforeLength -ne 34603520 -or $beforeHash -ne $case.Sha256) {
        throw "VHD does not match the pinned generated candidate identity: $vhdPath"
    }
    $initialImage = Get-DiskImage -ImagePath $vhdPath -StorageType VHD
    if ($initialImage.Attached) {
        throw "Refusing an already-attached VHD: $vhdPath"
    }
    if ($PreflightOnly) {
        if ($initialImage.Size -ne 34603008) {
            throw "Unexpected fixed-VHD virtual size: $($initialImage.Size)"
        }
        $results += [pscustomobject]@{
            Name = $case.Name
            FileSystem = $case.FileSystem
            VhdPath = $vhdPath
            VhdBytes = $beforeLength
            VirtualBytes = $initialImage.Size
            Sha256Before = $beforeHash
            Sha256After = $beforeHash
            DetachedBefore = $true
            DetachedAfter = $true
            ReadOnlyAttached = $null
            NoDriveLetter = $null
            PartitionOffsetBytes = $null
            Payloads = @()
            ChkdskExitCode = $null
            ChkdskOutput = @()
        }
        Write-Host "[PASS] pinned detached VHD preflight / $beforeHash / $vhdPath"
        continue
    }

    $attached = $false
    $payloadResults = @()
    $chkdskOutput = @()
    $chkdskExit = $null
    $volumePath = $null
    try {
        $null = Mount-DiskImage -ImagePath $vhdPath -StorageType VHD -Access ReadOnly -NoDriveLetter -PassThru
        $attached = $true

        $image = Get-DiskImage -ImagePath $vhdPath -StorageType VHD
        if (-not $image.Attached) {
            throw "Storage provider did not report the exact VHD as attached."
        }
        $disk = Assert-One -Values @($image | Get-Disk) -Description "associated virtual disk"
        if (-not $disk.IsReadOnly) {
            throw "Associated virtual disk is not read-only."
        }
        if ($disk.IsBoot -or $disk.IsSystem) {
            throw "Boot or system disks are categorically refused."
        }
        if ($disk.PartitionStyle -ne "MBR") {
            throw "Expected an MBR validation wrapper, found $($disk.PartitionStyle)."
        }

        $partition = Assert-One -Values @($disk | Get-Partition) -Description "associated partition"
        if ($partition.Offset -ne 1MB) {
            throw "Expected a 1 MiB partition offset, found $($partition.Offset) bytes."
        }
        if ($null -ne $partition.DriveLetter) {
            throw "No drive letter may be assigned during validation."
        }

        $volume = Assert-One -Values @($partition | Get-Volume) -Description "associated volume"
        if ($null -ne $volume.DriveLetter) {
            throw "No drive letter may be assigned during validation."
        }
        if ($volume.FileSystem -ine $case.FileSystem) {
            throw "Expected $($case.FileSystem), found $($volume.FileSystem)."
        }
        if ($volume.Path -notmatch '^\\\\\?\\Volume\{[0-9A-Fa-f-]+\}\\$') {
            throw "Expected a volume GUID path, found $($volume.Path)."
        }

        $roundTrip = Assert-One -Values @(Get-DiskImage -Volume $volume) -Description "round-trip disk image"
        if ([IO.Path]::GetFullPath($roundTrip.ImagePath) -ine [IO.Path]::GetFullPath($vhdPath)) {
            throw "Volume association did not round-trip to the exact VHD path."
        }

        foreach ($payload in $payloads) {
            $payloadPath = Join-Path $volume.Path $payload.Path
            $payloadItem = Get-Item -LiteralPath $payloadPath -Force
            if (-not ($payloadItem -is [IO.FileInfo]) -or $payloadItem.Length -ne $payload.Length) {
                throw "Payload type or length mismatch: $($payload.Path)"
            }
            $payloadHash = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash
            if ($payloadHash -ne $payload.Sha256) {
                throw "Payload hash mismatch: $($payload.Path)"
            }
            $payloadResults += [pscustomobject]@{
                Path = $payload.Path
                Length = $payloadItem.Length
                Sha256 = $payloadHash
            }
        }

        Write-Host "[CHECK] $($case.Name) at $($volume.Path)"
        $volumePath = $volume.Path
        $chkdskOutput = @(& "$env:SystemRoot\System32\chkdsk.exe" $volume.Path 2>&1 | ForEach-Object {
            Write-Host $_
            $_.ToString()
        })
        $chkdskExit = $LASTEXITCODE
        if ($chkdskExit -ne 0) {
            throw "CHKDSK reported exit code $chkdskExit; no repair was attempted."
        }
    }
    finally {
        if ($attached) {
            Dismount-DiskImage -ImagePath $vhdPath -StorageType VHD -ErrorAction Continue
        }
    }

    $finalImage = Get-DiskImage -ImagePath $vhdPath -StorageType VHD
    if ($finalImage.Attached) {
        throw "VHD remained attached after validation: $vhdPath"
    }
    $afterItem = Get-Item -LiteralPath $vhdPath -Force
    $afterHash = (Get-FileHash -LiteralPath $vhdPath -Algorithm SHA256).Hash
    if ($afterItem.Length -ne $beforeLength -or $afterHash -ne $beforeHash) {
        throw "Read-only Windows validation changed VHD bytes: $vhdPath"
    }
    $results += [pscustomobject]@{
        Name = $case.Name
        FileSystem = $case.FileSystem
        VhdPath = $vhdPath
        VhdBytes = $afterItem.Length
        VirtualBytes = $finalImage.Size
        Sha256Before = $beforeHash
        Sha256After = $afterHash
        DetachedBefore = $true
        DetachedAfter = $true
        ReadOnlyAttached = $true
        NoDriveLetter = $true
        PartitionOffsetBytes = 1MB
        VolumeGuidPath = $volumePath
        Payloads = $payloadResults
        ChkdskExitCode = $chkdskExit
        ChkdskOutput = $chkdskOutput
    }
    Write-Host "[PASS] $($case.Name) / SHA256 $afterHash / detached / no drive letter"
}

if ($null -ne $reportFullPath) {
    $report = [ordered]@{
        Schema = "starconverter.windows-vhd-validation"
        Version = 1
        Complete = $true
        Mode = $(if ($PreflightOnly) { "detached-preflight" } else { "read-only-windows-driver" })
        GeneratedUtc = [DateTime]::UtcNow.ToString("o")
        WindowsVersion = [Environment]::OSVersion.VersionString
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        ChkdskVersion = (Get-Item -LiteralPath "$env:SystemRoot\System32\chkdsk.exe").VersionInfo.FileVersion
        NtfsDriverVersion = (Get-Item -LiteralPath "$env:SystemRoot\System32\drivers\ntfs.sys").VersionInfo.FileVersion
        ExfatDriverVersion = (Get-Item -LiteralPath "$env:SystemRoot\System32\drivers\exfat.sys").VersionInfo.FileVersion
        Cases = $results
    }
    $json = $report | ConvertTo-Json -Depth 8
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
