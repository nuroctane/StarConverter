param(
    [string]$FixtureRoot = "",
    [string[]]$Vhds = @(
        "converted-rich-exfat-to-ntfs-windows.vhd",
        "converted-rich-ntfs-to-exfat-windows.vhd",
        "ntfs-structural-validation.vhd",
        "exfat-structural-validation.vhd"
    ),
    [switch]$SkipWritableCopy,
    [switch]$SkipControl
)

# Diagnostic companion to validate-windows-vhd.ps1. It never pins, never passes or fails a
# candidate, and always exits 0 so it can run after a failed gate and explain what the Windows
# filesystem drivers saw. It attaches only regular VHD files: the exact generated fixtures
# read-only, a disposable temporary copy writable, and a diskpart-formatted control VHD. No
# physical disk is discovered, selected, or touched.

$ErrorActionPreference = "Continue"
Set-StrictMode -Off

if ([string]::IsNullOrWhiteSpace($env:windir) -and -not [string]::IsNullOrWhiteSpace($env:SystemRoot)) {
    $env:windir = $env:SystemRoot
}
Import-Module Storage -ErrorAction SilentlyContinue

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($FixtureRoot)) {
    $FixtureRoot = Join-Path $repoRoot "target\external-validator-fixtures"
}
$fixtureDirectory = (Resolve-Path -LiteralPath $FixtureRoot).Path
$scratch = Join-Path $fixtureDirectory "probe-scratch"
$null = New-Item -ItemType Directory -Path $scratch -Force

function Write-Line {
    param([string]$Text)
    Write-Host "[PROBE] $Text"
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Format-Hex {
    param([byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString("X2") }) -join " ")
}

function Read-FileBytes {
    param([string]$Path, [long]$Offset, [int]$Count)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $null = $stream.Seek($Offset, [IO.SeekOrigin]::Begin)
        $buffer = New-Object byte[] $Count
        $read = $stream.Read($buffer, 0, $Count)
        if ($read -lt $Count) {
            [Array]::Resize([ref]$buffer, $read)
        }
        return $buffer
    }
    finally {
        $stream.Dispose()
    }
}

function Write-BootSector {
    param([string]$Label, [string]$Path)
    $boot = Read-FileBytes -Path $Path -Offset 1MB -Count 512
    if ($boot.Length -lt 512) {
        Write-Line "$Label boot sector unreadable"
        return
    }
    $oem = [Text.Encoding]::ASCII.GetString($boot, 3, 8)
    Write-Line "$Label boot OEM='$oem' bpb[0x0B..0x53]= $(Format-Hex $boot[0x0B..0x53])"
    Write-Line "$Label boot tail[0x1F0..0x1FF]= $(Format-Hex $boot[0x1F0..0x1FF])"
}

function Write-RecentFilesystemEvents {
    param([DateTime]$Since)
    foreach ($log in @("Microsoft-Windows-Ntfs/Operational", "Microsoft-Windows-Ntfs/WHC", "System")) {
        $events = @()
        try {
            $filter = @{ LogName = $log; StartTime = $Since }
            $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
                Where-Object { $log -ne "System" -or $_.ProviderName -match "Ntfs|exfat|volmgr|partmgr|disk|VHDMP|Microsoft-Windows-FilterManager|Microsoft-Windows-Kernel-General" } |
                Select-Object -First 25)
        }
        catch {
            if ($_.Exception.Message -notmatch "No events were found") {
                Write-Line "event query for $log failed: $($_.Exception.Message)"
            }
        }
        foreach ($event in $events) {
            $message = ($event.Message -replace "`r?`n", " ")
            if ($message.Length -gt 600) {
                $message = $message.Substring(0, 600) + "..."
            }
            Write-Line "event $log #$($event.Id) $($event.ProviderName) $($event.TimeCreated.ToString('o')): $message"
        }
    }
}

function Write-AttachedObservation {
    param([string]$Label, [string]$Path)
    $image = Get-DiskImage -ImagePath $Path -StorageType VHD
    Write-Line "$Label attached=$($image.Attached) number=$($image.Number) size=$($image.Size)"
    $disk = @($image | Get-Disk) | Select-Object -First 1
    if ($null -eq $disk) {
        Write-Line "$Label no disk object"
        return
    }
    Write-Line ("{0} disk: Number={1} Size={2} Style={3} ReadOnly={4} Offline={5} OfflineReason={6} Operational={7} Health={8}" -f `
        $Label, $disk.Number, $disk.Size, $disk.PartitionStyle, $disk.IsReadOnly, $disk.IsOffline, $disk.OfflineReason, $disk.OperationalStatus, $disk.HealthStatus)
    foreach ($partition in @($disk | Get-Partition)) {
        Write-Line ("{0} partition: Offset={1} Size={2} MbrType={3} Type={4} Letter=[{5}] AccessPaths={6}" -f `
            $Label, $partition.Offset, $partition.Size, $partition.MbrType, $partition.Type, $partition.DriveLetter, ($partition.AccessPaths -join ';'))
        $volumes = @($partition | Get-Volume)
        foreach ($volume in $volumes) {
            $attempt = 0
            while ([string]::IsNullOrWhiteSpace($volume.FileSystem) -and $attempt -lt 3) {
                $attempt++
                $null = Get-ChildItem -LiteralPath $volume.Path -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 500
                $volume = @($partition | Get-Volume) | Select-Object -First 1
            }
            Write-Line ("{0} volume: Path={1} FileSystem='{2}' Type={3} Label='{4}' Size={5} Remaining={6} Health={7} Operational={8}" -f `
                $Label, $volume.Path, $volume.FileSystem, $volume.FileSystemType, $volume.FileSystemLabel, $volume.Size, $volume.SizeRemaining, $volume.HealthStatus, $volume.OperationalStatus)
            if (-not [string]::IsNullOrWhiteSpace($volume.Path)) {
                & "$env:SystemRoot\System32\fsutil.exe" fsinfo volumeinfo $volume.Path 2>&1 | ForEach-Object { Write-Line "$Label fsutil: $_" }
                if ($volume.FileSystem -ieq "NTFS") {
                    & "$env:SystemRoot\System32\fsutil.exe" fsinfo ntfsinfo $volume.Path 2>&1 | ForEach-Object { Write-Line "$Label ntfsinfo: $_" }
                }
                $target = $volume.Path.TrimEnd('\')
                $chkdskLines = @(& "$env:SystemRoot\System32\chkdsk.exe" $target 2>&1 | ForEach-Object { $_.ToString() })
                Write-Line "$Label chkdsk exit=$LASTEXITCODE lines=$($chkdskLines.Count)"
                foreach ($line in $chkdskLines) {
                    if (-not [string]::IsNullOrWhiteSpace($line)) {
                        Write-Line "$Label chkdsk: $line"
                    }
                }
                try {
                    $entries = @(Get-ChildItem -LiteralPath $volume.Path -Force -ErrorAction Stop | Select-Object -First 16)
                    Write-Line ("{0} root entries: {1}" -f $Label, (($entries | ForEach-Object { $_.Name }) -join ', '))
                }
                catch {
                    Write-Line "$Label root listing failed: $($_.Exception.Message)"
                }
            }
        }
    }
}

function Invoke-ReadOnlyProbe {
    param([string]$Label, [string]$Path)
    $since = [DateTime]::Now.AddSeconds(-2)
    $before = Get-Sha256 -Path $Path
    Write-BootSector -Label $Label -Path $Path
    try {
        $null = Mount-DiskImage -ImagePath $Path -StorageType VHD -Access ReadOnly -NoDriveLetter -PassThru -ErrorAction Stop
        Write-AttachedObservation -Label "$Label(ro)" -Path $Path
    }
    catch {
        Write-Line "$Label(ro) attach failed: $($_.Exception.Message)"
    }
    finally {
        $null = Dismount-DiskImage -ImagePath $Path -StorageType VHD -ErrorAction SilentlyContinue
    }
    $after = Get-Sha256 -Path $Path
    Write-Line "$Label(ro) sha256 before=$before after=$after unchanged=$($before -eq $after)"
    Write-RecentFilesystemEvents -Since $since
}

function Write-ChangedBlocks {
    param([string]$Label, [string]$Original, [string]$Modified)
    $a = [IO.File]::ReadAllBytes($Original)
    $b = [IO.File]::ReadAllBytes($Modified)
    if ($a.Length -ne $b.Length) {
        Write-Line "$Label length changed $($a.Length) -> $($b.Length)"
    }
    $limit = [Math]::Min($a.Length, $b.Length)
    $block = 4096
    $changed = New-Object System.Collections.Generic.List[string]
    $left = New-Object byte[] $block
    $right = New-Object byte[] $block
    for ($offset = 0; $offset -lt $limit; $offset += $block) {
        $count = [Math]::Min($block, $limit - $offset)
        [Buffer]::BlockCopy($a, $offset, $left, 0, $count)
        [Buffer]::BlockCopy($b, $offset, $right, 0, $count)
        if (-not [Linq.Enumerable]::SequenceEqual([byte[]]$left, [byte[]]$right)) {
            $partitionRelative = $offset - 1MB
            $cluster = if ($partitionRelative -ge 0) { [Math]::Floor($partitionRelative / 4096) } else { -1 }
            $changed.Add(("0x{0:X} (partition+0x{1:X}, cluster {2})" -f $offset, $partitionRelative, $cluster))
            if ($changed.Count -ge 96) {
                $changed.Add("...")
                break
            }
        }
    }
    Write-Line "$Label changed 4 KiB blocks: $($changed.Count)"
    foreach ($entry in $changed) {
        Write-Line "$Label   $entry"
    }
}

function Invoke-WritableCopyProbe {
    param([string]$Label, [string]$Path)
    $copy = Join-Path $scratch ("writable-copy-" + [IO.Path]::GetFileName($Path))
    Copy-Item -LiteralPath $Path -Destination $copy -Force
    $since = [DateTime]::Now.AddSeconds(-2)
    try {
        $null = Mount-DiskImage -ImagePath $copy -StorageType VHD -NoDriveLetter -PassThru -ErrorAction Stop
        Write-AttachedObservation -Label "$Label(rw-copy)" -Path $copy
    }
    catch {
        Write-Line "$Label(rw-copy) attach failed: $($_.Exception.Message)"
    }
    finally {
        $null = Dismount-DiskImage -ImagePath $copy -StorageType VHD -ErrorAction SilentlyContinue
    }
    Write-ChangedBlocks -Label "$Label(rw-copy)" -Original $Path -Modified $copy
    Write-RecentFilesystemEvents -Since $since
    Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue
}

function New-ControlVhd {
    param([string]$FileSystem)
    $path = Join-Path $scratch "control-$FileSystem.vhd"
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Force
    }
    $script = Join-Path $scratch "control-$FileSystem.diskpart.txt"
    @(
        "create vdisk file=`"$path`" maximum=40 type=fixed",
        "select vdisk file=`"$path`"",
        "attach vdisk",
        "convert mbr",
        "create partition primary offset=1024",
        "format fs=$FileSystem quick label=CTRL$FileSystem",
        "detach vdisk",
        "exit"
    ) | Set-Content -LiteralPath $script -Encoding ASCII
    $output = @(& "$env:SystemRoot\System32\diskpart.exe" /s $script 2>&1 | ForEach-Object { $_.ToString() })
    Write-Line "control $FileSystem diskpart exit=$LASTEXITCODE"
    foreach ($line in $output) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            Write-Line "control $FileSystem diskpart: $line"
        }
    }
    if (Test-Path -LiteralPath $path) {
        return $path
    }
    return $null
}

Write-Line "host $([Environment]::OSVersion.VersionString) powershell $($PSVersionTable.PSVersion) ntfs.sys $((Get-Item "$env:SystemRoot\System32\drivers\ntfs.sys").VersionInfo.FileVersion) exfat.sys $((Get-Item "$env:SystemRoot\System32\drivers\exfat.sys").VersionInfo.FileVersion)"

foreach ($name in $Vhds) {
    $path = Join-Path $fixtureDirectory $name
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Line "$name missing"
        continue
    }
    Write-Line "===== $name ====="
    Invoke-ReadOnlyProbe -Label $name -Path $path
    if (-not $SkipWritableCopy) {
        Invoke-WritableCopyProbe -Label $name -Path $path
    }
}

if (-not $SkipControl) {
    foreach ($fileSystem in @("ntfs", "exfat")) {
        Write-Line "===== Windows-formatted control ($fileSystem) ====="
        $control = New-ControlVhd -FileSystem $fileSystem
        if ($null -ne $control) {
            Invoke-ReadOnlyProbe -Label "control-$fileSystem" -Path $control
            Remove-Item -LiteralPath $control -Force -ErrorAction SilentlyContinue
        }
    }
}

Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
Write-Line "done (diagnostic only; exit 0)"
exit 0
