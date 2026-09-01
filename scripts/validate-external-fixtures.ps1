param(
    [string]$ValidatorRoot = "/tmp/starconverter-validators-current/root",
    [switch]$SkipExport
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$fixtureRoot = Join-Path $repoRoot "target\external-validator-fixtures"
$exfatImage = Join-Path $fixtureRoot "exfat-structural-recommended-upcase.img"
$ntfsImage = Join-Path $fixtureRoot "ntfs-structural-activation-blocked.img"
$ntfsLargeClusterImage = Join-Path $fixtureRoot "ntfs-structural-64k-cluster.img"
$exfatVhd = Join-Path $fixtureRoot "exfat-structural-validation.vhd"
$ntfsVhd = Join-Path $fixtureRoot "ntfs-structural-validation.vhd"
$richExfatImage = Join-Path $fixtureRoot "exfat-rich-namespace-payload.img"
$richNtfsImage = Join-Path $fixtureRoot "ntfs-rich-namespace-payload.img"
$convertedNtfsImage = Join-Path $fixtureRoot "converted-rich-exfat-to-ntfs.img"
$convertedNtfsEscrow = Join-Path $fixtureRoot "converted-rich-exfat-to-ntfs.img.starconverter-escrow"
$convertedExfatImage = Join-Path $fixtureRoot "converted-rich-ntfs-to-exfat.img"
$convertedExfatEscrow = Join-Path $fixtureRoot "converted-rich-ntfs-to-exfat.img.starconverter-escrow"
$windowsNtfsPartition = Join-Path $fixtureRoot "converted-rich-exfat-to-ntfs-windows-partition.img"
$windowsNtfsEscrow = Join-Path $fixtureRoot "converted-rich-exfat-to-ntfs-windows-partition.img.starconverter-escrow"
$windowsNtfsVhd = Join-Path $fixtureRoot "converted-rich-exfat-to-ntfs-windows.vhd"
$windowsExfatPartition = Join-Path $fixtureRoot "converted-rich-ntfs-to-exfat-windows-partition.img"
$windowsExfatEscrow = Join-Path $fixtureRoot "converted-rich-ntfs-to-exfat-windows-partition.img.starconverter-escrow"
$windowsExfatVhd = Join-Path $fixtureRoot "converted-rich-ntfs-to-exfat-windows.vhd"
$manifest = Join-Path $fixtureRoot "rich-fixture-manifest.txt"
$edgeExfatImage = Join-Path $fixtureRoot "exfat-edge-corpus.img"
$edgeNtfsImage = Join-Path $fixtureRoot "ntfs-edge-corpus.img"
$convertedEdgeNtfsImage = Join-Path $fixtureRoot "converted-edge-exfat-to-ntfs.img"
$convertedEdgeNtfsEscrow = Join-Path $fixtureRoot "converted-edge-exfat-to-ntfs.img.starconverter-escrow"
$convertedEdgeExfatImage = Join-Path $fixtureRoot "converted-edge-ntfs-to-exfat.img"
$convertedEdgeExfatEscrow = Join-Path $fixtureRoot "converted-edge-ntfs-to-exfat.img.starconverter-escrow"
$edgeManifest = Join-Path $fixtureRoot "edge-corpus-manifest.tsv"
$misalignedNtfsImage = Join-Path $fixtureRoot "ntfs-misaligned-8k-payload.img"
$relocatedExfatImage = Join-Path $fixtureRoot "converted-misaligned-ntfs-to-exfat.img"
$relocatedExfatEscrow = Join-Path $fixtureRoot "converted-misaligned-ntfs-to-exfat.img.starconverter-escrow"
$relocationManifest = Join-Path $fixtureRoot "misaligned-relocation-manifest.tsv"
$allFixtures = @(
    $exfatImage,
    $ntfsImage,
    $ntfsLargeClusterImage,
    $exfatVhd,
    $ntfsVhd,
    $richExfatImage,
    $richNtfsImage,
    $convertedNtfsImage,
    $convertedNtfsEscrow,
    $convertedExfatImage,
    $convertedExfatEscrow,
    $windowsNtfsPartition,
    $windowsNtfsEscrow,
    $windowsNtfsVhd,
    $windowsExfatPartition,
    $windowsExfatEscrow,
    $windowsExfatVhd,
    $manifest,
    $edgeExfatImage,
    $edgeNtfsImage,
    $convertedEdgeNtfsImage,
    $convertedEdgeNtfsEscrow,
    $convertedEdgeExfatImage,
    $convertedEdgeExfatEscrow,
    $edgeManifest,
    $misalignedNtfsImage,
    $relocatedExfatImage,
    $relocatedExfatEscrow,
    $relocationManifest
)

function Convert-ToWslPath {
    param([Parameter(Mandatory = $true)][string]$WindowsPath)

    $resolved = (Resolve-Path -LiteralPath $WindowsPath).Path
    if ($resolved.Length -lt 4 -or $resolved[1] -ne ':' -or $resolved[2] -ne '\') {
        throw "Only absolute drive-letter paths can be translated safely: $resolved"
    }
    $drive = [char]::ToLowerInvariant($resolved[0])
    $tail = $resolved.Substring(3).Replace('\', '/')
    return "/mnt/$drive/$tail"
}

function Invoke-WslValidator {
    param(
        [Parameter(Mandatory = $true)][string]$Program,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $libraryPath = "$ValidatorRoot/lib/x86_64-linux-gnu:$ValidatorRoot/usr/lib/x86_64-linux-gnu"
    & wsl.exe env "LD_LIBRARY_PATH=$libraryPath" "$ValidatorRoot/$Program" @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Read-only validator $Program failed with exit code $LASTEXITCODE"
    }
}

Push-Location $repoRoot
try {
    if (-not $SkipExport) {
        & cargo test -p starconverter-core --test export_external_fixtures -- --ignored --nocapture
        if ($LASTEXITCODE -ne 0) {
            throw "Fixture export failed with exit code $LASTEXITCODE"
        }
    }

    foreach ($path in $allFixtures) {
        $item = Get-Item -LiteralPath $path
        if (-not ($item -is [System.IO.FileInfo])) {
            throw "External validator input is not a regular file: $path"
        }
        if (-not $item.FullName.StartsWith($fixtureRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "External validator input escaped the fixture directory: $($item.FullName)"
        }
    }

    $before = @{}
    foreach ($path in $allFixtures) {
        $before[$path] = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash
    }

    $exfatWsl = Convert-ToWslPath $exfatImage
    $ntfsWsl = Convert-ToWslPath $ntfsImage
    $ntfsLargeClusterWsl = Convert-ToWslPath $ntfsLargeClusterImage
    $richExfatWsl = Convert-ToWslPath $richExfatImage
    $richNtfsWsl = Convert-ToWslPath $richNtfsImage
    $convertedNtfsWsl = Convert-ToWslPath $convertedNtfsImage
    $convertedExfatWsl = Convert-ToWslPath $convertedExfatImage
    $edgeExfatWsl = Convert-ToWslPath $edgeExfatImage
    $edgeNtfsWsl = Convert-ToWslPath $edgeNtfsImage
    $convertedEdgeNtfsWsl = Convert-ToWslPath $convertedEdgeNtfsImage
    $convertedEdgeExfatWsl = Convert-ToWslPath $convertedEdgeExfatImage
    $edgeManifestWsl = Convert-ToWslPath $edgeManifest
    $misalignedNtfsWsl = Convert-ToWslPath $misalignedNtfsImage
    $relocatedExfatWsl = Convert-ToWslPath $relocatedExfatImage
    $relocationManifestWsl = Convert-ToWslPath $relocationManifest
    $exfatMountValidatorWsl = Convert-ToWslPath (Join-Path $repoRoot "scripts\validate-exfat-readonly-mount.sh")
    $mountValidatorWsl = Convert-ToWslPath (Join-Path $repoRoot "scripts\validate-ntfs-readonly-mount.sh")
    Invoke-WslValidator "usr/sbin/fsck.exfat" @("-n", $exfatWsl)
    Invoke-WslValidator "bin/ntfsinfo" @("-m", $ntfsWsl)
    Invoke-WslValidator "bin/ntfsls" @("-s", "-l", $ntfsWsl)
    Invoke-WslValidator "bin/ntfsfix" @("-n", $ntfsWsl)
    Invoke-WslValidator "bin/ntfsinfo" @("-m", $ntfsLargeClusterWsl)
    Invoke-WslValidator "bin/ntfsls" @("-s", "-l", $ntfsLargeClusterWsl)
    Invoke-WslValidator "bin/ntfsfix" @("-n", $ntfsLargeClusterWsl)
    Invoke-WslValidator "usr/sbin/fsck.exfat" @("-n", $richExfatWsl)
    & wsl.exe -u root -- sh $exfatMountValidatorWsl $ValidatorRoot $richExfatWsl
    if ($LASTEXITCODE -ne 0) {
        throw "Read-only exFAT mount validation failed with exit code $LASTEXITCODE"
    }
    Invoke-WslValidator "bin/ntfsinfo" @("-m", $richNtfsWsl)
    Invoke-WslValidator "bin/ntfsls" @("-a", "-l", "-R", "-p", "/", $richNtfsWsl)
    Invoke-WslValidator "bin/ntfsls" @("-a", "-l", "-p", "/alpha", $richNtfsWsl)
    $omegaDirectory = "/alpha/$([char]0x03A9)mega"
    Invoke-WslValidator "bin/ntfsls" @("-a", "-l", "-p", $omegaDirectory, $richNtfsWsl)
    Invoke-WslValidator "bin/ntfsfix" @("-n", $richNtfsWsl)
    & wsl.exe -u root -- sh $mountValidatorWsl $ValidatorRoot $richNtfsWsl
    if ($LASTEXITCODE -ne 0) {
        throw "Read-only NTFS mount validation failed with exit code $LASTEXITCODE"
    }
    Invoke-WslValidator "usr/sbin/fsck.exfat" @("-n", $convertedExfatWsl)
    & wsl.exe -u root -- sh $exfatMountValidatorWsl $ValidatorRoot $convertedExfatWsl
    if ($LASTEXITCODE -ne 0) {
        throw "Read-only converted exFAT mount validation failed with exit code $LASTEXITCODE"
    }
    Invoke-WslValidator "bin/ntfsinfo" @("-m", $convertedNtfsWsl)
    Invoke-WslValidator "bin/ntfsls" @("-a", "-l", "-R", "-p", "/", $convertedNtfsWsl)
    Invoke-WslValidator "bin/ntfsfix" @("-n", $convertedNtfsWsl)
    & wsl.exe -u root -- sh $mountValidatorWsl $ValidatorRoot $convertedNtfsWsl
    if ($LASTEXITCODE -ne 0) {
        throw "Read-only converted NTFS mount validation failed with exit code $LASTEXITCODE"
    }
    Invoke-WslValidator "usr/sbin/fsck.exfat" @("-n", $edgeExfatWsl)
    & wsl.exe -u root -- sh $exfatMountValidatorWsl $ValidatorRoot $edgeExfatWsl $edgeManifestWsl
    if ($LASTEXITCODE -ne 0) {
        throw "Read-only edge-corpus exFAT mount validation failed with exit code $LASTEXITCODE"
    }
    Invoke-WslValidator "bin/ntfsinfo" @("-m", $edgeNtfsWsl)
    Invoke-WslValidator "bin/ntfsls" @("-a", "-l", "-R", "-p", "/", $edgeNtfsWsl)
    Invoke-WslValidator "bin/ntfsfix" @("-n", $edgeNtfsWsl)
    & wsl.exe -u root -- sh $mountValidatorWsl $ValidatorRoot $edgeNtfsWsl $edgeManifestWsl
    if ($LASTEXITCODE -ne 0) {
        throw "Read-only edge-corpus NTFS mount validation failed with exit code $LASTEXITCODE"
    }
    Invoke-WslValidator "usr/sbin/fsck.exfat" @("-n", $convertedEdgeExfatWsl)
    & wsl.exe -u root -- sh $exfatMountValidatorWsl $ValidatorRoot $convertedEdgeExfatWsl $edgeManifestWsl
    if ($LASTEXITCODE -ne 0) {
        throw "Read-only converted edge-corpus exFAT mount validation failed with exit code $LASTEXITCODE"
    }
    Invoke-WslValidator "bin/ntfsinfo" @("-m", $convertedEdgeNtfsWsl)
    Invoke-WslValidator "bin/ntfsls" @("-a", "-l", "-R", "-p", "/", $convertedEdgeNtfsWsl)
    Invoke-WslValidator "bin/ntfsfix" @("-n", $convertedEdgeNtfsWsl)
    & wsl.exe -u root -- sh $mountValidatorWsl $ValidatorRoot $convertedEdgeNtfsWsl $edgeManifestWsl
    if ($LASTEXITCODE -ne 0) {
        throw "Read-only converted edge-corpus NTFS mount validation failed with exit code $LASTEXITCODE"
    }
    Invoke-WslValidator "bin/ntfsinfo" @("-m", $misalignedNtfsWsl)
    Invoke-WslValidator "bin/ntfsfix" @("-n", $misalignedNtfsWsl)
    Invoke-WslValidator "usr/sbin/fsck.exfat" @("-n", $relocatedExfatWsl)
    & wsl.exe -u root -- sh $exfatMountValidatorWsl $ValidatorRoot $relocatedExfatWsl $relocationManifestWsl
    if ($LASTEXITCODE -ne 0) {
        throw "Read-only relocated exFAT mount validation failed with exit code $LASTEXITCODE"
    }

    foreach ($path in $allFixtures) {
        $after = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash
        if ($after -ne $before[$path]) {
            throw "Read-only validation changed fixture bytes: $path"
        }
        Write-Host "[PASS] $after  $path"
    }
}
finally {
    Pop-Location
}
