param(
    [string]$ValidatorRoot = "/tmp/starconverter-validators-current/root",
    [string]$DebDirectory,
    [string]$ReportName,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$workspace = Join-Path $repoRoot "target"
$cli = Join-Path $workspace "debug\starconverter.exe"
if (-not $ReportName) {
    $ReportName = "formatter-ads-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
}
$report = Join-Path $workspace $ReportName

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

function Invoke-Wsl {
    param(
        [Parameter(Mandatory = $true)][string]$What,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & wsl.exe -- @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed with exit code $LASTEXITCODE"
    }
}

Push-Location $repoRoot
try {
    if (-not $SkipBuild) {
        & cargo build -p starconverter-cli
        if ($LASTEXITCODE -ne 0) {
            throw "CLI build failed with exit code $LASTEXITCODE"
        }
    }
    if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) {
        throw "CLI binary is missing: $cli"
    }
    if (Test-Path -LiteralPath $report) {
        throw "Report already exists; the probe never overwrites: $report"
    }

    $extractWsl = Convert-ToWslPath (Join-Path $repoRoot "scripts\extract-validator-bundle.sh")
    $runWsl = Convert-ToWslPath (Join-Path $repoRoot "scripts\run-formatter-ads-probe.sh")

    & wsl.exe -- test -x "$ValidatorRoot/sbin/mkntfs"
    if ($LASTEXITCODE -ne 0) {
        if (-not $DebDirectory) {
            throw "Validator root lacks NTFS-3G below $ValidatorRoot; pass -DebDirectory with the downloaded .deb packages to unpack it"
        }
        $debWsl = Convert-ToWslPath $DebDirectory
        Invoke-Wsl "Validator bundle extraction" @("sh", $extractWsl, $debWsl, $ValidatorRoot)
    }

    $workspaceWsl = Convert-ToWslPath $workspace
    $cliWsl = Convert-ToWslPath $cli
    $reportWsl = "$workspaceWsl/$ReportName"
    Invoke-Wsl "Formatter-origin probe" @("sh", $runWsl, $ValidatorRoot, $workspaceWsl, "--cli", $cliWsl, "--report", $reportWsl)

    # ConvertFrom-Json rejects the empty-string key the report uses for the unnamed stream.
    Add-Type -AssemblyName System.Web.Extensions
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $result = $serializer.DeserializeObject((Get-Content -LiteralPath $report -Raw -Encoding UTF8))
    if (-not $result["passed"]) {
        throw "Probe report did not pass: $report"
    }
    Write-Host "[PASS] $($result['schema'])  $report"
    foreach ($descriptor in $result["descriptors"]) {
        Write-Host ("  {0,-8} {1,-8} {2,5} bytes  {3}" -f $descriptor["image"], $descriptor["object"], $descriptor["bytes"], $descriptor["sha256"])
    }
}
finally {
    Pop-Location
}
