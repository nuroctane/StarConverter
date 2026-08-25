[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-NativeSuccess {
    param([Parameter(Mandatory = $true)][string]$Description)

    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE"
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    Write-Host '[ STARCONVERTER :: CHECK ]'
    Write-Host '[RUST] cargo fmt --check'
    cargo fmt --all -- --check
    Assert-NativeSuccess 'cargo fmt --check'

    Write-Host '[RUST] cargo clippy'
    cargo clippy --workspace --all-targets -- -D warnings
    Assert-NativeSuccess 'cargo clippy'

    Write-Host '[RUST] cargo test'
    cargo test --workspace
    Assert-NativeSuccess 'cargo test'

    Write-Host '[RUST] compile bounded parser fuzz targets'
    cargo check --manifest-path .\fuzz\Cargo.toml --bins
    Assert-NativeSuccess 'cargo check for fuzz targets'

    $goCommand = Get-Command go -ErrorAction SilentlyContinue
    if ($null -eq $goCommand) {
        Write-Warning '[GO] toolchain not installed; lab checks skipped locally (CI still runs them).'
    }
    else {
        Write-Host '[GO] gofmt + go test'
        $unformatted = gofmt -l .\lab
        Assert-NativeSuccess 'gofmt'
        if ($unformatted) {
            throw "Go files need formatting: $($unformatted -join ', ')"
        }
        Push-Location .\lab
        try {
            go test ./...
            Assert-NativeSuccess 'go test'
        }
        finally {
            Pop-Location
        }
    }

    Write-Host '[READY] all available checks passed'
}
finally {
    Pop-Location
}
