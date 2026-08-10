[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    Write-Host '[ STARCONVERTER :: CHECK ]'
    Write-Host '[RUST] cargo fmt --check'
    cargo fmt --all -- --check

    Write-Host '[RUST] cargo clippy'
    cargo clippy --workspace --all-targets -- -D warnings

    Write-Host '[RUST] cargo test'
    cargo test --workspace

    $goCommand = Get-Command go -ErrorAction SilentlyContinue
    if ($null -eq $goCommand) {
        Write-Warning '[GO] toolchain not installed; lab checks skipped locally (CI still runs them).'
    }
    else {
        Write-Host '[GO] gofmt + go test'
        $unformatted = gofmt -l .\lab
        if ($unformatted) {
            throw "Go files need formatting: $($unformatted -join ', ')"
        }
        Push-Location .\lab
        try {
            go test ./...
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
