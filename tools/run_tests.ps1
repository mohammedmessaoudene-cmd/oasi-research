$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Push-Location $root
try {
    cargo +stable-x86_64-pc-windows-gnu test --locked --lib
    cargo +stable-x86_64-pc-windows-gnu test --locked --test authority
    python -I -B tools\verify_release.py .
    Write-Output 'WINDOWS PORTABLE SUBSET: PASS (PARTIAL; full Linux suite not executed)'
} finally {
    Pop-Location
}
