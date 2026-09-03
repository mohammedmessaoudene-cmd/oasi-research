param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('pre-doi', 'post-doi')]
    [string]$ReleasePhase,

    [Parameter(Position = 1)]
    [string]$ExpectedSoftwareDoi,

    [Parameter(Position = 2)]
    [string]$ExpectedArticleDoi
)

$ErrorActionPreference = 'Stop'
if ($ReleasePhase -eq 'pre-doi') {
    if ($ExpectedSoftwareDoi -or $ExpectedArticleDoi) {
        throw 'DOI pins are forbidden in pre-doi mode'
    }
} elseif (-not $ExpectedSoftwareDoi -or -not $ExpectedArticleDoi) {
    throw 'post-doi mode requires ExpectedSoftwareDoi and ExpectedArticleDoi'
}
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Push-Location $root
$previousTarget = $env:CARGO_TARGET_DIR
$temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporaryTarget = [IO.Path]::GetFullPath((Join-Path $temporaryRoot ("oasi-v02-cargo-" + [Guid]::NewGuid().ToString('N'))))
if (-not $temporaryTarget.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'temporary Cargo target escaped the system temporary directory'
}
[IO.Directory]::CreateDirectory($temporaryTarget) | Out-Null
$env:CARGO_TARGET_DIR = $temporaryTarget
try {
    $cargo = Get-Command cargo -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $cargo) {
        $cargoPath = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
        if (-not (Test-Path -LiteralPath $cargoPath -PathType Leaf)) {
            throw 'cargo was not found on PATH or in the standard per-user location'
        }
        $cargoExe = $cargoPath
    } else {
        $cargoExe = $cargo.Source
    }
    $rustcExe = Join-Path (Split-Path -Parent $cargoExe) 'rustc.exe'
    if (-not (Test-Path -LiteralPath $rustcExe -PathType Leaf)) {
        throw 'rustc.exe was not found beside cargo.exe'
    }
    $rustcVersion = ((& $rustcExe +stable-x86_64-pc-windows-gnu --version) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $rustcVersion -ne 'rustc 1.97.1 (8bab26f4f 2026-07-14)') {
        throw "exact rustc 1.97.1 qualification build is required; observed: $rustcVersion"
    }
    $cargoVersion = ((& $cargoExe +stable-x86_64-pc-windows-gnu --version) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $cargoVersion -ne 'cargo 1.97.1 (c980f4866 2026-06-30)') {
        throw "exact cargo 1.97.1 qualification build is required; observed: $cargoVersion"
    }
    & $cargoExe +stable-x86_64-pc-windows-gnu test --offline --locked --lib
    if ($LASTEXITCODE -ne 0) { throw "cargo --lib failed with exit code $LASTEXITCODE" }
    & $cargoExe +stable-x86_64-pc-windows-gnu test --offline --locked --test authority
    if ($LASTEXITCODE -ne 0) { throw "cargo authority test failed with exit code $LASTEXITCODE" }
    $python = Get-Command python -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $runtimeJson = ((& $python.Source -I -B -c 'import json, platform, sqlite3, sys, zlib; import cryptography, yaml; print(json.dumps(dict(implementation=sys.implementation.name, python=platform.python_version(), pyyaml=yaml.__version__, cryptography=cryptography.__version__, sqlite=sqlite3.sqlite_version, zlib=zlib.ZLIB_RUNTIME_VERSION), sort_keys=True))') | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "Python runtime preflight failed with exit code $LASTEXITCODE" }
    $runtime = $runtimeJson | ConvertFrom-Json
    $expectedRuntime = [ordered]@{
        implementation = 'cpython'
        python = '3.11.9'
        pyyaml = '6.0.3'
        cryptography = '50.0.1'
        sqlite = '3.45.1'
        zlib = '1.3.1'
    }
    foreach ($field in $expectedRuntime.Keys) {
        if ($runtime.$field -ne $expectedRuntime[$field]) {
            throw "publication Python runtime pin mismatch for ${field}: observed $($runtime.$field), expected $($expectedRuntime[$field])"
        }
    }
    & $python.Source -I -B tools\verify_experiments.py .
    if ($LASTEXITCODE -ne 0) { throw "experiment verification failed with exit code $LASTEXITCODE" }
    & $python.Source -I -B tools\verify_aera_terminology.py --self-test
    if ($LASTEXITCODE -ne 0) { throw "AERA terminology self-test failed with exit code $LASTEXITCODE" }
    & $python.Source -I -B tools\verify_aera_terminology.py .
    if ($LASTEXITCODE -ne 0) { throw "AERA terminology verification failed with exit code $LASTEXITCODE" }
    $phaseArgument = if ($ReleasePhase -eq 'pre-doi') { '--pre-doi' } else { '--post-doi' }
    $verifyArguments = @('tools\verify_release.py', '.', $phaseArgument)
    if ($ReleasePhase -eq 'post-doi') {
        $verifyArguments += @('--expected-software-doi', $ExpectedSoftwareDoi, '--expected-article-doi', $ExpectedArticleDoi)
    }
    & $python.Source -I -B @verifyArguments
    if ($LASTEXITCODE -ne 0) { throw "release verification failed with exit code $LASTEXITCODE" }
    Write-Output 'WINDOWS BOUNDED SUBSET + SEALED S5/S6 DATA CHECKS: PASS (PARTIAL; Linux S5/S6 execution tests and full Rust Linux suite not executed)'
} finally {
    $env:CARGO_TARGET_DIR = $previousTarget
    if ($temporaryTarget.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase) -and [IO.Directory]::Exists($temporaryTarget)) {
        [IO.Directory]::Delete($temporaryTarget, $true)
    }
    Pop-Location
}
