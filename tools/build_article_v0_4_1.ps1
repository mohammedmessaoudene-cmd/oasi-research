$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
& python -I -B (Join-Path $root 'tools\build_article_v0_4_1_verified.py') --root $root @args
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
