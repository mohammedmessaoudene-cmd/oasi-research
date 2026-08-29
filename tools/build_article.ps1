$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$source = Join-Path $root 'paper\v0.3\source'
$build = Join-Path ([System.IO.Path]::GetTempPath()) ('oasi-article-' + [guid]::NewGuid().ToString('N'))
Copy-Item -LiteralPath $source -Destination $build -Recurse
$env:SOURCE_DATE_EPOCH = '1767225600'
$env:FORCE_SOURCE_DATE = '1'
Push-Location $build
try {
    pdflatex --disable-installer -interaction=nonstopmode -halt-on-error main.tex
    biber main
    pdflatex --disable-installer -interaction=nonstopmode -halt-on-error main.tex
    pdflatex --disable-installer -interaction=nonstopmode -halt-on-error main.tex
    Copy-Item -LiteralPath (Join-Path $build 'main.pdf') -Destination (Join-Path $root 'paper\v0.3\OASI_SCIENTIFIC_ARTICLE_PREPRINT_V0_3.pdf')
} finally {
    Pop-Location
}
