#!/usr/bin/env sh
set -eu
root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT INT TERM
cp -R "$root/paper/v0.3/source/." "$build/"
export SOURCE_DATE_EPOCH=1767225600
export FORCE_SOURCE_DATE=1
cd "$build"
pdflatex -interaction=nonstopmode -halt-on-error main.tex
biber main
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdflatex -interaction=nonstopmode -halt-on-error main.tex
cp main.pdf "$root/paper/v0.3/OASI_SCIENTIFIC_ARTICLE_PREPRINT_V0_3.pdf"
