#!/bin/sh
set -eu
workdir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$workdir/webui"
npm ci
npm run build:embed
cd "$workdir/apps"
go build -o cmd/web/hackernel-web ./cmd/web
