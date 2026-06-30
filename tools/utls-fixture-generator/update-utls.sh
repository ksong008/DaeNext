#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

version="${1:-latest}"

go get "github.com/refraction-networking/utls@${version}"
go mod tidy
go list -m github.com/refraction-networking/utls
