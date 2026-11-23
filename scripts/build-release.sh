#!/usr/bin/env bash
# Builds Terraform Registry release assets for a version into release/:
# one zip per platform, the registry manifest, and SHA256SUMS. Signing
# SHA256SUMS happens separately, in the release workflow's publish job.
#
# Usage: scripts/build-release.sh v1.2.3
set -euo pipefail

tag="${1:?usage: $0 vX.Y.Z}"
if [[ ! "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "version must look like v1.2.3, got '$tag'" >&2
  exit 1
fi
version="${tag#v}"
name="terraform-provider-heist"

mkdir release
build_dir="$(mktemp -d)"
trap 'rm -r -- "$build_dir"' EXIT

for target in darwin/amd64 darwin/arm64 linux/386 linux/amd64 linux/arm linux/arm64 windows/386 windows/amd64 windows/arm64; do
  goos="${target%/*}"
  goarch="${target#*/}"
  ext=""
  [ "$goos" = windows ] && ext=".exe"
  binary="$build_dir/${goos}_${goarch}/${name}_${tag}${ext}"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$binary" .
  # The registry expects the binary at the root of each zip.
  (cd "$(dirname "$binary")" && zip -q -X "$OLDPWD/release/${name}_${version}_${goos}_${goarch}.zip" "$(basename "$binary")")
done

cp terraform-registry-manifest.json "release/${name}_${version}_manifest.json"
(cd release && sha256sum -- * > "${name}_${version}_SHA256SUMS")
