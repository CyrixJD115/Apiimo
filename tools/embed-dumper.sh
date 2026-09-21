#!/bin/sh
# Build the vendored Il2CppDumper (apiimo-il2cpp) as a self-contained
# single-file executable and embed its compressed image + config.json into
# apiimo-api/assets/ for include_bytes! embedding.
#
# Requires: dotnet SDK 8, zstd.
set -eu
cd "$(dirname "$0")/.."

for tool in dotnet zstd; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "embed-dumper: '$tool' is required but not on PATH" >&2
        exit 1
    fi
done

ASSETS=apiimo-api/assets
PUBLISH="$ASSETS/.publish"

dotnet publish apiimo-il2cpp/Il2CppDumper \
    -c Release -f net8.0 -r linux-x64 \
    --self-contained true -p:PublishSingleFile=true \
    -o "$PUBLISH" -v q

zstd -f -19 -T0 -q "$PUBLISH/Il2CppDumper" -o "$ASSETS/il2cpp-dumper.sfx.zst"
cp "$PUBLISH/config.json" "$ASSETS/config.json"
rm -rf "$PUBLISH"

echo "embed-dumper: assets ready"
ls -la "$ASSETS/il2cpp-dumper.sfx.zst" "$ASSETS/config.json"
