#!/usr/bin/env bash
# Builds the tarball the customer installs: a self-contained single binary (no .NET on the host), the systemd unit,
# the install script and the production settings. Used by `make package` and by the Docker lab, so the lab installs
# exactly what a customer gets.
#   deploy/package.sh <version> <rid: linux-x64|linux-arm64> <output dir>
set -euo pipefail

VERSION="${1:?version}"
RID="${2:?runtime id, e.g. linux-x64}"
OUT="${3:?output directory}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
NAME="xrcopilotlab-intrusion-mcp-${VERSION}-${RID}"
DIST="${OUT}/${NAME}"

rm -rf "$DIST" && mkdir -p "$DIST"
dotnet publish "$HERE/src/XrCopilotLab.Intrusion.Mcp.Server/XrCopilotLab.Intrusion.Mcp.Server.csproj" \
  -c Release -r "$RID" --self-contained true -p:PublishSingleFile=true -p:DebugType=none -p:Version="$VERSION" -o "$DIST/bin"
cp "$HERE/deploy/linux/xrcopilotlab-intrusion-mcp.service" "$HERE/deploy/linux/install.sh" "$HERE/deploy/linux/appsettings.Production.json" "$DIST/"
chmod +x "$DIST/install.sh"
tar -C "$OUT" -czf "${DIST}.tar.gz" "$NAME"
echo "${DIST}.tar.gz"
