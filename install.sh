#!/usr/bin/env bash
# tapid install script — Linux + macOS
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/EyeRunnMan/tapid/main/install.sh | sh
#
# Optional env vars:
#   TAPID_VERSION  pin to a specific tag (default: latest release)
#   TAPID_DIR      install dir (default: ~/.local/bin)

set -euo pipefail

REPO="EyeRunnMan/tapid"
INSTALL_DIR="${TAPID_DIR:-$HOME/.local/bin}"

err() { echo "tapid-install: $*" >&2; exit 1; }

# Detect OS
case "$(uname -s)" in
  Linux)   os="linux" ;;
  Darwin)  os="darwin" ;;
  *)       err "unsupported OS: $(uname -s)" ;;
esac

# Detect arch
case "$(uname -m)" in
  x86_64|amd64)   arch="amd64" ;;
  aarch64|arm64)  arch="arm64" ;;
  *)              err "unsupported arch: $(uname -m)" ;;
esac

# Resolve version
ver="${TAPID_VERSION:-}"
if [ -z "$ver" ]; then
  ver=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -oE '"tag_name":\s*"[^"]+' | sed 's/.*"v\?//' | head -1)
  [ -n "$ver" ] || err "could not resolve latest release tag"
  ver="v${ver#v}"
fi

asset="tapid_${ver}_${os}_${arch}.tar.gz"
url="https://github.com/${REPO}/releases/download/${ver}/${asset}"
sha_url="${url}.sha256"

echo "→ tapid install: ${ver} ${os}/${arch}"
echo "→ download: ${url}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "${tmp}/${asset}" "$url" || err "download failed"
curl -fsSL -o "${tmp}/${asset}.sha256" "$sha_url" 2>/dev/null || true

if [ -f "${tmp}/${asset}.sha256" ]; then
  expected=$(awk '{print $1}' "${tmp}/${asset}.sha256")
  actual=$(sha256sum "${tmp}/${asset}" | awk '{print $1}')
  [ "$expected" = "$actual" ] || err "sha256 mismatch (expected $expected, got $actual)"
  echo "✓ sha256 verified"
else
  echo "⚠ no checksum file found, skipping verification"
fi

mkdir -p "$INSTALL_DIR"
tar -xzf "${tmp}/${asset}" -C "$tmp"
mv "${tmp}/tapid" "${INSTALL_DIR}/tapid"
chmod 0755 "${INSTALL_DIR}/tapid"

echo ""
echo "✓ installed: ${INSTALL_DIR}/tapid"
echo ""

# PATH check
case ":$PATH:" in
  *":${INSTALL_DIR}:"*)
    echo "✓ ${INSTALL_DIR} is on PATH — try: tapid help"
    ;;
  *)
    cat <<EOF
⚠ ${INSTALL_DIR} is NOT on your PATH.

Add to your shell rc:

  export PATH="${INSTALL_DIR}:\$PATH"

Then reopen your shell, or run:
  ${INSTALL_DIR}/tapid help
EOF
    ;;
esac
