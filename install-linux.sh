#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_BIN="${TARGET_BIN:-/usr/local/bin/ue}"

chmod +x "${ROOT_DIR}/ue"
chmod +x "${ROOT_DIR}/cli/ue.js"
ln -sf "${ROOT_DIR}/ue" "${TARGET_BIN}"

echo "Universal Engine CLI installed:"
echo "  launcher: ${ROOT_DIR}/ue"
echo "  symlink : ${TARGET_BIN}"
echo
echo "Try:"
echo "  ue --status"
