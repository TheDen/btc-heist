#!/usr/bin/env bash
set -euo pipefail

URL="http://addresses.loyce.club/Bitcoin_addresses_LATEST.txt.gz"
OUT="Bitcoin_addresses_LATEST.txt"

echo "Downloading ${URL}..."
curl -fL "$URL" | gunzip -c > "$OUT"
echo "Saved to ${OUT} ($(wc -l < "$OUT") addresses)"
