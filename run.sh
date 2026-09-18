#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "Este pacote foi preparado para Linux x86_64."
  exit 1
fi

if [[ ! -f wordlists/optional/rockyou.txt ]]; then
  echo "Preparando RockYou na primeira execução..."
  gzip -dc wordlists/optional/rockyou.txt.gz > wordlists/optional/rockyou.txt.tmp
  mv wordlists/optional/rockyou.txt.tmp wordlists/optional/rockyou.txt
fi

if ! ./hashcat/hashcat.bin -I >/dev/null 2>&1; then
  echo "Hashcat não encontrou um dispositivo OpenCL."
  echo "No Ubuntu/Debian, instale o driver da GPU ou use: sudo apt install pocl-opencl-icd"
  exit 1
fi

exec ./registration-audit
