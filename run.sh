#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "Este pacote foi preparado para Linux x86_64."
  exit 1
fi

if ! ./hashcat/hashcat.bin -I >/dev/null 2>&1; then
  echo "Hashcat não encontrou um dispositivo OpenCL."
  echo "No Ubuntu/Debian, instale o driver da GPU ou use: sudo apt install pocl-opencl-icd"
  exit 1
fi

# O código-fonte evita a dependência da glibc usada para empacotar o binário.
if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))'; then
  exec python3 src/registration_audit.py
fi

echo "Python 3.10+ não encontrado; tentando o executável portátil."
exec ./registration-audit
