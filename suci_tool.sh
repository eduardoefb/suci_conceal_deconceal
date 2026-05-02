#!/usr/bin/env bash
# Ensure ./env exists with dependencies, then run suci_tool.py with that interpreter.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

ENV_PY="$ROOT/env/bin/python"

need_setup() {
  [[ ! -x "$ENV_PY" ]] && return 0
  if ! "$ENV_PY" -c "import customtkinter, pycrate_mobile, CryptoMobile" 2>/dev/null; then
    return 0
  fi
  return 1
}

if need_setup; then
  if ! command -v python3 >/dev/null 2>&1; then
    echo "suci_tool.sh: python3 not found. Install Python 3.10+ (with venv)." >&2
    exit 1
  fi
  python3 "$ROOT/suci_tool.py" --setup-env
fi

exec "$ENV_PY" "$ROOT/suci_tool.py" "$@"
