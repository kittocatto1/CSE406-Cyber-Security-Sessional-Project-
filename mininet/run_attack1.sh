#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

if [[ $EUID -ne 0 ]]; then
    echo "> Re-running as root"
    exec sudo "$0" "$@"
fi

echo "> Cleaning up any leftover Mininet state from a previous run"
mn -c > /dev/null 2>&1 || true

echo "Launching the Attack 1 mininet demo"
echo
/usr/bin/python3 auto_attack1.py
