#!/bin/sh
set -eu
cd "$(dirname "$0")"
python3 -m pytest -q test_func.py
case "${1:-vulnerable}" in
  vulnerable)
    if python3 -m pytest -q test_vuln.py; then
      echo 'vulnerability unexpectedly absent' >&2
      exit 1
    fi
    ;;
  fixed)
    python3 -m pytest -q test_vuln.py
    ;;
  *)
    echo 'usage: run-tests.sh [vulnerable|fixed]' >&2
    exit 2
    ;;
esac
