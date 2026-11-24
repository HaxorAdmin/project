#!/usr/bin/env sh
cd "$(dirname "$0")" || exit 1
if [ ! -x .venv/bin/python ]; then
    echo 'First-time Kali setup:'
    echo 'python3 -m venv .venv'
    echo '.venv/bin/python -m pip install -r requirements.txt'
    exit 1
fi
exec .venv/bin/python main.py "$@"
