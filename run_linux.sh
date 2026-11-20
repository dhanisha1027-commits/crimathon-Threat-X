#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
if [ ! -f data/threatx.sqlite ]; then python3 seed_demo.py; fi
printf 'Open http://127.0.0.1:8765 in your browser.\n'
printf 'Demo credentials: cat .demo-credentials.txt\n'
python3 app.py
