"""Run once to seed only synthetic test data and credentials."""
import os
import secrets
from pathlib import Path
from core import ROOT, connect, create_admin, init_db, issue_key, seed

init_db()
with connect() as db:
    existing = db.execute('SELECT COUNT(*) FROM admins').fetchone()[0]
if existing:
    print('Database already initialized. For a fresh setup, delete data/threatx.sqlite and rerun.')
    raise SystemExit(0)
seed()
password = secrets.token_urlsafe(14)
create_admin('admin', password)
token = issue_key()
contents = ('ThreatX NEEDZERO LOCAL DEMO CREDENTIALS - DO NOT SHARE\n'
            'Admin username: admin\n'
            f'Admin password: {password}\n'
            f'TallyBridge synthetic API token: {token}\n'
            'These are only for local synthetic demo. Delete this file after the event.\n')
path = ROOT / '.demo-credentials.txt'
with open(path, 'w', encoding='utf8') as f:
    f.write(contents)
try:
    os.chmod(path, 0o600)
except OSError:
    pass
print('Sample vendors, admin account, and legacy demonstration integration created.')
print('Your local credentials were saved to .demo-credentials.txt')
print('Open the file and keep the token available for your browser demo.')
