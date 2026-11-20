"""ThreatX NEEDZERO: SQLite-backed demo policy and experimental access engine.

All records and identities are synthetic. This is NOT production-ready IAM.
"""
import hashlib
from contextlib import contextmanager
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get('THREATX_DB', ROOT / 'data' / 'threatx.sqlite'))
FIELDS = ('vendor_id', 'vendor_name', 'phone', 'email', 'bank_account', 'payment_status')
SENSITIVE_FIELDS = ('bank_account', 'payment_status')


@contextmanager
def connect():
    """Open a transaction and always close the SQLite connection."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA busy_timeout = 10000')
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS vendors(
            vendor_id TEXT PRIMARY KEY,
            vendor_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT NOT NULL,
            bank_account TEXT NOT NULL,
            payment_status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS admins(
            username TEXT PRIMARY KEY,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS api_keys(
            id INTEGER PRIMARY KEY,
            label TEXT NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            read_fields TEXT NOT NULL,
            write_fields TEXT NOT NULL,
            vendor_scope TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            at_utc INTEGER NOT NULL,
            actor TEXT NOT NULL,
            method TEXT NOT NULL,
            record_id TEXT NOT NULL,
            requested TEXT NOT NULL,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL);
        ''')


def pw_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 300_000).hex()


def create_admin(username, password):
    salt = secrets.token_hex(16)
    with connect() as db:
        db.execute('INSERT OR REPLACE INTO admins(username,salt,password_hash) VALUES(?,?,?)',
                   (username, salt, pw_hash(password, salt)))


def verify_admin(username, password):
    with connect() as db:
        row = db.execute('SELECT * FROM admins WHERE username=?', (username,)).fetchone()
    return bool(row and hmac.compare_digest(row['password_hash'], pw_hash(password, row['salt'])))


def token_hash(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def issue_key(label='TallyBridge Connect (simulated legacy)', lifetime_hours=24):
    token = 'tx_' + secrets.token_urlsafe(32)
    with connect() as db:
        db.execute('''INSERT INTO api_keys(label,token_hash,read_fields,write_fields,vendor_scope,expires_at,active)
                   VALUES(?,?,?,?,?,?,1)''',
                   (label, token_hash(token), json.dumps(FIELDS), json.dumps(['phone', 'email', 'bank_account']),
                    '*', int(time.time()) + lifetime_hours * 3600))
    return token


def seed(reset=False):
    init_db()
    vendors = [
        ('V-0412', 'Coastal Packaging Ltd', '+91 90000 12345', 'coastal@example.test', '****4417', 'Pending'),
        ('V-0208', 'Southern Haulage', '+91 90000 22345', 'southern@example.test', '****4521', 'Paid'),
        ('V-0527', 'Metro Fuel Traders', '+91 90000 32345', 'metro@example.test', '****7284', 'Pending'),
        ('V-0681', 'Delta Supplies', '+91 90000 42345', 'delta@example.test', '****6219', 'Paid')]
    with connect() as db:
        if reset:
            db.execute('DELETE FROM vendors')
            db.execute('DELETE FROM audit')
        for record in vendors:
            db.execute('INSERT OR IGNORE INTO vendors VALUES(?,?,?,?,?,?)', record)


def get_key(token):
    if not token:
        return None
    with connect() as db:
        return db.execute('SELECT * FROM api_keys WHERE token_hash=?', (token_hash(token),)).fetchone()


def get_key_info():
    with connect() as db:
        rows = db.execute('SELECT id,label,read_fields,write_fields,vendor_scope,expires_at,active FROM api_keys ORDER BY id').fetchall()
    return [dict(r) | {'read_fields': json.loads(r['read_fields']), 'write_fields': json.loads(r['write_fields'])} for r in rows]


def audit(actor, method, vendor_id, fields, decision, reason):
    with connect() as db:
        db.execute('INSERT INTO audit(at_utc,actor,method,record_id,requested,decision,reason) VALUES(?,?,?,?,?,?,?)',
                   (int(time.time()), actor, method, vendor_id, ','.join(fields), decision, reason))


def authorize(token, action, vendor_id, fields):
    """Server-side check; returns (authorized, reason, key)."""
    key = get_key(token)
    if not key:
        return False, 'Invalid integration credential', None
    if not key['active']:
        return False, 'Integration credential revoked', key
    if key['expires_at'] <= int(time.time()):
        return False, 'Integration credential expired', key
    scope = key['vendor_scope']
    if scope != '*' and vendor_id not in set(json.loads(scope)):
        return False, 'Vendor outside approved record scope', key
    allowed_fields = json.loads(key['read_fields'] if action == 'read' else key['write_fields'])
    if not fields or any(f not in FIELDS for f in fields):
        return False, 'Unknown or empty requested field', key
    forbidden = sorted(set(fields) - set(allowed_fields))
    if forbidden:
        return False, 'Not permitted for field(s): ' + ', '.join(forbidden), key
    return True, 'Allowed by active integration contract', key


def read_vendor(token, vendor_id, fields):
    ok, reason, key = authorize(token, 'read', vendor_id, fields)
    actor = key['label'] if key else 'Unknown integration'
    if not ok:
        audit(actor, 'READ', vendor_id, fields, 'DENY', reason)
        return 403 if key else 401, {'error': 'ACCESS DENIED', 'reason': reason}
    # Whitelist column names before embedding in SQL: never use untrusted column names.
    columns = ', '.join(fields)
    with connect() as db:
        row = db.execute(f'SELECT {columns} FROM vendors WHERE vendor_id=?', (vendor_id,)).fetchone()
    if not row:
        audit(actor, 'READ', vendor_id, fields, 'DENY', 'Vendor does not exist')
        return 404, {'error': 'Not found'}
    audit(actor, 'READ', vendor_id, fields, 'ALLOW', reason)
    return 200, {'record': dict(row), 'exposed_fields': fields}


def write_vendor(token, vendor_id, changes):
    fields = list(changes)
    ok, reason, key = authorize(token, 'write', vendor_id, fields)
    actor = key['label'] if key else 'Unknown integration'
    if not ok:
        audit(actor, 'WRITE', vendor_id, fields, 'DENY', reason)
        return 403 if key else 401, {'error': 'ACCESS DENIED', 'reason': reason}
    # Prevent changing record IDs and enforce simple expected text formats.
    if any(not isinstance(value, str) or len(value)>150 for value in changes.values()):
        audit(actor, 'WRITE', vendor_id, fields, 'DENY', 'Invalid field value')
        return 400, {'error': 'Invalid field value'}
    sql = ', '.join(f'{f}=?' for f in fields)
    with connect() as db:
        cur = db.execute(f'UPDATE vendors SET {sql} WHERE vendor_id=?', [*changes.values(), vendor_id])
    if cur.rowcount == 0:
        audit(actor, 'WRITE', vendor_id, fields, 'DENY', 'Vendor does not exist')
        return 404, {'error': 'Not found'}
    audit(actor, 'WRITE', vendor_id, fields, 'ALLOW', reason)
    return 200, {'status': 'UPDATED', 'fields': fields}


def sync_task(record):
    """Controlled stand-in for the third-party's approved contact-sync function.

    Missing values are visible as None so the experimental comparison fails.
    This does not inspect or prove necessity for arbitrary third-party software.
    """
    return {'external_vendor_id': record.get('vendor_id'),
            'display_name': record.get('vendor_name'),
            'contact_phone': record.get('phone')}


def discover_minimum_fields():
    """Deletion testing against *all* seeded vendor fixture records."""
    with connect() as db:
        records = [dict(row) for row in db.execute('SELECT * FROM vendors ORDER BY vendor_id')]
    if not records:
        raise RuntimeError('No records seeded')
    expected = [sync_task(r) for r in records]
    allowed = list(FIELDS)
    trials = []
    # Iterative removal; every attempted removal is tested on all fixtures.
    for candidate in list(FIELDS):
        proposal = [f for f in allowed if f != candidate]
        observed = [sync_task({k: r[k] for k in proposal}) for r in records]
        intact = (observed == expected)
        trials.append({'removed_field': candidate, 'sync_still_passes': intact,
                       'result': 'UNNECESSARY FOR TESTED TASK' if intact else 'REQUIRED BY TESTED TASK'})
        if intact:
            allowed = proposal
    return {'task': 'vendor contact synchronization', 'fixtures_tested': len(records),
            'recommended_read_fields': allowed,
            'recommended_write_fields': [],
            'trials': trials,
            'limits': 'Only the supplied task and fixtures were tested. Administrator review is required.'}


def apply_discovered_contract(key_id, vendor_scope='*', hours=24):
    result = discover_minimum_fields()
    if vendor_scope != '*':
        allowed_ids = {r[0] for r in synthetic_vendors()}
        requested = [v.strip() for v in vendor_scope.split(',') if v.strip()]
        if not requested or not set(requested).issubset(allowed_ids):
            raise ValueError('Vendor scope must contain existing vendor IDs')
        vendor_scope = json.dumps(sorted(set(requested)))
    if not isinstance(hours, int) or not 1 <= hours <= 168:
        raise ValueError('Expiry must be between 1 and 168 hours')
    with connect() as db:
        cur = db.execute('''UPDATE api_keys SET read_fields=?,write_fields=?,vendor_scope=?,expires_at=? WHERE id=?''',
                         (json.dumps(result['recommended_read_fields']), json.dumps([]), vendor_scope,
                          int(time.time()) + 3600 * hours, key_id))
    if cur.rowcount != 1:
        raise ValueError('Integration key not found')
    audit('Administrator', 'APPLY CONTRACT', '-', result['recommended_read_fields'], 'ALLOW', 'Experimental contract approved')
    return result


def revoke_key(key_id):
    with connect() as db:
        cur = db.execute('UPDATE api_keys SET active=0 WHERE id=?', (key_id,))
    audit('Administrator', 'REVOKE', '-', [], 'ALLOW', f'Credential {key_id} revoked')
    return cur.rowcount



def _scope_and_expiry(vendor_scope, hours):
    """Validate manual or discovered contract input before touching credentials."""
    if not isinstance(hours, int) or not 1 <= hours <= 168:
        raise ValueError('Expiry must be between 1 and 168 hours')
    if not isinstance(vendor_scope, str) or len(vendor_scope) > 512:
        raise ValueError('Invalid vendor scope')
    if vendor_scope != '*':
        allowed_ids = {r['vendor_id'] for r in synthetic_vendors()}
        requested = [v.strip() for v in vendor_scope.split(',') if v.strip()]
        if not requested or not set(requested).issubset(allowed_ids):
            raise ValueError('Vendor scope must contain existing vendor IDs')
        vendor_scope = json.dumps(sorted(set(requested)))
    return vendor_scope, int(time.time()) + 3600 * hours


def update_manual_contract(key_id, read_fields, write_fields, vendor_scope='*', hours=24, acknowledge_sensitive=False):
    """Update field-level contract. Only admin-only, CSRF-protected HTTP route calls this."""
    if not isinstance(read_fields, list) or not isinstance(write_fields, list):
        raise ValueError('Read and Write permissions must be lists')
    for label, fields in (('Read', read_fields), ('Write', write_fields)):
        if len(fields) > len(FIELDS) or any(not isinstance(f, str) or f not in FIELDS for f in fields) or len(fields) != len(set(fields)):
            raise ValueError(label + ' permissions contain an unknown or repeated field')
    if 'vendor_id' in write_fields:
        raise ValueError('The primary vendor ID cannot be modified by third parties')
    if any(f in SENSITIVE_FIELDS for f in write_fields) and acknowledge_sensitive is not True:
        raise ValueError('Sensitive write access requires explicit high-risk confirmation')
    vendor_scope, expires_at = _scope_and_expiry(vendor_scope, hours)
    with connect() as db:
        row = db.execute('SELECT active FROM api_keys WHERE id=?', (key_id,)).fetchone()
        if row is None:
            raise ValueError('Integration key not found')
        if not row['active']:
            raise ValueError('Credential is revoked. Rotate it to issue a new token, then edit permissions.')
        db.execute("UPDATE api_keys SET read_fields=?,write_fields=?,vendor_scope=?,expires_at=? WHERE id=?",
                   (json.dumps(read_fields), json.dumps(write_fields), vendor_scope, expires_at, key_id))
    audit('Administrator', 'EDIT CONTRACT', '-', sorted(set(read_fields+write_fields)), 'ALLOW',
          f'Manual permissions set: {len(read_fields)} readable, {len(write_fields)} writable fields')
    return {'read_fields': read_fields, 'write_fields': write_fields, 'vendor_scope': vendor_scope, 'expires_at': expires_at}


def rotate_integration_token(key_id, hours=24):
    """Replace token hash, issue new token once; keep existing least-privilege policy."""
    if not isinstance(hours, int) or not 1 <= hours <= 168:
        raise ValueError('Expiry must be between 1 and 168 hours')
    new_token = 'tx_' + secrets.token_urlsafe(32)
    with connect() as db:
        row = db.execute('SELECT id FROM api_keys WHERE id=?', (key_id,)).fetchone()
        if row is None:
            raise ValueError('Integration not found')
        db.execute('UPDATE api_keys SET token_hash=?,active=1,expires_at=? WHERE id=?',
                   (token_hash(new_token), int(time.time()) + hours * 3600, key_id))
    audit('Administrator', 'ROTATE CREDENTIAL', '-', [], 'ALLOW',
          f'Old token invalidated; new credential issued for {hours} hours')
    return new_token


def synthetic_vendors():
    with connect() as db:
        return db.execute('SELECT * FROM vendors ORDER BY vendor_id').fetchall()


def recent_audit(limit=60):
    with connect() as db:
        return [dict(r) for r in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT ?', (limit,)).fetchall()]
