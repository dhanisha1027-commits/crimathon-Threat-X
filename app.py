"""ThreatX NEEDZERO: local-only Python HTTP demo. No external dependencies.

Do not deploy Python's stdlib HTTPServer to the public internet.
"""
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import html
import json
import os
import secrets
import time

from core import (
    ROOT, apply_discovered_contract, connect, discover_minimum_fields, get_key_info,
    read_vendor, recent_audit, revoke_key, synthetic_vendors, verify_admin, write_vendor,
    update_manual_contract, rotate_integration_token
)

SESSIONS = {}
MAX_BYTES = 12_000
COOKIE_NAME = 'threatx_session'


def json_response(handler, status, payload):
    body = json.dumps(payload, ensure_ascii=False).encode('utf8')
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json; charset=utf-8')
    handler.send_header('Content-Length', str(len(body)))
    handler.send_header('Cache-Control', 'no-store')
    handler.send_header('X-Content-Type-Options', 'nosniff')
    handler.send_header('X-Frame-Options', 'DENY')
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    server_version = 'ThreatXLocalDemo/1.0'

    def log_message(self, fmt, *args):
        # Deliberately never log Authorization headers or request bodies.
        print('%s - %s' % (self.address_string(), fmt % args))

    def _get_session(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get('Cookie', ''))
        except Exception:
            return None
        val = cookie.get(COOKIE_NAME)
        if not val:
            return None
        session = SESSIONS.get(val.value)
        if not session or session['expires'] < time.time():
            SESSIONS.pop(val.value, None)
            return None
        return session

    def _read_json(self):
        try:
            size = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return None
        if not 0 < size <= MAX_BYTES:
            return None
        try:
            return json.loads(self.rfile.read(size))
        except (ValueError, UnicodeDecodeError):
            return None

    def _admin_check(self, write=False):
        session = self._get_session()
        if not session:
            json_response(self, 401, {'error': 'Admin login required'})
            return False
        if write and not secrets.compare_digest(self.headers.get('X-CSRF-Token', ''), session['csrf']):
            json_response(self, 403, {'error': 'Admin CSRF verification failed'})
            return False
        return True

    def _api_token(self):
        value = self.headers.get('Authorization', '')
        return value[7:] if value.startswith('Bearer ') else ''

    def _redirect(self, location, cookie=None):
        self.send_response(303)
        self.send_header('Location', location)
        self.send_header('Cache-Control', 'no-store')
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def _serve_file(self, name, ctype):
        # Name is chosen from a static allowlist, not from a user-provided file path.
        source = ROOT / 'static' / name
        body = source.read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlsplit(self.path)
        path = url.path
        if path == '/':
            self._redirect('/admin' if self._get_session() else '/login')
            return
        if path == '/login':
            self._serve_file('login.html', 'text/html; charset=utf-8')
            return
        if path == '/styles.css':
            self._serve_file('styles.css', 'text/css; charset=utf-8')
            return
        if path == '/main.js':
            self._serve_file('main.js', 'text/javascript; charset=utf-8')
            return
        if path == '/admin':
            session = self._get_session()
            if not session:
                self._redirect('/login')
                return
            source = (ROOT / 'static' / 'admin.html').read_text(encoding='utf8')
            body = source.replace('__CSRF_TOKEN__', html.escape(session['csrf'], quote=True)).encode('utf8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Frame-Options', 'DENY')
            self.end_headers()
            self.wfile.write(body)
            return
        if path == '/admin/api/state':
            if not self._admin_check():
                return
            keys = get_key_info()
            vendors = [dict(r) for r in synthetic_vendors()]
            json_response(self, 200, {'integrations': keys,
                                     'vendors': [{'vendor_id': v['vendor_id'], 'vendor_name': v['vendor_name'],
                                                  'bank_account': v['bank_account']} for v in vendors],
                                     'audit': recent_audit()})
            return
        if path == '/admin/api/discover':
            if not self._admin_check():
                return
            json_response(self, 200, discover_minimum_fields())
            return
        if path.startswith('/api/vendors/'):
            vendor_id = path.removeprefix('/api/vendors/')
            if '/' in vendor_id or not vendor_id:
                json_response(self, 404, {'error': 'Invalid vendor'})
                return
            request = parse_qs(url.query)
            fields = [f.strip() for f in request.get('fields', ['vendor_id,vendor_name,phone'])[0].split(',')]
            status, payload = read_vendor(self._api_token(), vendor_id, fields)
            json_response(self, status, payload)
            return
        json_response(self, 404, {'error': 'Unknown endpoint'})

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == '/login':
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 1024:
                    raise ValueError()
                params = parse_qs(self.rfile.read(size).decode('utf8'))
                username = params.get('username', [''])[0]
                password = params.get('password', [''])[0]
            except (ValueError, UnicodeDecodeError):
                json_response(self, 400, {'error': 'Invalid login form'})
                return
            if not verify_admin(username, password):
                # No account enumeration in error message.
                self._redirect('/login?error=1')
                return
            token = secrets.token_urlsafe(32)
            SESSIONS[token] = {'username': username, 'csrf': secrets.token_urlsafe(24), 'expires': time.time() + 4*3600}
            cookie = f'{COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=14400'
            # Secure cookie needs HTTPS; demo deliberately binds to localhost only.
            self._redirect('/admin', cookie=cookie)
            return
        if path == '/admin/api/logout':
            if not self._admin_check(write=True):
                return
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get('Cookie', ''))
                key = cookie.get(COOKIE_NAME)
                if key:
                    SESSIONS.pop(key.value, None)
            except Exception:
                pass
            self._redirect('/login', cookie=f'{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
            return
        if path == '/admin/api/apply':
            if not self._admin_check(write=True):
                return
            values = self._read_json()
            if not isinstance(values, dict):
                json_response(self, 400, {'error': 'Expected JSON object'})
                return
            try:
                result = apply_discovered_contract(int(values.get('key_id', 1)),
                                                   str(values.get('vendor_scope', '*')),
                                                   int(values.get('hours', 24)))
                json_response(self, 200, {'message': 'Verified minimum-access contract activated', 'result': result})
            except (ValueError, TypeError) as exc:
                json_response(self, 400, {'error': str(exc)})
            return
        if path == '/admin/api/manual':
            if not self._admin_check(write=True):
                return
            values = self._read_json()
            if not isinstance(values, dict):
                json_response(self, 400, {'error': 'Expected JSON object'})
                return
            try:
                result = update_manual_contract(
                    int(values.get('key_id', 1)), values.get('read_fields'), values.get('write_fields'),
                    str(values.get('vendor_scope', '*')), int(values.get('hours', 24)),
                    values.get('acknowledge_sensitive') is True)
                json_response(self, 200, {'message': 'Manual field permissions saved and enforced on the server', 'result': result})
            except (ValueError, TypeError, AttributeError) as exc:
                json_response(self, 400, {'error': str(exc)})
            return
        if path == '/admin/api/rotate':
            if not self._admin_check(write=True):
                return
            values = self._read_json()
            if not isinstance(values, dict):
                json_response(self, 400, {'error': 'Expected JSON object'})
                return
            try:
                token = rotate_integration_token(int(values.get('key_id', 1)), int(values.get('hours', 24)))
                json_response(self, 200, {'token': token, 'message': 'New token issued. Copy it now; the server stores only a hash.'})
            except (ValueError, TypeError, AttributeError) as exc:
                json_response(self, 400, {'error': str(exc)})
            return
        if path == '/admin/api/revoke':
            if not self._admin_check(write=True):
                return
            values = self._read_json()
            try:
                key_id = int(values.get('key_id', 1))
                changed = revoke_key(key_id)
                json_response(self, 200 if changed else 404, {'revoked': bool(changed)})
            except (ValueError, TypeError, AttributeError):
                json_response(self, 400, {'error': 'Invalid key ID'})
            return
        json_response(self, 404, {'error': 'Unknown endpoint'})

    def do_PATCH(self):
        path = urlsplit(self.path).path
        if path.startswith('/api/vendors/'):
            vendor_id = path.removeprefix('/api/vendors/')
            if not vendor_id or '/' in vendor_id:
                json_response(self, 404, {'error': 'Invalid vendor'})
                return
            changes = self._read_json()
            if not isinstance(changes, dict):
                json_response(self, 400, {'error': 'Expected JSON object'})
                return
            status, payload = write_vendor(self._api_token(), vendor_id, changes)
            json_response(self, status, payload)
            return
        json_response(self, 404, {'error': 'Unknown endpoint'})


def main():
    from core import init_db
    init_db()
    with connect() as db:
        if not db.execute('SELECT COUNT(*) FROM admins').fetchone()[0]:
            raise SystemExit('Run python seed_demo.py before starting the website.')
    host, port = '127.0.0.1', int(os.environ.get('THREATX_PORT', '8765'))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f'ThreatX NEEDZERO running at http://{host}:{port}')
    print('LOCAL SYNTHETIC DEMO ONLY — not for production or public hosting.')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nServer stopped')
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
