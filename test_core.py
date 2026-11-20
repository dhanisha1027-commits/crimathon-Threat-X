import os
import atexit
import tempfile
import unittest
from pathlib import Path

# Set test DB *before* loading core.
TMP = tempfile.TemporaryDirectory(prefix='threatx-test-')
atexit.register(TMP.cleanup)
os.environ['THREATX_DB'] = str(Path(TMP.name) / 'test.sqlite')
import core


class ThreatXTests(unittest.TestCase):
    def setUp(self):
        if core.DB_PATH.exists():
            core.DB_PATH.unlink()
        core.seed(reset=False)
        self.token = core.issue_key(lifetime_hours=24)
        with core.connect() as db:
            self.key_id = db.execute('SELECT id FROM api_keys').fetchone()[0]

    def test_experiment_finds_minimum_for_tested_task(self):
        result = core.discover_minimum_fields()
        self.assertEqual(set(result['recommended_read_fields']), {'vendor_id', 'vendor_name', 'phone'})
        self.assertEqual(result['recommended_write_fields'], [])
        self.assertEqual(result['fixtures_tested'], 4)
        self.assertEqual(len(result['trials']), 6)

    def test_overprivileged_legacy_demonstration_then_restriction(self):
        status, body = core.read_vendor(self.token, 'V-0412', ['vendor_name', 'bank_account'])
        self.assertEqual(status, 200)
        self.assertEqual(body['record']['bank_account'], '****4417')
        status, _ = core.write_vendor(self.token, 'V-0412', {'bank_account': '****9083'})
        self.assertEqual(status, 200)
        core.apply_discovered_contract(self.key_id)
        status, body = core.read_vendor(self.token, 'V-0412', ['vendor_id', 'vendor_name', 'phone'])
        self.assertEqual(status, 200)
        self.assertNotIn('bank_account', body['record'])
        status, _ = core.read_vendor(self.token, 'V-0412', ['bank_account'])
        self.assertEqual(status, 403)
        status, _ = core.write_vendor(self.token, 'V-0412', {'bank_account': '****7777'})
        self.assertEqual(status, 403)
        with core.connect() as db:
            val = db.execute('SELECT bank_account FROM vendors WHERE vendor_id=?', ('V-0412',)).fetchone()[0]
        self.assertEqual(val, '****9083')

    def test_vendor_scope(self):
        core.apply_discovered_contract(self.key_id, vendor_scope='V-0412')
        self.assertEqual(core.read_vendor(self.token, 'V-0412', ['phone'])[0], 200)
        self.assertEqual(core.read_vendor(self.token, 'V-0208', ['phone'])[0], 403)

    def test_expired_token_denied(self):
        with core.connect() as db:
            db.execute('UPDATE api_keys SET expires_at=1 WHERE id=?', (self.key_id,))
        self.assertEqual(core.read_vendor(self.token, 'V-0412', ['phone'])[0], 403)

    def test_revoked_token_denied(self):
        core.revoke_key(self.key_id)
        self.assertEqual(core.read_vendor(self.token, 'V-0412', ['phone'])[0], 403)

    def test_unknown_token_denied(self):
        self.assertEqual(core.read_vendor('fake_token', 'V-0412', ['phone'])[0], 401)

    def test_sql_field_injection_rejected(self):
        self.assertEqual(core.read_vendor(self.token, 'V-0412', ['bank_account FROM vendors; DROP TABLE vendors'])[0], 403)
        with core.connect() as db:
            self.assertIsNotNone(db.execute('SELECT * FROM vendors LIMIT 1').fetchone())

    def test_audit_allow_and_deny(self):
        core.apply_discovered_contract(self.key_id)
        core.read_vendor(self.token, 'V-0412', ['phone'])
        core.read_vendor(self.token, 'V-0412', ['bank_account'])
        decisions = [a['decision'] for a in core.recent_audit()]
        self.assertIn('ALLOW', decisions)
        self.assertIn('DENY', decisions)

    def test_manual_read_permissions_enforced(self):
        core.update_manual_contract(self.key_id, ['vendor_id','vendor_name','phone'], [], hours=24)
        self.assertEqual(core.read_vendor(self.token, 'V-0412', ['phone'])[0], 200)
        self.assertEqual(core.read_vendor(self.token, 'V-0412', ['bank_account'])[0], 403)
        self.assertEqual(core.write_vendor(self.token, 'V-0412', {'bank_account':'****9999'})[0], 403)

    def test_manual_field_edit_persists(self):
        core.update_manual_contract(self.key_id, ['vendor_name','email'], ['email'], vendor_scope='V-0412')
        info = core.get_key_info()[0]
        self.assertEqual(info['read_fields'], ['vendor_name','email'])
        self.assertEqual(info['write_fields'], ['email'])
        self.assertEqual(core.read_vendor(self.token, 'V-0208', ['email'])[0], 403)
        self.assertEqual(core.write_vendor(self.token, 'V-0412', {'email':'new@example.test'})[0], 200)

    def test_reject_sensitive_write_without_confirm(self):
        with self.assertRaisesRegex(ValueError, 'high-risk'):
            core.update_manual_contract(self.key_id, ['vendor_id'], ['bank_account'])

    def test_reject_id_write(self):
        with self.assertRaises(ValueError):
            core.update_manual_contract(self.key_id, ['vendor_id'], ['vendor_id'])

    def test_reject_unknown_field(self):
        with self.assertRaises(ValueError):
            core.update_manual_contract(self.key_id, ['vendor_id','not_a_field'], [])

    def test_rotate_after_revocation_preserves_permissions(self):
        core.update_manual_contract(self.key_id, ['vendor_id','phone'], [])
        core.revoke_key(self.key_id)
        self.assertEqual(core.read_vendor(self.token, 'V-0412', ['phone'])[0], 403)
        new_token = core.rotate_integration_token(self.key_id)
        self.assertEqual(core.read_vendor(self.token, 'V-0412', ['phone'])[0], 401)
        self.assertEqual(core.read_vendor(new_token, 'V-0412', ['phone'])[0], 200)
        self.assertEqual(core.read_vendor(new_token, 'V-0412', ['bank_account'])[0], 403)

    def test_manual_update_cannot_unrevoke(self):
        core.revoke_key(self.key_id)
        with self.assertRaisesRegex(ValueError, 'revoked'):
            core.update_manual_contract(self.key_id, ['vendor_id'], [])

    def test_nonexistent_vendor_not_leaked(self):
        self.assertEqual(core.read_vendor(self.token, 'V-9999', ['phone'])[0], 404)


if __name__ == '__main__':
    unittest.main()
