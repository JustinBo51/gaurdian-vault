"""Basic integration tests. Run after installing requirements.txt with: python -m unittest discover -s tests"""
import os, tempfile, unittest

_tmp = tempfile.TemporaryDirectory()
os.environ['GUARDIAN_VAULT_DATA'] = _tmp.name
os.environ['SECRET_KEY'] = 'test-only-secret-key-that-is-not-for-production'
from app import app, connect_db

class GuardianVaultTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        with connect_db() as db:
            db.execute('DELETE FROM attachments')
            db.execute('DELETE FROM records')
            db.execute('DELETE FROM children')
            db.execute('DELETE FROM cases')
            db.execute('DELETE FROM users')
            db.commit()
        self.client = app.test_client()

    def csrf(self):
        with self.client.session_transaction() as sess:
            return sess.get('csrf_token')

    def register(self, name, email):
        self.client.get('/register')
        token = self.csrf()
        return self.client.post('/register', data={'csrf_token': token, 'display_name': name, 'email': email, 'password': 'very-long-test-password-123'}, follow_redirects=True)

    def test_register_and_create_case(self):
        r = self.register('Test User', 'one@example.test')
        self.assertEqual(r.status_code, 200)
        r = self.client.post('/cases/new', data={'csrf_token': self.csrf(), 'title':'Test family case', 'jurisdiction':'Test County'}, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'Test family case', r.data)

    def test_case_isolation_between_users(self):
        self.register('User One', 'one@example.test')
        r = self.client.post('/cases/new', data={'csrf_token': self.csrf(), 'title':'Private case'}, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        with connect_db() as db:
            case_id = db.execute("SELECT id FROM cases WHERE title='Private case'").fetchone()[0]
        self.client.post('/logout', data={'csrf_token': self.csrf()}, follow_redirects=True)
        self.register('User Two', 'two@example.test')
        r = self.client.get(f'/cases/{case_id}')
        self.assertEqual(r.status_code, 404)

    def test_record_persists_and_searches(self):
        self.register('Test User', 'one@example.test')
        self.client.post('/cases/new', data={'csrf_token': self.csrf(), 'title':'Case A'}, follow_redirects=True)
        with connect_db() as db:
            case_id = db.execute("SELECT id FROM cases WHERE title='Case A'").fetchone()[0]
        r = self.client.post(f'/cases/{case_id}/records/new', data={'csrf_token': self.csrf(), 'title':'Phone call with caseworker', 'record_type':'Communication', 'event_date':'2026-10-26', 'details':'Discussed next appointment'}, follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        r = self.client.get('/search?q=caseworker')
        self.assertIn(b'Phone call with caseworker', r.data)

if __name__ == '__main__': unittest.main()
