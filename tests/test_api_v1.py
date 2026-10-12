"""Focused contract and lifecycle tests for the account-scoped API."""
import hashlib
import json
import os
import re
import time
import unittest
from contextlib import closing
from unittest.mock import MagicMock, patch

import test_keep
import api_v1

keep = test_keep.keep
api = keep.app.extensions['keep_api']


class ApiV1Tests(unittest.TestCase):
    def setUp(self):
        keep.app.config.update(TESTING=True)
        self.client = keep.app.test_client()
        self.cid = 1
        with closing(keep.attribution_db()) as db, db:
            saved_connections = [tuple(row) for row in db.execute('SELECT name,value FROM connection_settings')]
            for table in ('api_idempotency', 'api_rate_limits', 'api_keys', 'keep_attribution',
                          'keep_schedules', 'activity_log', 'user_profiles', 'auth_rate_limits'):
                db.execute(f'DELETE FROM {table}')
            db.execute("""INSERT INTO user_profiles
                (plex_id, plex_username, display_name, email, auth_type, status, plex_access,
                 session_version, can_remove_any, can_keep_indefinitely)
                VALUES ('7', 'owner', 'Owner', 'owner@example.com', 'plex', 'active', 'active', 0, 0, 1)""")
            db.execute("""INSERT INTO user_profiles
                (plex_id, plex_username, display_name, email, auth_type, status, plex_access,
                 session_version, can_remove_any, can_keep_indefinitely, plex_checked_at)
                VALUES ('8', 'member', 'Member', 'member@example.com', 'plex', 'active', 'active', 0, 0, 0, CURRENT_TIMESTAMP)""")
        def restore_connections():
            with closing(keep.attribution_db()) as db, db:
                db.execute('DELETE FROM connection_settings')
                db.executemany('INSERT INTO connection_settings(name,value) VALUES (?,?)', saved_connections)
        self.addCleanup(restore_connections)
        self.login(self.client, '7', 'owner')

    def login(self, client, user_id, username=None):
        with client.session_transaction() as session:
            session.clear()
            session['plex_user'] = {'id': user_id, 'username': username or user_id,
                                    'thumb': '', 'session_version': 0}
            session['csrf_token'] = 'test-csrf'

    def make_key(self, user_id='7', scopes=('collections:read', 'media:read', 'keeps:read', 'keeps:write'),
                 name='test integration', client=None, expiry_days='90'):
        client = client or self.client
        self.login(client, user_id, 'owner' if user_id == '7' else 'member')
        if user_id != '7':
            # Preserve coverage for credentials issued before settings became
            # owner-only. New member credentials cannot be created via the UI.
            with closing(keep.attribution_db()) as db, db:
                profile = db.execute('SELECT * FROM user_profiles WHERE plex_id=?', (user_id,)).fetchone()
                expires_at = 0 if expiry_days == 'never' else time.time() + int(expiry_days) * 86400
                token, _ = api.create_key(db, profile, name, scopes, expires_at)
            return token
        response = client.post('/settings/api-keys', data={
            'csrf_token': 'test-csrf', 'action': 'create', 'name': name,
            'expiry_days': expiry_days, 'scope': list(scopes),
        })
        self.assertEqual(response.status_code, 200)
        match = re.search(r'<input id="new-api-key" value="([^"]+)"', response.get_data(as_text=True))
        self.assertIsNotNone(match, response.get_data(as_text=True)[:500])
        return match.group(1)

    def bearer_client(self, token):
        client = keep.app.test_client()
        return client, {'Authorization': 'Bearer ' + token}

    def auth(self, token, method='GET', path='/api/v1/collections', **kwargs):
        client, headers = self.bearer_client(token)
        headers.update(kwargs.pop('headers', {}))
        return getattr(client, method.lower())(path, headers=headers, **kwargs)

    def seed_keep(self, user_id='7', media_id='42', collection_id=1, expires_at='2026-11-01 00:00:00',
                  extension_available_at=None):
        with closing(keep.attribution_db()) as db, db:
            db.execute('''INSERT INTO keep_attribution(collection_id,media_id,user_id,username)
                VALUES (?,?,?,?)''', (str(collection_id), media_id, user_id, user_id))
            db.execute('''INSERT INTO keep_schedules(collection_id,media_id,expires_at,extension_available_at)
                VALUES (?,?,?,?)''', (str(collection_id), media_id, expires_at, extension_available_at))

    def test_key_creation_is_hash_only_one_time_and_account_bound(self):
        token = self.make_key()
        self.assertRegex(token, r'^keep_[A-Za-z0-9_-]{43}$')
        with closing(keep.attribution_db()) as db:
            owner_key = db.execute('SELECT * FROM api_keys WHERE user_id=?', ('7',)).fetchone()
            self.assertEqual(owner_key['secret_hash'], hashlib.sha256(token.encode()).hexdigest())
            self.assertNotIn(token, tuple(owner_key))
            self.assertEqual(owner_key['account_version'], 0)
        later = self.client.get('/settings/api-keys').get_data(as_text=True)
        self.assertNotIn(token, later)

        bob_client = keep.app.test_client()
        self.login(bob_client, '8', 'member')
        bob_response = bob_client.get('/settings/api-keys')
        self.assertEqual(bob_response.status_code, 403)
        bob_page = bob_response.get_data(as_text=True)
        self.assertNotIn(owner_key['prefix'], bob_page)
        with closing(keep.attribution_db()) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM api_keys WHERE user_id=?', ('8',)).fetchone()[0], 0)

    def test_never_expiring_key_authenticates_and_expiry_input_is_explicit(self):
        token = self.make_key(name='never integration', expiry_days='never')
        self.assertEqual(self.auth(token).status_code, 200)
        with closing(keep.attribution_db()) as db:
            row = db.execute('SELECT expires_at FROM api_keys WHERE secret_hash=?',
                             (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
            self.assertEqual(row['expires_at'], 0)

        finite = self.make_key(name='default finite')
        with closing(keep.attribution_db()) as db:
            finite_expiry = db.execute('SELECT expires_at FROM api_keys WHERE secret_hash=?',
                                       (hashlib.sha256(finite.encode()).hexdigest(),)).fetchone()[0]
        self.assertGreater(finite_expiry, time.time())
        self.assertLessEqual(finite_expiry, time.time() + 90 * 86400 + 5)

        negative = self.make_key(name='negative expiry')
        with closing(keep.attribution_db()) as db, db:
            db.execute('UPDATE api_keys SET expires_at=-1 WHERE secret_hash=?',
                       (hashlib.sha256(negative.encode()).hexdigest(),))
        self.assertEqual(self.auth(negative).status_code, 401)

        for invalid in ('0', '-1', '1', '31', '364', '366', '030', '90.0', 'Never', ''):
            response = self.client.post('/settings/api-keys', data={
                'csrf_token': 'test-csrf', 'action': 'create', 'name': 'invalid expiry',
                'expiry_days': invalid, 'scope': ['collections:read']})
            self.assertIn('Choose an expiry', response.get_data(as_text=True))
        with closing(keep.attribution_db()) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM api_keys WHERE name='invalid expiry'").fetchone()[0], 0)

    def test_expiry_presets_and_historical_rotation_keep_original_expiry(self):
        for days in ('30', '90', '365'):
            with self.subTest(days=days):
                before = time.time()
                token = self.make_key(name='preset ' + days, expiry_days=days)
                with closing(keep.attribution_db()) as db:
                    expires_at = db.execute('SELECT expires_at FROM api_keys WHERE secret_hash=?',
                                            (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()[0]
                self.assertGreaterEqual(expires_at, before + int(days) * 86400)
                self.assertLessEqual(expires_at, time.time() + int(days) * 86400)

        token = self.make_key(name='historical custom expiry')
        original_expiry = time.time() + 12 * 86400
        with closing(keep.attribution_db()) as db, db:
            row = db.execute('SELECT id FROM api_keys WHERE secret_hash=?',
                             (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
            db.execute('UPDATE api_keys SET expires_at=? WHERE id=?', (original_expiry, row['id']))
        rotated = self.client.post('/settings/api-keys', data={
            'csrf_token': 'test-csrf', 'action': 'rotate', 'key_id': row['id']})
        self.assertEqual(rotated.status_code, 200)
        with closing(keep.attribution_db()) as db:
            replacement = db.execute("SELECT expires_at FROM api_keys WHERE name='historical custom expiry' AND revoked_at IS NULL").fetchone()
        self.assertEqual(replacement['expires_at'], original_expiry)

    def test_never_expiry_counts_toward_limit_and_rotation_preserves_never(self):
        token = self.make_key(name='never rotates', scopes=('collections:read',), expiry_days='never')
        with closing(keep.attribution_db()) as db, db:
            first = dict(db.execute('SELECT * FROM api_keys WHERE secret_hash=?',
                                    (hashlib.sha256(token.encode()).hexdigest(),)).fetchone())
            for index in range(19):
                db.execute('INSERT INTO api_keys VALUES (?,?,?,?,?,?,?,?,?,NULL,NULL)',
                           (f'limit-{index}', '7', f'limit {index}', f'prefix-{index}',
                            hashlib.sha256(f'limit-key-{index}'.encode()).hexdigest(),
                            '["collections:read"]', 0, time.time(), 0 if index == 0 else time.time() + 86400))
        too_many = self.client.post('/settings/api-keys', data={
            'csrf_token': 'test-csrf', 'action': 'create', 'name': 'twenty first',
            'expiry_days': '90', 'scope': ['collections:read']})
        self.assertIn('more than 20 active keys', too_many.get_data(as_text=True))
        with closing(keep.attribution_db()) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM api_keys WHERE user_id=?', ('7',)).fetchone()[0], 20)

        # Rotation reuses the existing record's expiry and scopes while minting a new secret.
        with closing(keep.attribution_db()) as db, db:
            db.execute("DELETE FROM api_keys WHERE id != ?", (first['id'],))
        rotated = self.client.post('/settings/api-keys', data={
            'csrf_token': 'test-csrf', 'action': 'rotate', 'key_id': first['id']})
        self.assertEqual(rotated.status_code, 200)
        match = re.search(r'<input id="new-api-key" value="([^"]+)"', rotated.get_data(as_text=True))
        self.assertIsNotNone(match)
        new_token = match.group(1)
        self.assertNotEqual(token, new_token)
        self.assertEqual(self.auth(token).status_code, 401)
        self.assertEqual(self.auth(new_token).status_code, 200)
        with closing(keep.attribution_db()) as db:
            new_row = db.execute('SELECT * FROM api_keys WHERE secret_hash=?',
                                 (hashlib.sha256(new_token.encode()).hexdigest(),)).fetchone()
            self.assertEqual(new_row['expires_at'], 0)
            self.assertEqual(json.loads(new_row['scopes']), ['collections:read'])
            rotation = db.execute("SELECT description FROM activity_log WHERE action='api-key-rotate' ORDER BY id DESC LIMIT 1").fetchone()[0]
            self.assertIn('never rotates', rotation)
            self.assertIn('collections:read', rotation)
            self.assertIn('never expires', rotation)
            self.assertNotIn(new_token, rotation)

    def test_never_expiring_key_still_rechecks_account_and_plex_lease(self):
        for description, mutation in (
                ('disabled', "UPDATE user_profiles SET status='disabled' WHERE plex_id='7'"),
                ('session changed', "UPDATE user_profiles SET session_version=session_version+1 WHERE plex_id='7'"),
                ('Plex revoked', "UPDATE user_profiles SET plex_access='revoked' WHERE plex_id='7'")):
            with self.subTest(description=description):
                token = self.make_key(name='never ' + description, expiry_days='never')
                with closing(keep.attribution_db()) as db, db:
                    db.execute(mutation)
                response = self.auth(token)
                self.assertEqual((response.status_code, response.json['error']['code']), (401, 'invalid_token'))
                with closing(keep.attribution_db()) as db, db:
                    db.execute("UPDATE user_profiles SET status='active',plex_access='active',session_version=0 WHERE plex_id='7'")

    def test_never_expiring_member_key_rejects_expired_plex_lease(self):
        member = keep.app.test_client()
        token = self.make_key(user_id='8', name='member never', expiry_days='never', client=member)
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET plex_checked_at='2000-01-01 00:00:00' WHERE plex_id='8'")
        response = self.auth(token)
        self.assertEqual((response.status_code, response.json['error']['code']), (401, 'invalid_token'))
        key_id = hashlib.sha256(token.encode()).hexdigest()
        with closing(keep.attribution_db()) as db:
            key_id = db.execute('SELECT id FROM api_keys WHERE secret_hash=?', (key_id,)).fetchone()[0]
        rotate = member.post('/settings/api-keys', data={
            'csrf_token': 'test-csrf', 'action': 'rotate', 'key_id': key_id})
        self.assertEqual(rotate.status_code, 302)
        with closing(keep.attribution_db()) as db:
            self.assertIsNone(db.execute('SELECT revoked_at FROM api_keys WHERE id=?', (key_id,)).fetchone()[0])

    def test_rotation_rechecks_current_account_version(self):
        token = self.make_key(name='session rotation', expiry_days='never')
        with closing(keep.attribution_db()) as db:
            key_id = db.execute('SELECT id FROM api_keys WHERE secret_hash=?',
                                 (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()[0]
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET session_version=1 WHERE plex_id='7'")
        response = self.client.post('/settings/api-keys', data={
            'csrf_token': 'test-csrf', 'action': 'rotate', 'key_id': key_id})
        self.assertEqual(response.status_code, 302)
        with closing(keep.attribution_db()) as db:
            self.assertIsNone(db.execute('SELECT revoked_at FROM api_keys WHERE id=?', (key_id,)).fetchone()[0])

    def test_canonical_routes_legacy_redirects_and_account_navigation(self):
        old_keys = self.client.get('/account/api-keys')
        self.assertEqual(old_keys.status_code, 302)
        self.assertEqual(old_keys.headers['Location'], '/settings/api-keys')
        old_reference = self.client.get('/api-reference')
        self.assertEqual(old_reference.status_code, 302)
        self.assertEqual(old_reference.headers['Location'], '/settings/api-reference')
        self.assertEqual(self.client.get('/settings/api-reference').status_code, 200)

        for path in ('/settings/api-keys', '/settings/api-reference'):
            owner_page = self.client.get(path).get_data(as_text=True)
            owner_nav = re.search(r'<nav class="admin-nav".*?</nav>', owner_page, re.S).group(0)
            self.assertEqual(len(re.findall(r'<a\s', owner_nav)), 7)
            self.assertIn('href="/settings/jobs"', owner_nav)
            owner_menu = re.search(r'<div class="user-links".*?</div>', owner_page, re.S).group(0)
            self.assertNotIn('/settings/api-keys', owner_menu)

        member = keep.app.test_client()
        self.login(member, '8', 'member')
        for path in ('/settings/api-keys', '/settings/api-reference', '/account/api-keys', '/api-reference'):
            with self.subTest(path=path):
                response = member.get(path)
                self.assertEqual(response.status_code, 403)
                self.assertIn('Owner access only', response.get_data(as_text=True))

        member_page = member.get('/help').get_data(as_text=True)
        member_menu = re.search(r'<div class="user-links".*?</div>', member_page, re.S).group(0)
        self.assertNotIn('/settings/api-keys', member_menu)
        self.assertNotIn('/settings/api-reference', member_menu)
        self.assertNotIn('/settings/users', member_menu)

        # Owners retain the old POST route while its GET canonicalizes.
        legacy_post = self.client.post('/account/api-keys', data={
            'csrf_token': 'test-csrf', 'action': 'create', 'name': 'legacy client',
            'expiry_days': '90', 'scope': ['collections:read']})
        self.assertEqual(legacy_post.status_code, 200)
        self.assertIn('new-api-key', legacy_post.get_data(as_text=True))

    def test_nonowners_cannot_perform_any_key_lifecycle_action(self):
        token = self.make_key()
        with closing(keep.attribution_db()) as db:
            original = dict(db.execute('SELECT * FROM api_keys').fetchone())
        member = keep.app.test_client()
        self.login(member, '8', 'member')
        for path in ('/settings/api-keys', '/account/api-keys'):
            for action in ('create', 'rotate', 'revoke', 'remove'):
                with self.subTest(path=path, action=action):
                    response = member.post(path, data={
                        'csrf_token': 'test-csrf', 'action': action, 'key_id': original['id'],
                        'name': 'forbidden creation', 'expiry_days': '90', 'scope': ['collections:read']})
                    self.assertEqual(response.status_code, 403)
                    self.assertNotIn('new-api-key', response.get_data(as_text=True))
        with closing(keep.attribution_db()) as db:
            self.assertEqual([dict(row) for row in db.execute('SELECT * FROM api_keys')], [original])
            self.assertEqual(db.execute("SELECT count(*) FROM activity_log WHERE description LIKE '%forbidden creation%'").fetchone()[0], 0)
        self.assertEqual(self.auth(token).status_code, 200)

    def test_local_accounts_and_managers_do_not_gain_api_settings_access(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute("""UPDATE user_profiles SET auth_type='local', can_remove_any=1,
                          can_keep_indefinitely=1, can_delete_media=1, can_delete_any=1
                          WHERE plex_id='8'""")
        member = keep.app.test_client()
        self.login(member, '8', 'local manager')
        with member.session_transaction() as browser_session:
            browser_session['plex_user']['auth_type'] = 'local'
        for path in ('/settings/api-keys', '/settings/api-reference', '/account/api-keys', '/api-reference'):
            with self.subTest(path=path):
                self.assertEqual(member.get(path).status_code, 403)
                self.assertEqual(member.head(path).status_code, 403)
        response = member.post('/settings/api-keys', data={
            'csrf_token': 'test-csrf', 'action': 'create', 'name': 'local manager creation',
            'expiry_days': 'never', 'scope': ['keeps:write']})
        self.assertEqual(response.status_code, 403)
        html = member.get('/help').get_data(as_text=True)
        self.assertNotIn('href="/settings/api-keys"', html)
        self.assertNotIn('href="/settings/api-reference"', html)

    def test_anonymous_api_settings_and_legacy_routes_require_sign_in(self):
        anonymous = keep.app.test_client()
        for path in ('/settings/api-keys', '/settings/api-reference', '/account/api-keys', '/api-reference'):
            with self.subTest(path=path):
                response = anonymous.get(path)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.headers['Location'], '/login')
        for path in ('/settings/api-keys', '/account/api-keys'):
            response = anonymous.post(path, data={'action': 'create'})
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.headers['Location'], '/login')

    def test_revoked_owned_key_removal_cleans_only_its_runtime_records_and_keeps_audit(self):
        token = self.make_key(name='cleanup integration', scopes=('collections:read',))
        other = self.make_key(name='other integration', scopes=('media:read',))
        with closing(keep.attribution_db()) as db, db:
            rows = {row['name']: dict(row) for row in db.execute('SELECT * FROM api_keys')}
            target_id, other_id = rows['cleanup integration']['id'], rows['other integration']['id']
            db.execute('INSERT INTO api_idempotency VALUES (?,?,?,?,?,?,?)',
                       (target_id, 'target-key-hash', 'request-hash', 'succeeded', 200, '{}', time.time()))
            db.execute('INSERT INTO api_idempotency VALUES (?,?,?,?,?,?,?)',
                       (other_id, 'other-key-hash', 'request-hash', 'succeeded', 200, '{}', time.time()))
            window = int(time.time()) // 60 * 60
            for suffix in ('read', 'write'):
                db.execute('INSERT INTO api_rate_limits VALUES (?,?,?)',
                           ('key:' + target_id + ':' + suffix, window, 1))
                db.execute('INSERT INTO api_rate_limits VALUES (?,?,?)',
                           ('key:' + other_id + ':' + suffix, window, 1))
        revoke = self.client.post('/settings/api-keys', data={
            'csrf_token': 'test-csrf', 'action': 'revoke', 'key_id': target_id})
        self.assertIn('API key revoked', revoke.get_data(as_text=True))
        remove = self.client.post('/settings/api-keys', data={
            'csrf_token': 'test-csrf', 'action': 'remove', 'key_id': target_id})
        self.assertIn('API key removed', remove.get_data(as_text=True))
        with closing(keep.attribution_db()) as db:
            self.assertIsNone(db.execute('SELECT 1 FROM api_keys WHERE id=?', (target_id,)).fetchone())
            self.assertIsNotNone(db.execute('SELECT 1 FROM api_keys WHERE id=?', (other_id,)).fetchone())
            self.assertIsNone(db.execute('SELECT 1 FROM api_idempotency WHERE key_id=?', (target_id,)).fetchone())
            self.assertIsNotNone(db.execute('SELECT 1 FROM api_idempotency WHERE key_id=?', (other_id,)).fetchone())
            target_limits = db.execute('SELECT count(*) FROM api_rate_limits WHERE subject LIKE ?',
                                       ('key:' + target_id + ':%',)).fetchone()[0]
            other_limits = db.execute('SELECT count(*) FROM api_rate_limits WHERE subject LIKE ?',
                                      ('key:' + other_id + ':%',)).fetchone()[0]
            self.assertEqual(target_limits, 0)
            self.assertEqual(other_limits, 2)
            events = [tuple(row) for row in db.execute(
                "SELECT action,description FROM activity_log WHERE action LIKE 'api-key-%'")]
        actions = [event[0] for event in events]
        self.assertIn('api-key-create', actions)
        self.assertIn('api-key-revoke', actions)
        self.assertIn('api-key-remove', actions)
        descriptions = '\n'.join(event[1] for event in events)
        self.assertIn('cleanup integration', descriptions)
        self.assertIn('collections:read', descriptions)
        self.assertIn('expires', descriptions)
        self.assertNotIn(token, descriptions)
        self.assertNotIn(hashlib.sha256(token.encode()).hexdigest(), descriptions)
        self.assertNotIn(other, descriptions)

    def test_active_and_foreign_keys_cannot_be_removed_and_remove_requires_csrf(self):
        active = self.make_key(name='active removal')
        with closing(keep.attribution_db()) as db:
            active_id = db.execute('SELECT id FROM api_keys WHERE secret_hash=?',
                                   (hashlib.sha256(active.encode()).hexdigest(),)).fetchone()[0]
        no_csrf = self.client.post('/settings/api-keys', data={
            'action': 'remove', 'key_id': active_id})
        self.assertEqual(no_csrf.status_code, 403)
        active_remove = self.client.post('/settings/api-keys', data={
            'csrf_token': 'test-csrf', 'action': 'remove', 'key_id': active_id})
        self.assertIn('Revoke this key before removing it', active_remove.get_data(as_text=True))
        with closing(keep.attribution_db()) as db:
            self.assertIsNotNone(db.execute('SELECT 1 FROM api_keys WHERE id=?', (active_id,)).fetchone())

        owner_token = self.make_key(name='foreign removal')
        with closing(keep.attribution_db()) as db:
            owner_id = db.execute('SELECT id FROM api_keys WHERE secret_hash=?',
                                   (hashlib.sha256(owner_token.encode()).hexdigest(),)).fetchone()[0]
        bob = keep.app.test_client()
        self.login(bob, '8', 'member')
        foreign = bob.post('/settings/api-keys', data={
            'csrf_token': 'test-csrf', 'action': 'remove', 'key_id': owner_id})
        self.assertEqual(foreign.status_code, 403)
        self.assertIn('Owner access only', foreign.get_data(as_text=True))
        with closing(keep.attribution_db()) as db:
            self.assertIsNotNone(db.execute('SELECT 1 FROM api_keys WHERE id=?', (owner_id,)).fetchone())
        self.assertEqual(self.auth(owner_token).status_code, 200)

    def test_key_audit_uses_browser_alias_and_historical_uuid_events_render_with_name(self):
        with self.client.session_transaction() as session:
            session['plex_user'] = {'id': '7', 'username': 'Browser Alias',
                                    'thumb': '', 'session_version': 0}
        created = self.client.post('/settings/api-keys', data={
            'csrf_token': 'test-csrf', 'action': 'create', 'name': 'audit integration',
            'expiry_days': 'never', 'scope': ['collections:read']})
        token = re.search(r'<input id="new-api-key" value="([^"]+)"',
                          created.get_data(as_text=True)).group(1)
        with closing(keep.attribution_db()) as db, db:
            row = dict(db.execute('SELECT * FROM api_keys WHERE secret_hash=?',
                                  (hashlib.sha256(token.encode()).hexdigest(),)).fetchone())
            current = db.execute("SELECT actor_id,actor_name,action,description FROM activity_log WHERE action='api-key-create' ORDER BY id DESC LIMIT 1").fetchone()
            self.assertEqual((current['actor_id'], current['actor_name']), ('7', 'Browser Alias'))
            self.assertIn('audit integration', current['description'])
            self.assertIn('collections:read', current['description'])
            self.assertIn('never expires', current['description'])
            self.assertNotIn(token, current['description'])
            self.assertNotIn(row['secret_hash'], current['description'])
            db.execute('''INSERT INTO activity_log(actor_id,actor_name,action,description)
                VALUES (?,?,?,?)''', ('7', 'Old Profile Alias', 'api-key-create', 'API key ' + row['id']))
        history = self.client.get('/settings/activity?filter=api').get_data(as_text=True)
        self.assertIn('Created API key “audit integration”', history)
        self.assertIn('Browser Alias', history)
        self.assertNotIn(row['id'], history)

    def test_key_revoke_and_atomic_rotation_invalidate_old_secret(self):
        old = self.make_key()
        with closing(keep.attribution_db()) as db:
            row = dict(db.execute('SELECT * FROM api_keys WHERE user_id=?', ('7',)).fetchone())
        rotated = self.client.post('/settings/api-keys', data={
            'csrf_token': 'test-csrf', 'action': 'rotate', 'key_id': row['id']})
        self.assertEqual(rotated.status_code, 200)
        html = rotated.get_data(as_text=True)
        match = re.search(r'<input id="new-api-key" value="([^"]+)"', html)
        self.assertIsNotNone(match)
        new = match.group(1)
        self.assertNotEqual(old, new)
        self.assertEqual(self.auth(old).status_code, 401)
        self.assertEqual(self.auth(new).status_code, 200)
        with closing(keep.attribution_db()) as db:
            rows = db.execute('SELECT revoked_at FROM api_keys WHERE user_id=? ORDER BY created_at', ('7',)).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertIsNotNone(rows[0]['revoked_at'])
        self.assertIsNone(rows[1]['revoked_at'])

        with closing(keep.attribution_db()) as db:
            current_id = db.execute('SELECT id FROM api_keys WHERE revoked_at IS NULL AND user_id=?', ('7',)).fetchone()[0]
        revoked = self.client.post('/settings/api-keys', data={
            'csrf_token': 'test-csrf', 'action': 'revoke', 'key_id': current_id})
        self.assertEqual(revoked.status_code, 200)
        self.assertEqual(self.auth(new).status_code, 401)

    def test_bearer_auth_isolated_from_browser_session_webhook_and_legacy_api(self):
        token = self.make_key(scopes=('collections:read',))
        anonymous = keep.app.test_client()
        no_bearer = anonymous.get('/api/v1/collections')
        self.assertEqual(no_bearer.status_code, 401)
        self.assertEqual(no_bearer.json['error']['code'], 'invalid_token')
        self.assertIn('Bearer', no_bearer.headers['WWW-Authenticate'])
        self.assertEqual(self.auth(token).status_code, 200)

        with anonymous.session_transaction() as session:
            session['plex_user'] = {'id': '7', 'username': 'owner'}
        self.assertEqual(anonymous.get('/api/v1/collections').status_code, 401)
        legacy_client = keep.app.test_client()
        self.assertEqual(legacy_client.get('/api/counts', headers={'Authorization': 'Bearer ' + token}).status_code, 302)
        webhook = anonymous.post('/api/webhooks/maintainerr', headers={'Authorization': 'Bearer ' + token}, json={})
        self.assertEqual(webhook.status_code, 401)

    def test_expired_revoked_disabled_deleted_and_changed_account_keys_are_rejected(self):
        token = self.make_key()
        with closing(keep.attribution_db()) as db, db:
            db.execute('UPDATE api_keys SET expires_at=?', (time.time() - 1,))
        self.assertEqual(self.auth(token).json['error']['code'], 'invalid_token')

        token = self.make_key(name='second')
        with closing(keep.attribution_db()) as db, db:
            db.execute('UPDATE api_keys SET revoked_at=? WHERE secret_hash=?', (time.time(), hashlib.sha256(token.encode()).hexdigest()))
        self.assertEqual(self.auth(token).status_code, 401)

        for mutation in (
            "UPDATE user_profiles SET status='disabled' WHERE plex_id='7'",
            "UPDATE user_profiles SET plex_access='revoked' WHERE plex_id='7'",
            "UPDATE user_profiles SET session_version=session_version+1 WHERE plex_id='7'",
            "DELETE FROM user_profiles WHERE plex_id='7'",
        ):
            token = self.make_key(name='lifecycle')
            with closing(keep.attribution_db()) as db, db:
                db.execute(mutation)
            response = self.auth(token)
            self.assertEqual(response.status_code, 401, mutation)
            self.assertEqual(response.json['error']['code'], 'invalid_token', mutation)
            with closing(keep.attribution_db()) as db, db:
                db.execute('''INSERT OR IGNORE INTO user_profiles
                    (plex_id, plex_username, auth_type, status, plex_access, session_version)
                    VALUES ('7','owner','plex','active','active',0)''')
                db.execute("UPDATE user_profiles SET status='active',plex_access='active',session_version=0 WHERE plex_id='7'")

    def test_scopes_are_required_for_each_resource(self):
        collection_only = self.make_key(scopes=('collections:read',))
        self.assertEqual(self.auth(collection_only, path='/api/v1/media').json['error']['code'], 'insufficient_scope')
        self.assertEqual(self.auth(collection_only, path='/api/v1/keeps').status_code, 403)
        media_only = self.make_key(name='media only', scopes=('media:read',))
        with patch.object(api, 'feed', return_value=[]):
            self.assertEqual(self.auth(media_only, path='/api/v1/media?collection_id=1').status_code, 200)
        self.assertEqual(self.auth(media_only).status_code, 403)

    def test_unknown_method_and_oversized_requests_use_json_errors(self):
        token = self.make_key()
        unknown = self.auth(token, path='/api/v1/unknown')
        self.assertEqual((unknown.status_code, unknown.json['error']['code']), (404, 'not_found'))
        wrong_method = self.auth(token, method='POST', path='/api/v1/collections')
        self.assertEqual((wrong_method.status_code, wrong_method.json['error']['code']), (405, 'method_not_allowed'))
        self.assertIn('GET', wrong_method.headers['Allow'])
        large = self.auth(token, method='POST', path='/api/v1/keeps', data='x' * 9000,
                          content_type='application/json', headers={'Idempotency-Key': 'large-body-key-0001'})
        self.assertEqual((large.status_code, large.json['error']['code']), (413, 'payload_too_large'))
        bad_type = self.auth(token, method='POST', path='/api/v1/keeps', data='{}',
                             content_type='text/plain', headers={'Idempotency-Key': 'bad-content-type-001'})
        self.assertEqual((bad_type.status_code, bad_type.json['error']['code']), (415, 'unsupported_media_type'))

    def test_hidden_collections_invalid_fields_and_media_allowlist(self):
        token = self.make_key(scopes=('media:read', 'keeps:read'))
        hidden = self.auth(token, path='/api/v1/media?collection_id=2')
        self.assertEqual((hidden.status_code, hidden.json['error']['code']), (404, 'not_found'))
        invalid = self.auth(token, path='/api/v1/media?unexpected=1')
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(self.auth(token, path='/api/v1/media?collection_id=1&collection_id=1').status_code, 400)
        with patch.object(api, 'feed', side_effect=lambda cid, kind, deadline: [] if kind == 'exclusions' else [
                {'mediaServerId': '42', 'internalPath': '/private/path', 'accessToken': 'secret',
                 'mediaData': {'title': 'Sample', 'year': 2020, 'type': 'movie', 'providerIds': {'tmdb': ['1']}}}
        ]):
            response = self.auth(token, path='/api/v1/media?collection_id=1&state=all')
        self.assertEqual(response.status_code, 200)
        item = response.json['data'][0]
        self.assertEqual(set(item), {'id', 'media_id', 'collection_id', 'title', 'year', 'type', 'state',
                                    'provider_ids', 'entered_leaving_at', 'keep'})
        self.assertEqual(item, {'id': '1:42', 'media_id': '42', 'collection_id': 1, 'title': 'Sample',
                                'year': 2020, 'type': 'movie', 'state': 'leaving',
                                'provider_ids': {'tmdb': ['1'], 'tvdb': [], 'imdb': []},
                                'entered_leaving_at': None, 'keep': None})

    def test_exact_media_identity_is_collection_bound_and_kept_takes_precedence(self):
        token = self.make_key(scopes=('media:read',))
        leaving = {'mediaServerId': '42', 'addDate': '2026-09-01T03:00:00+03:00',
                   'mediaData': {'title': 'Leaving copy', 'type': 'movie', 'tmdbId': 100}}
        kept = {'mediaServerId': '42', 'addDate': '2026-09-01T00:00:00Z',
                'mediaData': {'title': 'Kept copy', 'type': 'movie', 'tmdbId': 100}}
        with patch.object(api, 'feed', side_effect=lambda cid, kind, deadline:
                          [kept] if kind == 'exclusions' else [leaving]) as feed:
            response = self.auth(token, path='/api/v1/media/1:42')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['data']['id'], '1:42')
            self.assertEqual(response.json['data']['state'], 'kept')
            self.assertEqual(response.json['data']['title'], 'Kept copy')
            self.assertIsNone(response.json['data']['entered_leaving_at'])
            self.assertEqual({call.args[0] for call in feed.call_args_list}, {1})
            for item_id in ('2:42', '0:42', '1:042', '1:0', '1:42:3', '1000000000:42'):
                with self.subTest(item_id=item_id):
                    self.assertEqual(self.auth(token, path='/api/v1/media/' + item_id).status_code, 404)
            self.assertEqual(self.auth(token, path='/api/v1/media/1:42?state=all').status_code, 400)
        with patch.object(api, 'feed', return_value=[]):
            self.assertEqual(self.auth(token, path='/api/v1/media/1:42').status_code, 404)
        self.assertEqual(self.auth(self.make_key(scopes=('collections:read',)),
                                   path='/api/v1/media/1:42').json['error']['code'], 'insufficient_scope')

    def test_provider_lookup_preserves_all_matches_and_disambiguates_media_type(self):
        token = self.make_key(scopes=('media:read',))
        entries = {
            1: [{'mediaServerId': '42', 'mediaData': {'title': 'Movie', 'type': 'movie', 'tmdbId': 100}},
                {'mediaServerId': '43', 'mediaData': {'title': 'Episode', 'type': 'episode', 'tmdbId': 100}}],
            3: [{'mediaServerId': '44', 'mediaData': {'title': 'Show', 'type': 'series',
                                                     'providerIds': {'tmdb': ['100'], 'tvdb': ['200']}}}],
            5: [{'mediaServerId': '45', 'mediaData': {'title': 'Another collection', 'type': 'movie',
                                                     'providerIds': {'tmdb': ['100']}}}],
        }
        with patch.object(api, 'feed', side_effect=lambda cid, kind, deadline:
                          [] if kind == 'exclusions' else entries.get(cid, [])):
            movies = self.auth(token, path='/api/v1/media?provider=tmdb&provider_id=100&media_type=movie&state=all')
            self.assertEqual([row['id'] for row in movies.json['data']], ['1:42', '5:45'])
            shows = self.auth(token, path='/api/v1/media?provider=tmdb&provider_id=100&media_type=show')
            self.assertEqual([row['id'] for row in shows.json['data']], ['3:44'])
            exact = self.auth(token, path='/api/v1/media?media_id=42')
            self.assertEqual([row['id'] for row in exact.json['data']], ['1:42'])
            narrowed = self.auth(token, path='/api/v1/media?provider=tmdb&provider_id=100&media_type=movie&collection_id=5')
            self.assertEqual([row['id'] for row in narrowed.json['data']], ['5:45'])
            hidden = self.auth(token, path='/api/v1/media?provider=tmdb&provider_id=100&media_type=movie&collection_id=2')
            self.assertEqual(hidden.status_code, 404)
            for query in ('provider=tmdb', 'provider_id=100', 'provider=tmdb&provider_id=100',
                          'provider=url&provider_id=100&media_type=movie',
                          'provider=tmdb&provider_id=0100&media_type=movie',
                          'provider=tvdb&provider_id=0&media_type=show',
                          'provider=tmdb&provider_id=1.5&media_type=movie',
                          'provider=imdb&provider_id=tt0000000&media_type=movie',
                          'provider=imdb&provider_id=https://example.test&media_type=movie',
                          'media_id=042', 'media_type=episode', 'media_id=42&media_id=42'):
                with self.subTest(query=query):
                    self.assertEqual(self.auth(token, path='/api/v1/media?' + query).status_code, 400)

    def test_provider_and_lifecycle_metadata_are_allowlisted_and_bounded(self):
        token = self.make_key(scopes=('media:read',))
        item = {'mediaServerId': '42', 'addDate': '2026-09-01T03:00:00+03:00',
                'imdbId': 'tt9999999', 'accessToken': 'private-token',
                'mediaData': {'title': 'Sample', 'type': 'movie', 'tmdbId': True,
                              'tvdbId': 200, 'imdbId': 'tt1234567',
                              'providerIds': {'tmdb': ['0', '01', 1.2, False, {}, 'https://secret.test',
                                                      *map(str, range(1, 30))],
                                              'tvdb': ['200', '201'], 'imdb': ['tt1234567', 'tt2345678'],
                                              'private': ['secret-token']}}}
        with patch.object(api, 'feed', side_effect=lambda cid, kind, deadline:
                          [] if kind == 'exclusions' else [item]):
            response = self.auth(token, path='/api/v1/media/1:42')
            data = response.json['data']
            self.assertEqual(data['provider_ids']['tmdb'], list(map(str, range(1, 11))))
            self.assertEqual(data['provider_ids']['tvdb'], ['200', '201'])
            self.assertEqual(data['provider_ids']['imdb'], ['tt1234567', 'tt2345678'])
            self.assertEqual(data['entered_leaving_at'], '2026-09-01T00:00:00Z')
            self.assertNotIn('private-token', response.get_data(as_text=True))
            self.assertNotIn('secret.test', response.get_data(as_text=True))
            self.assertNotIn('tt9999999', response.get_data(as_text=True))
            for date in (None, '2026-09-01T00:00:00', '2026-09-31T00:00:00Z', 'secret/path', True):
                item['addDate'] = date
                self.assertIsNone(self.auth(token, path='/api/v1/media/1:42').json['data']['entered_leaving_at'])

    def test_embedded_keep_obeys_scope_and_current_ownership(self):
        self.seed_keep(user_id='7', media_id='42')
        self.seed_keep(user_id='8', media_id='43')
        entries = [{'mediaServerId': mid, 'mediaData': {'title': 'Kept', 'type': 'movie'}}
                   for mid in ('42', '43')]
        owner_without_scope = self.make_key(scopes=('media:read',))
        owner_with_scope = self.make_key(scopes=('media:read', 'keeps:read'))
        member = self.make_key(user_id='8', scopes=('media:read', 'keeps:read'))
        with patch.object(api, 'feed', side_effect=lambda cid, kind, deadline:
                          entries if kind == 'exclusions' else []):
            self.assertIsNone(self.auth(owner_without_scope, path='/api/v1/media/1:42').json['data']['keep'])
            own = self.auth(owner_with_scope, path='/api/v1/media/1:42').json['data']['keep']
            self.assertTrue(own['owned_by_current_user'])
            self.assertEqual(own['expires_at'], '2026-11-01T00:00:00Z')
            self.assertIsNone(self.auth(member, path='/api/v1/media/1:42').json['data']['keep'])
            self.assertTrue(self.auth(member, path='/api/v1/media/1:43').json['data']['keep']['owned_by_current_user'])

    def test_embedded_keep_rechecks_permissions_and_attribution_after_upstream_read(self):
        self.seed_keep(user_id='7', media_id='42')
        token = self.make_key(user_id='8', scopes=('media:read', 'keeps:read'))
        item = {'mediaServerId': '42', 'mediaData': {'title': 'Kept', 'type': 'movie'}}
        for path in ('/api/v1/media?collection_id=1&state=kept', '/api/v1/media/1:42'):
            for change in ('manager permission', 'attribution'):
                with self.subTest(path=path, change=change):
                    with closing(keep.attribution_db()) as db, db:
                        db.execute("UPDATE user_profiles SET can_remove_any=? WHERE plex_id='8'",
                                   (int(change == 'manager permission'),))
                        db.execute('UPDATE keep_attribution SET user_id=? WHERE collection_id=? AND media_id=?',
                                   ('7' if change == 'manager permission' else '8', '1', '42'))
                    def changed_feed(cid, kind, deadline):
                        with closing(keep.attribution_db()) as db, db:
                            db.execute("UPDATE user_profiles SET can_remove_any=0 WHERE plex_id='8'")
                            db.execute("UPDATE keep_attribution SET user_id='7' WHERE collection_id='1' AND media_id='42'")
                        return [item] if kind == 'exclusions' else []
                    with patch.object(api, 'feed', side_effect=changed_feed):
                        response = self.auth(token, path=path)
                    self.assertEqual(response.status_code, 200)
                    data = response.json['data']
                    self.assertIsNone((data[0] if isinstance(data, list) else data)['keep'])

    def test_operational_status_requires_explicit_scope_and_current_owner(self):
        existing = self.make_key()
        self.assertEqual(self.auth(existing, path='/api/v1/status').json['error']['code'], 'insufficient_scope')
        member = self.make_key(user_id='8', scopes=('status:read',))
        self.assertEqual(self.auth(member, path='/api/v1/status').json['error']['code'], 'permission_denied')
        token = self.make_key(scopes=('status:read',))
        self.assertEqual(self.client.get('/api/v1/status').status_code, 401)
        self.assertEqual(self.auth(token, path='/api/v1/status?limit=1').status_code, 400)
        with (patch.object(keep.background_jobs.Store, '_initialize',
                          side_effect=AssertionError('Status must not initialize jobs')),
             patch.object(keep.background_jobs.Store, '_retry_controls',
                          side_effect=AssertionError('Status must not retry controls')),
             patch.object(keep.requests, 'get', side_effect=AssertionError('No probe')),
             patch.object(keep.requests, 'post', side_effect=AssertionError('No write'))):
            response = self.auth(token, path='/api/v1/status')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['data']['version'], keep.APP_VERSION)
        self.assertTrue(response.json['data']['jobs'])

    def test_status_allowlist_and_sqlite_failures_do_not_leak_diagnostics(self):
        token = self.make_key(scopes=('status:read',))
        snapshot = {'worker': {'available': True, 'checked_at': '2026-10-11T22:00:00+00:00',
                               'label': 'private worker secret'},
                    'jobs': [{'id': 'keep-expiry', 'status': 'success', 'last_run': '2026-10-11T21:55:00Z',
                              'last_success': '2026-10-11T21:55:00Z', 'next_run': None,
                              'last_attempt_status': 'success', 'queued': False, 'interval': 30,
                              'result': 'private result secret', 'scope': 'private fingerprint'}]}
        with patch.object(keep, 'jobs_snapshot', return_value=snapshot) as jobs:
            response = self.auth(token, path='/api/v1/status')
        jobs.assert_called_once_with(read_only=True)
        self.assertEqual(set(response.json['data']), {'version', 'observed_at', 'worker', 'jobs'})
        self.assertEqual(set(response.json['data']['worker']), {'available', 'heartbeat_at'})
        self.assertEqual(set(response.json['data']['jobs'][0]), {'id', 'status', 'last_run_at',
                         'last_success_at', 'next_run_at', 'last_attempt_status', 'queued', 'interval_seconds'})
        self.assertNotIn('private', response.get_data(as_text=True))
        with patch.object(keep, 'jobs_snapshot', side_effect=api_v1.sqlite3.OperationalError('private database path')):
            failed = self.auth(token, path='/api/v1/status')
        self.assertEqual(failed.status_code, 503)
        self.assertEqual(failed.json['error']['code'], 'service_unavailable')
        self.assertNotIn('private', failed.get_data(as_text=True))

    def test_new_reads_discard_results_after_settings_change_or_revocation(self):
        token = self.make_key(scopes=('media:read', 'status:read'))
        item = {'mediaServerId': '42', 'mediaData': {'title': 'Before revoke'}}
        def revoke(cid, kind, deadline):
            with closing(keep.attribution_db()) as db, db:
                db.execute('UPDATE api_keys SET revoked_at=? WHERE secret_hash=?',
                           (time.time(), hashlib.sha256(token.encode()).hexdigest()))
            return [] if kind == 'exclusions' else [item]
        with patch.object(api, 'feed', side_effect=revoke):
            self.assertEqual(self.auth(token, path='/api/v1/media/1:42').status_code, 401)
        token = self.make_key(scopes=('status:read',))
        def changed_status(**kwargs):
            keep.connection_settings.save({'MAINTAINERR_URL': 'http://changed.example.test'})
            return {'worker': {'available': False, 'checked_at': None}, 'jobs': []}
        with patch.object(keep, 'jobs_snapshot', side_effect=changed_status):
            self.assertEqual(self.auth(token, path='/api/v1/status').status_code, 409)

    def test_pagination_over_100_media_uses_complete_feed(self):
        token = self.make_key(scopes=('media:read',))
        def feed(cid, kind, deadline):
            if kind == 'exclusions':
                return []
            return [{'mediaServerId': str(index + 1), 'mediaData': {'title': f'Title {index}', 'year': 2020, 'type': 'movie'}}
                    for index in range(103)]
        with patch.object(api, 'feed', side_effect=feed):
            first = self.auth(token, path='/api/v1/media?collection_id=1&limit=100')
            second = self.auth(token, path='/api/v1/media?collection_id=1&limit=100&offset=100')
        self.assertEqual((first.status_code, len(first.json['data'])), (200, 100))
        self.assertEqual(first.json['pagination'], {'limit': 100, 'offset': 0, 'total': 103, 'next_offset': 100})
        self.assertEqual((second.status_code, len(second.json['data'])), (200, 3))
        self.assertEqual(second.json['pagination']['next_offset'], None)


    def test_aggregate_over_10000_fails_without_partial_media_page(self):
        token = self.make_key(scopes=('media:read',))
        with patch.object(api, 'feed', side_effect=lambda cid, kind, deadline: [] if kind == 'exclusions' else [
                {'mediaServerId': str(index), 'mediaData': {'title': f'Title {index}'}}
                for index in range(1, 10002)]):
            response = self.auth(token, path='/api/v1/media?collection_id=1&limit=100&offset=10000')
        self.assertEqual((response.status_code, response.json['error']['code']), (422, 'result_limit_exceeded'))
        self.assertNotIn('data', response.json)
        self.assertIn('Filter by collection', response.json['error']['message'])

    def test_exclusion_write_requires_bounded_exact_success_acknowledgement(self):
        class UpstreamResponse:
            status_code = 200
            def __init__(self, chunks):
                self.chunks = chunks
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def iter_content(self, chunk_size):
                return iter(self.chunks)

        cases = [
            ('missing code', [b'{"message":"ok"}'], False),
            ('zero code', [b'{"code":0}'], False),
            ('boolean code', [b'{"code":true}'], False),
            ('oversized body', [b' ' * 65537], False),
            ('integer success', [b'{"code":1}'], True),
        ]
        for label, chunks, succeeds in cases:
            with self.subTest(label=label), \
                 patch.object(api_v1.requests, 'post', return_value=UpstreamResponse(chunks)) as post:
                if succeeds:
                    self.assertIsNone(api.exclusion_write(1, '42', 0))
                else:
                    with self.assertRaises(api_v1.ApiProblem) as caught:
                        api.exclusion_write(1, '42', 0)
                    self.assertEqual((caught.exception.status, caught.exception.code), (502, 'mutation_uncertain'))
                self.assertTrue(post.call_args.kwargs['stream'])
                self.assertEqual(post.call_args.kwargs['timeout'], 5)
                self.assertFalse(post.call_args.kwargs['allow_redirects'])

    def test_feed_pages_streaming_payload_until_short_page(self):
        pages = []
        for ids in (range(1, 101), range(101, 102)):
            response = MagicMock()
            response.status_code = 200
            response.iter_content.return_value = [json.dumps({'items': [
                {'mediaServerId': str(value), 'mediaData': {'title': 'T'}} for value in ids
            ]}).encode()]
            response.__enter__ = unittest.mock.Mock(return_value=response)
            response.__exit__ = unittest.mock.Mock(return_value=False)
            pages.append(response)
        with patch.object(keep, 'connection_value', return_value='http://maintainerr'), \
             patch.object(api_v1.requests, 'get', side_effect=pages) as get:
            rows = api.feed(1, 'media', time.monotonic() + 20)
        self.assertEqual(len(rows), 101)
        self.assertEqual(get.call_count, 2)
        self.assertTrue(get.call_args_list[0].args[0].endswith('/content/1'))
        self.assertTrue(get.call_args_list[1].args[0].endswith('/content/2'))
        self.assertTrue(get.call_args.kwargs['stream'])

    def test_keeps_are_owner_scoped_and_indefinite_permission_is_live(self):
        self.seed_keep(user_id='7', media_id='41')
        self.seed_keep(user_id='8', media_id='42')
        owner_key = self.make_key(scopes=('keeps:read', 'keeps:write'))
        bob_client = keep.app.test_client()
        bob_key = self.make_key(user_id='8', scopes=('keeps:read', 'keeps:write'), client=bob_client)
        bob_rows = self.auth(bob_key, path='/api/v1/keeps').json['data']
        self.assertEqual([row['media_id'] for row in bob_rows], ['42'])
        self.assertEqual(self.auth(bob_key, path='/api/v1/keeps/1:41').status_code, 404)
        self.assertEqual(self.auth(owner_key, path='/api/v1/keeps/1:42').status_code, 200)
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET can_remove_any=1 WHERE plex_id='7'")
        manager_rows = self.auth(owner_key, path='/api/v1/keeps').json['data']
        self.assertEqual({row['media_id'] for row in manager_rows}, {'41', '42'})

        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET can_keep_indefinitely=0 WHERE plex_id='7'")
        with patch.object(api, 'feed', return_value=[{'mediaServerId': '42', 'mediaData': {}, 'ruleGroupId': 1}]), \
             patch.object(api, 'exclusion_write') as write:
            response = self.auth(bob_key, method='PATCH', path='/api/v1/keeps/1:42',
                                 json={'duration': 'indefinite'}, headers={'Idempotency-Key': 'indefinite-denied-001'})
        self.assertEqual((response.status_code, response.json['error']['code']), (403, 'permission_denied'))
        write.assert_not_called()

    def test_post_patch_delete_contract_and_idempotent_replay(self):
        token = self.make_key(scopes=('keeps:read', 'keeps:write'))
        feed = lambda cid, kind, deadline: ([] if kind == 'exclusions' else [
            {'mediaServerId': '42', 'mediaData': {'title': 'Eligible'}, 'ruleGroupId': 1}
        ])
        with patch.object(api, 'feed', side_effect=feed), \
             patch.object(api, 'exclusion_write') as exclusion, \
             patch.object(api, 'membership_remove') as membership:
            created = self.auth(token, method='POST', path='/api/v1/keeps',
                                json={'collection_id': 1, 'media_id': '42'},
                                headers={'Idempotency-Key': 'create-keep-request-0001'})
            self.assertEqual(created.status_code, 201)
            self.assertEqual(created.json['data']['id'], '1:42')
            self.assertEqual(created.json['data']['duration'], 'temporary')
            self.assertEqual(created.headers['Location'], '/api/v1/keeps/1:42')
            again = self.auth(token, method='POST', path='/api/v1/keeps',
                              json={'collection_id': 1, 'media_id': '42'},
                              headers={'Idempotency-Key': 'create-keep-request-0001'})
            self.assertEqual(again.status_code, 201)
            self.assertEqual(again.headers['Idempotency-Replayed'], 'true')
            self.assertEqual(exclusion.call_count, 1)
            self.assertEqual(membership.call_count, 1)

            changed = self.auth(token, method='POST', path='/api/v1/keeps',
                                json={'collection_id': 1, 'media_id': '43'},
                                headers={'Idempotency-Key': 'create-keep-request-0001'})
            self.assertEqual((changed.status_code, changed.json['error']['code']), (409, 'conflict'))

        with patch.object(api, 'feed', return_value=[{'mediaServerId': '42', 'mediaData': {}, 'ruleGroupId': 1}]), \
             patch.object(api, 'exclusion_write') as exclusion:
            patched = self.auth(token, method='PATCH', path='/api/v1/keeps/1:42',
                                json={'duration': 'indefinite'},
                                headers={'Idempotency-Key': 'patch-keep-request-0001'})
            self.assertEqual(patched.status_code, 200)
            self.assertEqual(patched.json['data']['duration'], 'indefinite')
            exclusion.assert_not_called()
            deleted = self.auth(token, method='DELETE', path='/api/v1/keeps/1:42',
                                headers={'Idempotency-Key': 'delete-keep-request-0001'})
            self.assertEqual(deleted.status_code, 204)
            self.assertEqual(deleted.data, b'')
            replayed = self.auth(token, method='DELETE', path='/api/v1/keeps/1:42',
                                 headers={'Idempotency-Key': 'delete-keep-request-0001'})
            self.assertEqual(replayed.status_code, 204)
            self.assertEqual(replayed.headers['Idempotency-Replayed'], 'true')
            self.assertEqual(exclusion.call_count, 1)
        with closing(keep.attribution_db()) as db:
            self.assertIsNone(db.execute('SELECT 1 FROM keep_schedules WHERE collection_id=? AND media_id=?', ('1', '42')).fetchone())

    def test_uncertain_attempt_is_retained_and_never_automatically_retried(self):
        token = self.make_key(scopes=('keeps:write',))
        feed = lambda cid, kind, deadline: ([] if kind == 'exclusions' else [
            {'mediaServerId': '42', 'mediaData': {}, 'ruleGroupId': 1}
        ])
        with patch.object(api, 'feed', side_effect=feed), \
             patch.object(api, 'exclusion_write', side_effect=api_v1.ApiProblem(502, 'mutation_uncertain', 'uncertain')) as write:
            first = self.auth(token, method='POST', path='/api/v1/keeps',
                              json={'collection_id': 1, 'media_id': '42'},
                              headers={'Idempotency-Key': 'uncertain-keep-write-001'})
            self.assertEqual((first.status_code, first.json['error']['code']), (502, 'mutation_uncertain'))
            retry = self.auth(token, method='POST', path='/api/v1/keeps',
                              json={'collection_id': 1, 'media_id': '42'},
                              headers={'Idempotency-Key': 'uncertain-keep-write-001'})
        self.assertEqual((retry.status_code, retry.json['error']['code']), (409, 'operation_uncertain'))
        self.assertEqual(write.call_count, 1)

    def test_lock_contention_and_revocation_during_eligibility_prevent_remote_write(self):
        token = self.make_key(scopes=('keeps:write',))
        with keep.keep_mutation_lock(), patch.object(api, 'exclusion_write') as write:
            busy = self.auth(token, method='POST', path='/api/v1/keeps',
                             json={'collection_id': 1, 'media_id': '42'},
                             headers={'Idempotency-Key': 'lock-contention-write-01'})
        self.assertEqual((busy.status_code, busy.json['error']['code']), (409, 'busy'))
        write.assert_not_called()

        def feed(cid, kind, deadline):
            if kind == 'exclusions':
                return []
            with closing(keep.attribution_db()) as db, db:
                db.execute("UPDATE user_profiles SET session_version=session_version+1 WHERE plex_id='7'")
            return [{'mediaServerId': '42', 'mediaData': {}, 'ruleGroupId': 1}]
        with patch.object(api, 'feed', side_effect=feed), patch.object(api, 'exclusion_write') as write:
            denied = self.auth(token, method='POST', path='/api/v1/keeps',
                               json={'collection_id': 1, 'media_id': '42'},
                               headers={'Idempotency-Key': 'revocation-race-write-01'})
        self.assertEqual((denied.status_code, denied.json['error']['code']), (401, 'invalid_token'))
        write.assert_not_called()

    def test_settings_change_after_request_entry_prevents_stale_endpoint_write(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('MAINTAINERR_URL', None)
            keep.connection_settings.save({'MAINTAINERR_URL': 'https://old.example.invalid'})
            token = self.make_key(scopes=('keeps:write',))
            claim = api.claim_request
            def change_settings(*args):
                result = claim(*args)
                keep.connection_settings.save({'MAINTAINERR_URL': 'https://new.example.invalid'})
                return result
            with patch.object(api, 'claim_request', side_effect=change_settings), \
                 patch.object(api, 'feed', side_effect=lambda cid, kind, deadline:
                     [] if kind == 'exclusions' else [{'mediaServerId': '42', 'mediaData': {}}]), \
                 patch.object(api_v1.requests, 'post') as post, \
                 patch.object(api_v1.requests, 'delete') as delete:
                response = self.auth(token, method='POST', path='/api/v1/keeps',
                    json={'collection_id':1, 'media_id':'42'},
                    headers={'Idempotency-Key':'settings-race-write-0001'})
            self.assertEqual((response.status_code, response.json['error']['code']), (409, 'conflict'))
            post.assert_not_called()
            delete.assert_not_called()
            with closing(keep.attribution_db()) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM keep_schedules').fetchone()[0], 0)
                self.assertEqual(db.execute('SELECT count(*) FROM api_idempotency').fetchone()[0], 0)

    def test_settings_change_during_media_read_discards_the_previous_configuration_result(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('MAINTAINERR_URL', None)
            keep.connection_settings.save({'MAINTAINERR_URL':'https://old.example.invalid'})
            token = self.make_key(scopes=('media:read',))
            def change_settings(cid, kind, deadline):
                if kind == 'exclusions':
                    keep.connection_settings.save({'MAINTAINERR_URL':'https://new.example.invalid'})
                    return []
                return [{'mediaServerId':'42', 'mediaData':{'title':'Previous service title'}}]
            with patch.object(api, 'feed', side_effect=change_settings):
                response = self.auth(token, path='/api/v1/media?collection_id=1')
            self.assertEqual((response.status_code, response.json['error']['code']), (409, 'conflict'))
            self.assertNotIn('data', response.json)
            self.assertNotIn('Previous service title', response.get_data(as_text=True))

    def test_completed_write_keeps_success_when_settings_change_before_response(self):
        token = self.make_key(scopes=('keeps:write',))
        original = api.finish_response
        def change_after_commit(response):
            keep.connection_settings.save({'SMTP_SENDER_NAME':'Updated synthetic sender'})
            return original(response)
        feed = lambda cid, kind, deadline: ([] if kind == 'exclusions' else [
            {'mediaServerId':'42', 'mediaData':{}}])
        with patch.dict(keep.app.after_request_funcs,
                {api.blueprint.name:[change_after_commit]}), \
             patch.object(api, 'feed', side_effect=feed), \
             patch.object(api, 'exclusion_write') as write, \
             patch.object(api, 'membership_remove'):
            response = self.auth(token, method='POST', path='/api/v1/keeps',
                json={'collection_id':1, 'media_id':'42'},
                headers={'Idempotency-Key':'completed-write-response-0001'})
        with closing(keep.attribution_db()) as db:
            self.assertEqual(db.execute('SELECT status FROM api_idempotency').fetchone()[0], 'succeeded')
            self.assertEqual(db.execute('SELECT count(*) FROM keep_schedules').fetchone()[0], 1)
        write.assert_called_once()
        self.assertEqual(response.status_code, 201)

    def test_api_error_envelopes_do_not_leak_exceptions(self):
        token = self.make_key(scopes=('media:read',))
        with patch.object(api, 'feed', side_effect=RuntimeError('secret upstream url')):
            response = self.auth(token, path='/api/v1/media')
        self.assertEqual((response.status_code, response.json['error']['code']), (500, 'internal_error'))
        self.assertNotIn('secret upstream url', response.get_data(as_text=True))
        self.assertIn('no-store', response.headers.get('Cache-Control', ''))

    def test_key_management_requires_csrf_before_create_or_revoke(self):
        token = self.make_key()
        with closing(keep.attribution_db()) as db:
            key_id = db.execute('SELECT id FROM api_keys WHERE secret_hash=?',
                                (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()[0]
        for path in ('/settings/api-keys', '/account/api-keys'):
            for action in ('create', 'revoke', 'rotate', 'remove'):
                with self.subTest(path=path, action=action):
                    response = self.client.post(path, data={
                        'csrf_token': 'wrong-token', 'action': action, 'key_id': key_id,
                        'name': 'csrf bypass', 'expiry_days': '90', 'scope': ['collections:read']})
                    self.assertEqual(response.status_code, 403)
            no_csrf = self.client.post(path, data={
                'action': 'create', 'name': 'csrf bypass', 'expiry_days': '90',
                'scope': ['collections:read']})
            self.assertEqual(no_csrf.status_code, 403)
        with closing(keep.attribution_db()) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM api_keys').fetchone()[0], 1)
            self.assertIsNone(db.execute('SELECT revoked_at FROM api_keys WHERE id=?', (key_id,)).fetchone()[0])

    def test_account_cannot_revoke_or_rotate_another_accounts_key(self):
        owner_token = self.make_key()
        with closing(keep.attribution_db()) as db:
            owner_row = dict(db.execute('SELECT * FROM api_keys WHERE secret_hash=?',
                                        (hashlib.sha256(owner_token.encode()).hexdigest(),)).fetchone())
        bob_client = keep.app.test_client()
        self.login(bob_client, '8', 'member')
        for action in ('revoke', 'rotate'):
            response = bob_client.post('/settings/api-keys', data={
                'csrf_token': 'test-csrf', 'action': action, 'key_id': owner_row['id']})
            self.assertEqual(response.status_code, 403)
            self.assertIn('Owner access only', response.get_data(as_text=True))
            with closing(keep.attribution_db()) as db:
                current = db.execute('SELECT * FROM api_keys WHERE id=?', (owner_row['id'],)).fetchone()
                self.assertIsNone(current['revoked_at'])
                self.assertEqual(db.execute('SELECT count(*) FROM api_keys').fetchone()[0], 1)
        self.assertEqual(self.auth(owner_token).status_code, 200)

    def test_per_key_rate_limit_returns_retry_after(self):
        token = self.make_key(scopes=('collections:read',))
        with closing(keep.attribution_db()) as db, db:
            key_id = db.execute('SELECT id FROM api_keys WHERE secret_hash=?',
                                (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()[0]
            now = int(time.time())
            window = now - now % 60
            db.execute('INSERT INTO api_rate_limits(subject,window,attempts) VALUES (?,?,60)',
                       ('key:' + key_id + ':read', window))
        response = self.auth(token)
        self.assertEqual((response.status_code, response.json['error']['code']), (429, 'rate_limited'))
        retry_after = int(response.headers['Retry-After'])
        self.assertGreaterEqual(retry_after, 1)
        self.assertLessEqual(retry_after, 60)

    def test_manager_revocation_during_read_blocks_write_and_idempotent_replay(self):
        self.seed_keep(user_id='7', media_id='41')
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET can_remove_any=1 WHERE plex_id='8'")
        bob = keep.app.test_client()
        manager_key = self.make_key(user_id='8', scopes=('keeps:read', 'keeps:write'), client=bob)
        item = {'mediaServerId': '41', 'mediaData': {}, 'ruleGroupId': 1}

        def revoke_during_lookup(cid, kind, deadline):
            if kind == 'exclusions':
                with closing(keep.attribution_db()) as db, db:
                    db.execute("UPDATE user_profiles SET can_remove_any=0 WHERE plex_id='8'")
                return [item]
            return []

        with patch.object(api, 'feed', side_effect=revoke_during_lookup), \
             patch.object(api, 'exclusion_write') as write:
            denied = self.auth(manager_key, method='PATCH', path='/api/v1/keeps/1:41',
                               json={'duration': 'temporary'},
                               headers={'Idempotency-Key': 'manager-race-write-0001'})
        self.assertIn(denied.status_code, (403, 404))
        write.assert_not_called()

        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET can_remove_any=1 WHERE plex_id='8'")
        with patch.object(api, 'feed', return_value=[item]):
            first = self.auth(manager_key, method='PATCH', path='/api/v1/keeps/1:41',
                              json={'duration': 'temporary'},
                              headers={'Idempotency-Key': 'manager-replay-check-0001'})
        self.assertEqual(first.status_code, 200)
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET can_remove_any=0 WHERE plex_id='8'")
        replay = self.auth(manager_key, method='PATCH', path='/api/v1/keeps/1:41',
                           json={'duration': 'temporary'},
                           headers={'Idempotency-Key': 'manager-replay-check-0001'})
        self.assertIn(replay.status_code, (403, 404),
                      'replay must recheck live object permission before returning cached data')

    def test_openapi_routes_match_live_api_methods(self):
        from pathlib import Path
        spec = json.loads(Path('static/openapi.json').read_text())
        documented = {}
        for path, item in spec['paths'].items():
            route = '/api/v1' + re.sub(r'\{([^}]+)\}', r'<\1>', path)
            documented[route] = {method.upper() for method in item
                                 if method.lower() in ('get', 'post', 'patch', 'delete')}
        actual = {}
        for rule in keep.app.url_map.iter_rules():
            if rule.rule == '/api/v1' or rule.rule.startswith('/api/v1/'):
                actual.setdefault(rule.rule, set()).update(set(rule.methods) - {'HEAD', 'OPTIONS'})
        self.assertEqual(actual, documented)

    def test_openapi_collection_schema_matches_live_payload(self):
        from pathlib import Path
        spec = json.loads(Path('static/openapi.json').read_text())
        def resolve(reference):
            target = spec
            for part in reference.removeprefix('#/').split('/'):
                target = target[part]
            return target
        token = self.make_key()
        collection_schema = resolve(spec['paths']['/collections']['get']['responses']['200']['content']['application/json']['schema']['$ref'])
        collection_item_schema = resolve(collection_schema['properties']['data']['items']['$ref'])
        collections = self.auth(token, path='/api/v1/collections?limit=1')
        self.assertEqual(collections.status_code, 200)
        self.assertEqual(set(collections.json['data'][0]), set(collection_item_schema['properties']))

    def test_openapi_media_and_keep_schemas_match_live_payloads(self):
        from pathlib import Path
        spec = json.loads(Path('static/openapi.json').read_text())
        def resolve(reference):
            target = spec
            for part in reference.removeprefix('#/').split('/'):
                target = target[part]
            return target
        token = self.make_key()
        media_schema = resolve(spec['paths']['/media']['get']['responses']['200']['content']['application/json']['schema']['$ref'])
        media_item_schema = resolve(media_schema['properties']['data']['items']['$ref'])
        with patch.object(api, 'feed', side_effect=lambda cid, kind, deadline: [] if kind == 'exclusions' else [
                {'mediaServerId': '42', 'mediaData': {'title': 'Contract title', 'year': 2024, 'type': 'movie'}}
        ]):
            media = self.auth(token, path='/api/v1/media?collection_id=1')
        self.assertEqual(set(media.json['data'][0]), set(media_item_schema['properties']))

        self.seed_keep(user_id='7', media_id='42')
        keep_schema = resolve(spec['paths']['/keeps']['get']['responses']['200']['content']['application/json']['schema']['$ref'])
        keep_item_schema = resolve(keep_schema['properties']['data']['items']['$ref'])
        keeps = self.auth(token, path='/api/v1/keeps?collection_id=1')
        self.assertEqual(keeps.status_code, 200)
        self.assertEqual(set(keeps.json['data'][0]), set(keep_item_schema['properties']))

        response_schema = resolve('#/components/schemas/KeepResponse')
        self.assertEqual(set(response_schema['required']), {'data'})
        self.assertEqual(response_schema['properties']['data']['$ref'], '#/components/schemas/Keep')
        for path, method, status in (('/keeps/{keep_id}', 'get', '200'),
                                     ('/keeps', 'post', '201'),
                                     ('/keeps/{keep_id}', 'patch', '200')):
            reference = spec['paths'][path][method]['responses'][status]['content']['application/json']['schema']['$ref']
            self.assertEqual(reference, '#/components/schemas/KeepResponse')

        singular = self.auth(token, path='/api/v1/keeps/1:42')
        self.assertEqual(singular.status_code, 200)
        self.assertEqual(set(singular.json), set(response_schema['properties']))
        self.assertEqual(set(singular.json['data']), set(keep_item_schema['properties']))

        feed = lambda cid, kind, deadline: ([] if kind == 'exclusions' else [
            {'mediaServerId': '43', 'mediaData': {'title': 'Eligible'}, 'ruleGroupId': 1}])
        with patch.object(api, 'feed', side_effect=feed), \
             patch.object(api, 'exclusion_write'), patch.object(api, 'membership_remove'):
            created = self.auth(token, method='POST', path='/api/v1/keeps',
                                json={'collection_id': 1, 'media_id': '43'},
                                headers={'Idempotency-Key': 'schema-create-live-0001'})
        self.assertEqual(created.status_code, 201)
        self.assertEqual(set(created.json), set(response_schema['properties']))
        self.assertEqual(set(created.json['data']), set(keep_item_schema['properties']))

        with patch.object(api, 'feed', return_value=[
                {'mediaServerId': '43', 'mediaData': {}, 'ruleGroupId': 1}]):
            updated = self.auth(token, method='PATCH', path='/api/v1/keeps/1:43',
                                json={'duration': 'indefinite'},
                                headers={'Idempotency-Key': 'schema-patch-live-0001'})
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(set(updated.json), set(response_schema['properties']))
        self.assertEqual(set(updated.json['data']), set(keep_item_schema['properties']))

    def test_openapi_exact_media_and_status_schemas_match_live_payloads(self):
        from pathlib import Path
        spec = json.loads(Path('static/openapi.json').read_text())
        schemas = spec['components']['schemas']

        def assert_fields(payload, schema_name):
            schema = schemas[schema_name]
            self.assertEqual(set(payload), set(schema['properties']))
            self.assertLessEqual(set(schema['required']), set(payload))

        token = self.make_key(scopes=('media:read', 'keeps:read', 'status:read'))
        self.seed_keep(media_id='42')
        kept = {'mediaServerId': '42', 'ruleGroupId': 1,
                'mediaData': {'title': 'Kept contract title', 'type': 'movie', 'tmdbId': 100}}
        leaving = {'mediaServerId': '43', 'addDate': '2026-10-11T20:00:00+02:00',
                   'mediaData': {'title': 'Leaving contract title', 'type': 'show', 'tvdbId': 200}}
        with patch.object(api, 'feed', side_effect=lambda cid, kind, deadline:
                          [kept] if kind == 'exclusions' else [leaving]):
            for media_id in ('42', '43'):
                with self.subTest(media_id=media_id):
                    response = self.auth(token, path='/api/v1/media/1:' + media_id)
                    self.assertEqual(response.status_code, 200)
                    assert_fields(response.json, 'MediaResponse')
                    media = response.json['data']
                    assert_fields(media, 'Media')
                    assert_fields(media['provider_ids'], 'ProviderIds')
                    for provider, identifiers in media['provider_ids'].items():
                        definition = schemas['ProviderIds']['properties'][provider]
                        self.assertIsInstance(identifiers, list)
                        self.assertLessEqual(len(identifiers), definition['maxItems'])
                        self.assertEqual(len(identifiers), len(set(identifiers)))
                        for identifier in identifiers:
                            self.assertRegex(identifier, definition['items']['pattern'])
                    self.assertIn(media['state'], schemas['Media']['properties']['state']['enum'])
                    if media['keep'] is not None:
                        assert_fields(media['keep'], 'Keep')
            self.assertIsNotNone(self.auth(token, path='/api/v1/media/1:42').json['data']['keep'])
            self.assertIsNone(self.auth(token, path='/api/v1/media/1:43').json['data']['keep'])

        status = self.auth(token, path='/api/v1/status')
        self.assertEqual(status.status_code, 200)
        assert_fields(status.json, 'StatusResponse')
        assert_fields(status.json['data'], 'Status')
        assert_fields(status.json['data']['worker'], 'WorkerStatus')
        jobs = status.json['data']['jobs']
        self.assertTrue(jobs)
        self.assertLessEqual(len(jobs), schemas['Status']['properties']['jobs']['maxItems'])
        for job in jobs:
            with self.subTest(job_id=job['id']):
                assert_fields(job, 'JobStatus')
                for field in ('id', 'status', 'last_attempt_status'):
                    self.assertIn(job[field], schemas['JobStatus']['properties'][field]['enum'])
                interval = job['interval_seconds']
                if interval is not None:
                    self.assertIs(type(interval), int)
                    definition = schemas['JobStatus']['properties']['interval_seconds']
                    self.assertGreaterEqual(interval, definition['minimum'])
                    self.assertLessEqual(interval, definition['maximum'])


if __name__ == '__main__':
    unittest.main()
