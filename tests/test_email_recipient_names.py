"""Email recipient identity matching and safe searchable presentation."""
from contextlib import closing
from html.parser import HTMLParser
from unittest import TestCase

import test_keep

keep = test_keep.keep


class RecipientCards(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.cards = []
        self.card = None
        self.depth = 0
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == 'div':
            if self.card is not None:
                self.depth += 1
            elif 'recipient-row' in attributes.get('class', '').split():
                self.card = {'search': attributes.get('data-search-text'), 'text': ''}
                self.depth = 1
                self.cards.append(self.card)
        elif tag == 'button' and self.card is not None and 'data-user-toggle' in attributes:
            self.card['edit_name'] = attributes.get('data-edit-name')
            self.card['label'] = attributes.get('aria-label')

    def handle_endtag(self, tag):
        if tag == 'div' and self.card is not None:
            self.depth -= 1
            if self.depth == 0:
                self.card = None

    def handle_data(self, data):
        if self.card is not None:
            self.card['text'] += data


class EmailRecipientNameTests(TestCase):
    def setUp(self):
        test_keep.KeepTests.setUp(self)
        with closing(keep.attribution_db()) as db, db:
            self.original_recipients = [tuple(row) for row in db.execute('SELECT * FROM email_recipients')]
            self.original_subscriptions = [tuple(row) for row in db.execute('SELECT * FROM recipient_subscriptions')]
            db.execute('DELETE FROM recipient_subscriptions')
            db.execute('DELETE FROM email_recipients')
        self.addCleanup(self.restore_recipients)

    def restore_recipients(self):
        with closing(keep.attribution_db()) as db, db:
            db.execute('DELETE FROM recipient_subscriptions')
            db.execute('DELETE FROM email_recipients')
            db.executemany('INSERT INTO email_recipients VALUES (?, ?, ?)', self.original_recipients)
            db.executemany('INSERT INTO recipient_subscriptions VALUES (?, ?, ?)', self.original_subscriptions)

    def add_recipient(self, email):
        with closing(keep.attribution_db()) as db, db:
            db.execute('INSERT INTO email_recipients(email, enabled) VALUES (?, 1)', (email,))
            keep.ensure_recipient_subscriptions(db, email)

    def add_user(self, user_id, email, full_name='', display_name='', username=''):
        with closing(keep.attribution_db()) as db, db:
            db.execute('''INSERT INTO user_profiles
                (plex_id, email, full_name, display_name, plex_username)
                VALUES (?, ?, ?, ?, ?)''', (user_id, email, full_name, display_name, username))

    def cards(self):
        response = self.client.get('/settings/email')
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        return RecipientCards(html).cards, html

    def test_case_insensitive_matching_shows_full_name_and_searches_all_aliases(self):
        self.add_recipient('ALEX@example.com')
        self.add_user('alex', 'alex@EXAMPLE.COM', 'Alex Johnson', 'AJ', 'alex_plex')
        cards, _ = self.cards()
        self.assertEqual(len(cards), 1)
        self.assertIn('Alex Johnson', cards[0]['text'])
        self.assertIn('ALEX@example.com', cards[0]['text'])
        self.assertEqual(cards[0]['search'], 'ALEX@example.com Alex Johnson AJ alex_plex')
        self.assertEqual(cards[0]['edit_name'], 'Alex Johnson (ALEX@example.com)')
        self.assertEqual(cards[0]['label'], 'Edit Alex Johnson (ALEX@example.com)')

    def test_display_name_and_username_fallbacks_preserve_standalone_recipients(self):
        self.add_recipient('display@example.com')
        self.add_recipient('plex@example.com')
        self.add_recipient('standalone@example.com')
        self.add_user('display', 'display@example.com', ' ', 'Bailey', 'bailey_plex')
        self.add_user('plex', 'plex@example.com', username='CaseyPlex')
        cards, _ = self.cards()
        self.assertEqual(len(cards), 3)
        self.assertIn('Bailey', cards[0]['text'])
        self.assertIn('CaseyPlex', cards[1]['text'])
        self.assertEqual(cards[2]['search'], 'standalone@example.com')
        self.assertIn('standalone@example.com', cards[2]['text'])

    def test_shared_address_has_one_recipient_card_with_each_distinct_name(self):
        self.add_recipient('family@example.com')
        self.add_user('alex', 'family@example.com', 'Alex Johnson', 'AJ')
        self.add_user('bailey', 'FAMILY@example.com', 'Bailey Johnson', 'BJ')
        self.add_user('duplicate', 'family@example.com', 'Alex Johnson', 'Other alias')
        cards, _ = self.cards()
        self.assertEqual(len(cards), 1)
        self.assertIn('Alex Johnson, Bailey Johnson', cards[0]['text'])
        self.assertEqual(cards[0]['text'].count('Alex Johnson'), 1)
        self.assertIn('Other alias', cards[0]['search'])

    def test_profile_changes_are_reflected_without_changing_email_recipient(self):
        self.add_recipient('person@example.com')
        self.add_user('person', 'person@example.com', 'Original Name')
        self.assertIn('Original Name', self.cards()[0][0]['text'])
        with closing(keep.attribution_db()) as db, db:
            db.execute("UPDATE user_profiles SET full_name = 'Updated Name' WHERE plex_id = 'person'")
        cards, _ = self.cards()
        self.assertIn('Updated Name', cards[0]['text'])
        self.assertNotIn('Original Name', cards[0]['search'])
        self.assertIn('person@example.com', cards[0]['text'])

    def test_names_are_escaped_in_visible_text_and_search_attributes(self):
        self.add_recipient('quoted@example.com')
        name = 'Alex "A" <script>alert(1)</script> & Bailey'
        self.add_user('quoted', 'quoted@example.com', name)
        cards, html = self.cards()
        self.assertEqual(cards[0]['search'], 'quoted@example.com ' + name)
        self.assertIn(name, cards[0]['text'])
        self.assertNotIn('<script>alert(1)</script>', html)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', html)

    def test_expanded_validation_error_preserves_name_for_accessible_toggle(self):
        self.add_recipient('alex@example.com')
        self.add_user('alex', 'alex@example.com', 'Alex Johnson')
        response = self.client.post('/settings/recipients/preferences', data={
            'csrf_token': 'test-csrf', 'email': 'alex@example.com',
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        card = RecipientCards(response.get_data(as_text=True)).cards[0]
        self.assertEqual(card['edit_name'], 'Alex Johnson (alex@example.com)')
        self.assertEqual(card['label'], 'Close settings for Alex Johnson (alex@example.com)')
