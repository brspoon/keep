import unittest
from html.parser import HTMLParser
import email_templates as email


class Elements(HTMLParser):
    def __init__(self, body):
        super().__init__()
        self.elements = []
        self.feed(body)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class EmailTemplateTests(unittest.TestCase):
    def test_all_email_types_have_inline_fallback_and_optional_system_theme(self):
        examples = [email.account_email('Alex', 'https://keep.example/setup', reset=reset)[1] for reset in (False, True)]
        examples.append(email.digest_email([dict(collection='Movies', title='Movie', days=7, urgent=True)], 'https://keep.example')[1])
        for body in examples:
            self.assertIn('prefers-color-scheme:dark', body)
            self.assertIn('name="color-scheme" content="light dark"', body)
            for _, attrs in Elements(body).elements:
                cls = attrs.get('class', '')
                if cls.startswith('mail-') and cls[5:] in email.STYLES:
                    self.assertIn(email.STYLES[cls[5:]], attrs.get('style', ''))
            self.assertIn('background:#efb34f;color:#17120a', body)
            self.assertNotIn('<script', body)
            self.assertNotIn('linear-gradient', body)

    def test_account_names_and_links_are_escaped_and_plain_text_preserved(self):
        for reset in (False, True):
            subject, body, plain = email.account_email('<Alex>', 'https://keep.example/setup?a=1&b=2', reset)
            self.assertIn('&lt;Alex&gt;', body)
            self.assertIn('?a=1&amp;b=2', body)
            self.assertIn('<Alex>', plain)
            self.assertIn('24 hours', body)
            self.assertIn('Reset' if reset else 'Set up', subject)

    def test_digest_uses_distinct_readable_urgent_badge_and_unknown_timing(self):
        _, body, plain = email.digest_email([
            dict(collection='Movies', title='<One>', year=2026, days=1, urgent=True),
            dict(collection='Movies', title='Unknown', days=None, urgent=False),
        ], 'https://keep.example')
        self.assertIn('mail-urgent', body)
        self.assertIn('Last chance · 1 day left', plain)
        self.assertIn('Check Keep for timing', plain)
        self.assertIn('&lt;One&gt;', body)
        self.assertIn('No poster', body)
