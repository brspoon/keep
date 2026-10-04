"""Serialize branded mail through the shared transport without opening a socket."""
from contextlib import closing
from email import policy
from email.parser import BytesParser
from pathlib import Path
import unittest
from unittest.mock import patch

from test_keep import keep


class EmailMimeTests(unittest.TestCase):
    def setUp(self):
        settings = {'EMAIL_ENABLED': 'true', 'SMTP_HOST': 'smtp.example.test',
                    'SMTP_FROM': 'keep@example.test', 'SMTP_SENDER_NAME': 'Keep',
                    'SMTP_PORT': '465', 'SMTP_SECURITY': 'ssl',
                    'KEEP_URL': 'https://keep.example'}
        values = patch.object(keep, 'connection_value', side_effect=settings.get)
        values.start()
        self.addCleanup(values.stop)
        transport = patch.object(keep.smtplib, 'SMTP_SSL')
        self.transport = transport.start()
        self.addCleanup(transport.stop)
        self.smtp = self.transport.return_value.__enter__.return_value
        self.smtp.send_message.return_value = {}

    def captured_message(self):
        self.smtp.send_message.assert_called_once()
        message = self.smtp.send_message.call_args.args[0]
        return BytesParser(policy=policy.default).parsebytes(message.as_bytes())

    def assert_embedded_logo(self, message):
        self.assertEqual(message.get_content_type(), 'multipart/alternative')
        plain, related = list(message.iter_parts())
        self.assertEqual(plain.get_content_type(), 'text/plain')
        self.assertEqual(related.get_content_type(), 'multipart/related')
        body, logo = list(related.iter_parts())
        self.assertEqual(body.get_content_type(), 'text/html')
        self.assertIn(f'cid:{keep.email_templates.LOGO_CID}', body.get_content())
        self.assertEqual(logo.get_content_type(), 'image/png')
        self.assertEqual(logo['Content-ID'], f'<{keep.email_templates.LOGO_CID}>')
        self.assertEqual(logo.get_content_disposition(), 'inline')
        self.assertEqual(logo.get_filename(), 'keep-icon.png')
        canonical = Path(keep.__file__).with_name('static') / 'keep-icon-192.png'
        self.assertEqual(logo.get_payload(decode=True), canonical.read_bytes())
        self.assertEqual(message.get_body(preferencelist=('html',)), body)
        self.assertFalse(message.defects)
        return plain.get_content(), body.get_content()

    def test_invitation_and_password_reset_embed_the_canonical_png(self):
        profile = {'display_name': 'Alex', 'full_name': '', 'email': 'viewer@example.test'}
        for reset in (False, True):
            with self.subTest(reset=reset):
                self.smtp.send_message.reset_mock()
                keep.send_local_setup_email(profile, 'synthetic-token', reset)
                message = self.captured_message()
                plain, body = self.assert_embedded_logo(message)
                expected = 'Reset your Keep password' if reset else 'Set up your Keep account'
                self.assertEqual(message['Subject'], expected)
                self.assertEqual(message['Bcc'], profile['email'])
                self.assertIn('https://keep.example/auth/local/setup/synthetic-token', plain)
                self.assertIn('https://keep.example/auth/local/setup/synthetic-token', body)

    def test_digest_and_reminder_delivery_embed_the_same_logo(self):
        item = dict(collection_id=1, collection='Movies', title='Example', year=2026,
                    days=2, urgent=True)
        tables = ('notification_queue', 'notification_reminders',
                  'notification_deliveries', 'notification_batches')
        for kind in ('MEDIA_ADDED_TO_COLLECTION', keep.REMINDER_KIND):
            with self.subTest(kind=kind):
                with closing(keep.attribution_db()) as db, db:
                    for table in tables:
                        db.execute('DELETE FROM ' + table)
                self.smtp.send_message.reset_mock()
                keep.queue_notifications(1, ['synthetic-title'], kind, 1000)
                with patch.object(keep, 'reconcile_reminder_queue'), \
                     patch.object(keep, 'resolve_digest', return_value=[item]), \
                     patch.object(keep, 'get_recipient_delivery_preferences',
                                  return_value={'viewer@example.test': {1}}):
                    self.assertEqual(keep.process_digest(now=2000), 'sent')
                message = self.captured_message()
                plain, body = self.assert_embedded_logo(message)
                self.assertIn('Last chance · 2 days left', plain)
                self.assertIn('Example', body)
                self.assertEqual(message['Bcc'], 'viewer@example.test')

    def test_unbranded_mail_retains_its_plain_and_html_alternatives(self):
        keep.send_email('viewer@example.test', 'Test', '<p>Test</p>', 'Test')
        message = self.captured_message()
        self.assertEqual([part.get_content_type() for part in message.iter_parts()],
                         ['text/plain', 'text/html'])
        self.assertEqual(message.get_body(preferencelist=('plain',)).get_content().strip(), 'Test')
        self.assertEqual(message.get_body(preferencelist=('html',)).get_content().strip(), '<p>Test</p>')
