"""Bounded email validation with the existing permissive address policy."""
import itertools
import re
import unittest

from test_keep import keep


class EmailValidationTests(unittest.TestCase):
    def test_preserves_existing_address_policy(self):
        valid = ('person@example.com', 'a+b@sub.example.com', 'é@例.子',
                 'a@..b', 'a@b..', 'a@...', 'a..b@under_score.example')
        invalid = ('', 'a', '@b.c', 'a@', 'a@@b.c', 'a@b', 'a@.b', 'a@b.',
                   'a b@c.d', 'a@b.c\n', 'a@b.\u00a0c', 'a@b.\u2003c')
        for address in valid:
            with self.subTest(address=address):
                self.assertTrue(keep.valid_email_address(address))
        for address in invalid:
            with self.subTest(address=address):
                self.assertFalse(keep.valid_email_address(address))

    def test_matches_legacy_policy_for_bounded_generated_addresses(self):
        legacy = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
        for length in range(8):
            for characters in itertools.product('a.@ \u00a0', repeat=length):
                address = ''.join(characters)
                self.assertEqual(keep.valid_email_address(address),
                                 bool(legacy.fullmatch(address)), repr(address))

    def test_shared_length_limit_and_backtracking_triggers(self):
        self.assertTrue(keep.valid_email_address('a' * 250 + '@b.c'))
        self.assertFalse(keep.valid_email_address('a' * 251 + '@b.c'))
        # The old expression backtracks over each possible dot separator.
        for address in ('a@' + '.' * 100000 + ' a',
                        'a@' + 'b.' * 50000 + '@c',
                        'a@' + '.' * 100000 + 'b'):
            self.assertFalse(keep.valid_email_address(address))


if __name__ == '__main__':
    unittest.main()
