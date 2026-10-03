import tempfile
import unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch
from artwork_cache import ArtworkCache, namespace


class CacheTests(unittest.TestCase):
    def test_cache_module_is_in_image_and_build_context(self):
        root = Path(__file__).resolve().parents[1]
        self.assertIn('!artwork_cache.py', (root / '.dockerignore').read_text().splitlines())
        self.assertIn('artwork_cache.py', (root / 'Dockerfile').read_text())

    def test_persistence_expiration_bounds_and_namespaces(self):
        with tempfile.TemporaryDirectory() as directory:
            path = directory + '/cache.sqlite3'
            cache = ArtworkCache(path, limit=10)
            cache.put('one', b'123456', 'image/jpeg', 60)
            self.assertEqual(ArtworkCache(path).get('one')[0], b'123456')
            cache.put('two', b'abcdef', 'image/jpeg', 60)
            self.assertIsNone(cache.get('one'))
            with patch('artwork_cache.time.time', return_value=9999999999):
                self.assertIsNone(cache.get('two'))
            self.assertNotEqual(namespace('radarr', lambda x: 'a'), namespace('radarr', lambda x: 'b'))

    def test_concurrent_requests_fetch_once_and_errors_are_not_cached(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = ArtworkCache(directory + '/cache.sqlite3')
            loader = Mock(return_value=(b'poster', 'image/jpeg'))
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(lambda _: cache.load('key', loader, 60), range(8)))
            self.assertEqual(len(results), 8)
            loader.assert_called_once()
            cache.forget('key')
            with self.assertRaises(ValueError):
                cache.load('key', Mock(side_effect=ValueError), 60)
            self.assertIsNone(cache.get('key'))
