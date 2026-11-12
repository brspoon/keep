"""Exercise the native FIPS property boundary in isolated, offline processes.

The default provider is deliberately restricted by fips=yes; no FIPS module or
certification is claimed. Each process starts with fresh digest caches.
"""
import argparse
import json
import subprocess
import sys


def expected_report():
    return {'schema': 'keep-hashlib-probes-v1', 'fips_cases': 12,
            'ordinary_controls': True, 'fresh_processes': True}


CHILD = r'''
import ctypes, importlib.util, json, sys
extension, api, secure, order = sys.argv[1:]
if extension:
    spec = importlib.util.spec_from_file_location('_hashlib', extension)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.modules['_hashlib'] = module
import _hashlib
if api == 'public':
    import hashlib
crypto = ctypes.CDLL('/usr/lib/libcrypto.so.3')
crypto.OSSL_PROVIDER_load.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
crypto.OSSL_PROVIDER_load.restype = ctypes.c_void_p
assert crypto.OSSL_PROVIDER_load(None, b'default')
crypto.EVP_default_properties_enable_fips.argtypes = [ctypes.c_void_p, ctypes.c_int]
crypto.EVP_default_properties_enable_fips.restype = ctypes.c_int
assert crypto.EVP_default_properties_enable_fips(None, 1) == 1
assert _hashlib.get_fips_mode() == 1
crypto.EVP_MD_fetch.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
crypto.EVP_MD_fetch.restype = ctypes.c_void_p
crypto.EVP_MD_free.argtypes = [ctypes.c_void_p]
for properties, available in ((None, False), (b'-fips', True), (b'fips=no', True)):
    md = crypto.EVP_MD_fetch(None, b'MD5', properties)
    assert bool(md) is available, ('Unmet native fetch precondition', properties, bool(md))
    if md: crypto.EVP_MD_free(md)
crypto.ERR_clear_error()
def digest(flag):
    if api == 'constructor': return _hashlib.openssl_md5(b'keep', usedforsecurity=flag)
    if api == 'generic': return _hashlib.new('md5', b'keep', usedforsecurity=flag)
    if api == 'alias': return _hashlib.new('MD5', b'keep', usedforsecurity=flag)
    if api == 'public':
        assert hashlib.md5 is _hashlib.openssl_md5
        return hashlib.md5(b'keep', usedforsecurity=flag)
    raise AssertionError('Unknown probe')
def allowed(flag):
    try: digest(flag).digest()
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return False
    return True
try:
    if order != 'fresh':
        warm = order == 'secure-first'
        allowed(warm)
    result = allowed(secure == 'true')
finally:
    assert crypto.EVP_default_properties_enable_fips(None, 0) == 1
    assert _hashlib.get_fips_mode() == 0
print(json.dumps(result))
'''


CONTROL = r'''
import importlib.util, sys
if sys.argv[1]:
    spec = importlib.util.spec_from_file_location('_hashlib', sys.argv[1])
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    sys.modules['_hashlib'] = module
import hashlib, hmac, _hashlib
for flag in (True, False):
    assert hashlib.sha256(b'abc', usedforsecurity=flag).hexdigest() == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    assert hashlib.new('sha256', b'abc', usedforsecurity=flag).digest() == hashlib.sha256(b'abc').digest()
    assert _hashlib.new('SHA256', b'abc', usedforsecurity=flag).digest() == hashlib.sha256(b'abc').digest()
    assert hashlib.md5(b'abc', usedforsecurity=flag).hexdigest() == '900150983cd24fb0d6963f7d28e17f72'
assert hmac.digest(b'key', b'data', 'sha256').hex() == '5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0'
assert hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 1).hex() == '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b'
'''


def check_hashlib(extension='', *, diagnose=False):
    # Native generic and named calls share the native property selector. The
    # public constructor must remain the OpenSSL constructor, not a wrapper.
    cases = [(api, flag, 'fresh') for api in ('constructor', 'generic', 'alias', 'public')
             for flag in (True, False)]
    cases += [('constructor', flag, order) for order in ('secure-first', 'insecure-first')
              for flag in (True, False)]
    observed = []
    for api, flag, order in cases:
        body = subprocess.check_output([sys.executable, '-I', '-S', '-B', '-c', CHILD,
            str(extension), api, str(flag).lower(), order], timeout=15)
        result = json.loads(body)
        expected = not flag
        observed.append({'api': api, 'secure': flag, 'order': order, 'allowed': result})
        if not diagnose and result is not expected:
            raise AssertionError(f'Wrong FIPS property behavior: {api}, secure={flag}, {order}')
    if diagnose:
        import hashlib, _hashlib, platform
        from pathlib import Path
        path = Path(_hashlib.__file__).resolve(strict=True)
        return {'architecture': platform.machine(), 'python': platform.python_version(),
                'extension': {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()},
                'cases': observed}
    subprocess.run([sys.executable, '-I', '-S', '-B', '-c', CONTROL, str(extension)],
                   check=True, timeout=15)
    return expected_report()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--extension', default='')
    parser.add_argument('--diagnose', action='store_true')
    args = parser.parse_args()
    print(json.dumps(check_hashlib(args.extension, diagnose=args.diagnose), sort_keys=True))
