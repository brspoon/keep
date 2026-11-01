"""Offline checks for the compiled getaddrinfo boundary, not a Python wrapper."""
import argparse
import importlib.util
import json
import sys


def check_socket(module):
    events = []
    def audit(event, args):
        if event == 'socket.getaddrinfo':
            events.append(args)
    sys.addaudithook(audit)
    hosts = ['local\0host', b'local\0host', 'localhost\0', b'localhost\0',
             '\0localhost', b'\0localhost', '\0', b'\0', 'b\u00fccher\0.example']
    ports = ['8\0000', b'8\0000', 'http\0', b'http\0', '\0', b'\0']
    flags = module.AI_NUMERICHOST | module.AI_NUMERICSERV
    rejected = 0
    for name, values in [('host', hosts), ('port', ports)]:
        for value in values:
            count = len(events)
            args = (value, 80) if name == 'host' else ('127.0.0.1', value)
            try:
                module.getaddrinfo(*args, module.AF_INET, module.SOCK_STREAM, 0, flags)
            except ValueError as error:
                if name not in str(error):
                    raise AssertionError('Wrong argument error') from error
            else:
                raise AssertionError('Compiled resolver accepted null-containing ' + name)
            if len(events) != count:
                raise AssertionError('Resolver audit reached before rejecting null input')
            rejected += 1
    controls = 0
    for host in ['127.0.0.1', b'127.0.0.1']:
        for port in [80, '80', b'80', None]:
            rows = module.getaddrinfo(host, port, module.AF_INET,
                                     module.SOCK_STREAM, 0, flags)
            expected = 0 if port is None else 80
            if not rows or any(row[4] != ('127.0.0.1', expected) for row in rows):
                raise AssertionError('Numeric resolver compatibility differs')
            controls += 1
    return {'schema': 'keep-socket-probes-v1', 'null_cases_rejected': rejected,
            'numeric_controls_passed': controls, 'resolver_audit_after_validation': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--extension')
    args = parser.parse_args()
    if args.extension:
        spec = importlib.util.spec_from_file_location('_socket', args.extension)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        sys.modules['_socket'] = module
    else:
        import _socket as module
    direct = check_socket(module)
    import socket
    public = check_socket(socket)
    print(json.dumps({'direct': direct, 'public': public}, sort_keys=True))
