#!/usr/bin/env python3
"""Fixed Docker-exec stdin/stdout mailbox.

Runtime qualification is a package decision, never browser or environment input.
"""
import os
from pathlib import Path
import sqlite3
import sys

from maintenance_protocol import ProtocolError, canonical
from private_store import StorageError
from maintenance_app import Controller, MaintenanceError, Store, dispatch, fixed_hooks

RUNTIME_QUALIFIED = True
VERBS = ('hello', 'enroll', 'queue', 'claim', 'revalidate', 'drain', 'status', 'complete', 'abort')
MAX_STDIN = 65536


def runtime_qualified():
    return (RUNTIME_QUALIFIED is True and sys.platform == 'linux'
            and Path(__file__).resolve().parent == Path('/app')
            and os.environ.get('KEEP_DB_PATH', '/app/data/keep.sqlite3') == '/app/data/keep.sqlite3'
            and Path('/app/VERSION').is_file() and Path('/app/app.py').is_file())


def main(argv=None, *, controller=None, stdin=None, stdout=None):
    args = list(sys.argv[1:] if argv is None else argv)
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    try:
        if len(args) != 1 or args[0] not in VERBS:
            raise ProtocolError('Mailbox operation is not allowed')
        data = stdin.read(MAX_STDIN + 1)
        if not isinstance(data, bytes) or len(data) > MAX_STDIN:
            raise ProtocolError('Mailbox input exceeded its bound')
        controller = controller or Controller(Store(), fixed_hooks(qualified=runtime_qualified()))
        output = dispatch(controller, args[0], data)
        if not isinstance(output, bytes) or len(output) > MAX_STDIN:
            raise ProtocolError('Mailbox output exceeded its bound')
        stdout.write(output)
        stdout.flush()
        return 0
    except (ProtocolError, StorageError, MaintenanceError, OSError, ValueError, sqlite3.Error):
        # Never serialize exception text, arguments, profile rows or raw input.
        stdout.write(canonical({'error': 'maintenance_unavailable'}))
        stdout.flush()
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
