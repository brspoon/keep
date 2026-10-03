#!/bin/sh
# Fetch the complete versioned installer before running it. Requires curl and Python 3.9+.
main() (
    set -eu
    umask 077
    command -v curl >/dev/null 2>&1 || { printf '%s\n' 'Keep requires curl.' >&2; exit 1; }
    command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'Keep requires Python 3.9 or newer.' >&2; exit 1; }
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || {
        printf '%s\n' 'Keep requires Python 3.9 or newer.' >&2; exit 1;
    }
    installer_tmp=$(mktemp -d "${TMPDIR:-/tmp}/keep-install.XXXXXXXX")
    trap 'rm -f "$installer_tmp/install_keep.py"; rmdir "$installer_tmp"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # Do not follow redirects to another origin or execute a failed/partial download.
    installer_status=$(curl --fail --silent --show-error --proto '=https' \
        --connect-timeout 15 --max-time 120 --write-out '%{http_code}' \
        --output "$installer_tmp/install_keep.py" \
        'https://raw.githubusercontent.com/brspoon/keep/2.21.2/scripts/install_keep.py')
    [ "$installer_status" = '200' ] || { printf '%s\n' 'Keep installer download returned an unexpected status.' >&2; exit 1; }
    python3 "$installer_tmp/install_keep.py" --start "$@"
)
main "$@"
