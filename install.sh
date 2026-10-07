#!/bin/sh
# Fetch the complete versioned installer before running it. Requires curl and Python 3.9+.
main() (
    set -eu
    umask 077
    prerequisite_help() {
        case "$1" in
            curl) keep_package=curl; keep_requirement='Keep requires curl.'; keep_docs='https://curl.se/download.html' ;;
            python3) keep_package=python3; keep_requirement='Keep requires Python 3.9 or newer.'; keep_docs='https://www.python.org/downloads/' ;;
        esac
        printf '%s\n' "$keep_requirement" >&2
        case "$(uname -s 2>/dev/null || printf unknown)" in
            Darwin)
                if command -v brew >/dev/null 2>&1; then
                    printf '%s\n' 'Install with your existing Homebrew:' "brew install $keep_package" >&2
                elif [ "$1" = curl ] && [ -x /usr/bin/curl ]; then
                    printf '%s\n' 'macOS includes curl at /usr/bin/curl. Restore /usr/bin to your PATH before rerunning the command.' >&2
                else
                    printf '%s\n' "Install using the official download: $keep_docs" >&2
                fi
                ;;
            Linux)
                if command -v apt-get >/dev/null 2>&1; then
                    printf '%s\n' 'Install from your distribution packages:' 'sudo apt-get update' "sudo apt-get install $keep_package" >&2
                elif command -v dnf >/dev/null 2>&1; then
                    printf '%s\n' 'Install from your distribution packages:' "sudo dnf install $keep_package" >&2
                else
                    printf '%s\n' "Install using your distribution's package manager. Official guidance: $keep_docs" >&2
                fi
                ;;
            *) printf '%s\n' "Official installation guidance: $keep_docs" >&2 ;;
        esac
        if [ "$1" = python3 ]; then
            printf '%s\n' 'Reopen your terminal and check: python3 --version' \
                'If your distribution still provides Python older than 3.9, use a supported Python installation before continuing.' >&2
        fi
        printf '%s\n' 'Then rerun the Keep installation command. No prerequisites were installed automatically.' >&2
        exit 1
    }
    command -v curl >/dev/null 2>&1 || prerequisite_help curl
    command -v python3 >/dev/null 2>&1 || prerequisite_help python3
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || {
        prerequisite_help python3
    }
    installer_tmp=$(mktemp -d "${TMPDIR:-/tmp}/keep-install.XXXXXXXX")
    trap 'rm -f "$installer_tmp/install_keep.py"; rmdir "$installer_tmp"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # Do not follow redirects to another origin or execute a failed/partial download.
    installer_status=$(curl --fail --silent --show-error --proto '=https' \
        --connect-timeout 15 --max-time 120 --write-out '%{http_code}' \
        --output "$installer_tmp/install_keep.py" \
        'https://raw.githubusercontent.com/brspoon/keep/2.23.3/scripts/install_keep.py')
    [ "$installer_status" = '200' ] || { printf '%s\n' 'Keep installer download returned an unexpected status.' >&2; exit 1; }
    python3 "$installer_tmp/install_keep.py" --start "$@"
)
main "$@"
