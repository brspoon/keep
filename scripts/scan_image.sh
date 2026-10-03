#!/bin/sh
# Run a pinned, checksum-verified scanner against a local image. No registry login.
set -eu
scan_image=${1:-keep-ci}
scan_report=${2:-vulnerabilities.json}
case "$(uname -m)" in
  x86_64) scan_arch=amd64; scan_checksum=1d444c5e7360471815f7158f71935fcecc68a3c417d85c7344f770854300bba2 ;;
  aarch64|arm64) scan_arch=arm64; scan_checksum=32aceeb8ee837244775fcb522372c8b3a47914986385f3148f4ee2c930482a84 ;;
  *) printf '%s\n' 'Unsupported scanner architecture' >&2; exit 1 ;;
esac
scan_tmp=$(mktemp -d)
trap 'rm -rf "$scan_tmp"' EXIT INT TERM
curl --fail --silent --show-error --location \
  --retry 4 --retry-all-errors --retry-delay 2 \
  "https://github.com/anchore/grype/releases/download/v0.118.0/grype_0.118.0_linux_${scan_arch}.tar.gz" \
  --output "$scan_tmp/grype.tar.gz"
printf '%s  %s\n' "$scan_checksum" "$scan_tmp/grype.tar.gz" | sha256sum --check --status
tar -xzf "$scan_tmp/grype.tar.gz" -C "$scan_tmp" grype
# No ignore list, fix-availability filter, or VEX suppression. Retain every finding.
if [ "${3:-}" = '--report-only' ]; then
  GRYPE_CHECK_FOR_APP_UPDATE=false "$scan_tmp/grype" "docker:$scan_image" --output json --file "$scan_report"
else
  GRYPE_CHECK_FOR_APP_UPDATE=false "$scan_tmp/grype" "docker:$scan_image" --fail-on high --output json --file "$scan_report"
fi
