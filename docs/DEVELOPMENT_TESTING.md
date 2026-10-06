# Development testing

Use Python 3.14 and [Node.js 24 LTS](https://nodejs.org/en/about/previous-releases). Node.js runs the JavaScript tests and optional branding tools; the application runtime uses Python. From the repository root:

```sh
python3.14 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -B -m unittest discover -s tests
node --test tests/test_*.cjs
```

Run the complete JavaScript glob; the interaction file alone omits Connections,
welcome-dialog, pull-to-refresh and removal-explanation regression coverage.
Tests use temporary SQLite databases, synthetic identities and mocked services.
They do not establish that real Plex authorization, SMTP delivery, installation
or recovery works end to end.

Build development images locally. The active release workflow tests native amd64
and arm64 images, Compose, non-root runtime, durable web/worker startup and security
policy. Local development does not require publishing to the project's registry.
See [release policy](RELEASE_POLICY.md) and [image security](IMAGE_SECURITY.md).

The nine native security probes include zlib delivery verification. The patched
library must replace `/usr/lib/libz.so.1.3.2` behind the existing `libz.so.1`
alias. The probe imports ordinary Python consumers and uses default SONAME
lookup, then checks loaded file identity, SHA-256 and loader candidates, along
with zlib/gzip round trips and `binascii.crc32`. Opening a patched library by
absolute path does not prove that the application uses it.

Original retained scans and passing probes describe the original image and cannot
validate this delivery correction. An isolated amd64 before-and-after trial is
supplementary; native arm64 execution is unavailable in the current local checks.
The corrected candidate still needs both complete native builds, provenance,
security/source checks and fresh Scout/Grype scans before release and exception
review. Existing review deadlines have not been extended. See
[zlib delivery correction](IMAGE_SECURITY.md#zlib-delivery-correction).

For UI checks, use an isolated preview with synthetic credentials and media.
Exercise desktop and narrow mobile layouts, keyboard focus, validation, saved
state, disclosure controls and modal scrolling. A desktop mobile viewport is not
physical-device acceptance. Never mount production SQLite or media in a test lab,
or put production secrets in screenshots. Test SMTP sends no email; actual email
acceptance requires a deliberately chosen test recipient and payload.

Check account roles, owner-only settings and API pages, local-user setup with
email disabled, connection saves and tests, Plex Connect/Reconnect, Keeps,
email links and background-job status. Test with disposable accounts and restore
the original settings afterward. Library deletion requires separately chosen
disposable media; removing Keep protection is a different operation.

## Installation platforms

The shell launcher targets Linux and macOS. The PowerShell launcher targets
native Windows with Docker Desktop running Linux containers, PowerShell 5.1 or
newer, and Python 3.9 or newer. A WSL terminal is not required. Both launchers
use the same Python installer and paired Linux container images.

| Target | Validation scope |
| --- | --- |
| Linux containers, amd64 and arm64 | Each release requires native image builds, packaged tests, security/source checks, and paired web/worker health probes in CI. A real Docker installer trial also checks startup, HTTP setup cookies, reruns and synthetic owner/data preservation on each architecture. |
| Linux/macOS shell installer | Launcher checks and isolated Python installer tests cover configuration, reruns, conflicts, bootstrap output, and simulated Docker failures. The Linux Docker trial exercises real containers; a clean macOS host, another device's LAN access and real Plex authorization remain separate acceptance checks. |
| Windows PowerShell installer | CI requires Windows PowerShell 5.1 syntax validation and five native Windows tests covering private ACLs, unsafe ACL/junction rejection, process locking, argument forwarding and failed-download cleanup. These tests do not establish Windows Docker Desktop or firewall behavior. A full Windows installation, rerun, and phone-access/Plex trial remains a separate acceptance check. |

Record the host OS, shell, Python version, Docker/Compose versions, image digest,
and actual observations for an installation trial. Verify the printed LAN address
from another device, not only from the Docker host. Follow the
[installation](INSTALLATION.md), [upgrade](MIGRATION.md) and
[backup/restore](PORTABLE_BACKUP.md) instructions on a disposable installation.
Record real observations separately from CI results; do not describe a platform
as tested end to end from unit tests alone.

## Contributor and release checks

Every pull request and main push runs the Python and JavaScript suites in the
`contributor-tests` job. Pull requests also check the contributed diff for whitespace
errors. This job has read-only repository permissions and no registry or publishing
credentials. The independent Windows installer check runs for every pull request.

Before dependency installation, contributor checks run the dependency-free image
exception deadline check. It also runs daily and on manual dispatch in the
read-only **Review image-exception deadlines** workflow:

```sh
python3 -B scripts/review_image.py --check-deadlines
python3 -B scripts/review_image.py --check-deadlines --warning-days 14
```

Upcoming deadlines within the notice window and expired exceptions produce
Actions warnings and a step summary. They do not fail this advisory check;
malformed policy does. The check does not build, scan or publish an image. Native
validation and promotion still reject a finding that needs an expired exception,
while a clean scan can pass with unused expired exceptions. See
[image security](IMAGE_SECURITY.md#exception-review-deadlines).

Pull requests from forks and from this repository do not run the native image,
vendor-provenance, vulnerability-scan, source-acquisition, or image privacy gates.
After merging to main, changes requiring native validation run those checks on
both architectures. Allowlisted prose and screenshots can skip native validation
only when the current version is already published; uncertain classification and
unpublished versions require full validation. Do not expose repository secrets
to pull-request code.

The stable `required-checks` result is the main branch's required merge check. It
always evaluates completed prerequisites, including failures and cancellations:
Change classification, Windows and contributor tests must pass. All pull requests
must leave the native jobs skipped. Main pushes must also pass candidate preparation
and both native architecture gates when the classification requires them; otherwise
those jobs must be skipped. Manual release dispatches retain their separate
publication prerequisites; they do not use this merge check.

Use results for the exact source revision being reviewed. For documentation edits,
check diffs, relative links and consistency with the implementation. Files copied
into the image also require the image checks. Runtime changes require the relevant
application and native image checks; see [release policy](RELEASE_POLICY.md).
