# Disposable recovery validation

The native image workflow runs `scripts/portable_container_trial.py` against each
actual packaged candidate. It uses the supported installer and Compose file with
an offline test overlay, unique project and volumes, and synthetic accounts and
service settings. Production containers, configuration and media are outside the
trial. Docker Compose 2.24.4 or later is required for this test overlay.

To run a cross-version trial on a Docker host, first obtain the verified candidate
and previous release image as locally available references. If separately retained
image archives are used, verify their SHA-256 checksums before `docker load`.
Record the Actions run and tested source revision. The current native workflow
does not use Actions candidate-image archives for transport. The trial does not
pull or publish an image:

Set `PREVIOUS_IMAGE` and `CANDIDATE_IMAGE` to those verified local references,
then run:

```sh
python3 scripts/portable_container_trial.py \
  --previous-image "$PREVIOUS_IMAGE" \
  --candidate-image "$CANDIDATE_IMAGE" \
  --evidence recovery-trial.json
```

The image arguments must be locally available tagged or digest references with
version and full source-revision labels. The runner inspects their immutable image
IDs and pins every trial service to those IDs. It records installer idempotence,
fresh unowned setup, paired web/worker health, consistent SQLite backup, restoration
into a new volume, local login and saved-state checks, recreation, and an intentional
failed-upgrade probe followed by restoration of the pre-upgrade snapshot. The probe
adds a dedicated synthetic marker table and exits with code 73. Recovery must remove
that marker and preserve the original state. It does not simulate every migration
failure or prove real Plex authorization.

For an older image, the runner first stops its disposable services and makes only
the seeded trial volume's data directory private (0700) as its existing non-root
owner. This applies the documented migration for volumes created with mode 0755;
it records the original mode and never changes database files recursively. Reports
also bind the exact runner, fixture and Compose source hashes to the trial.

The report records table counts and hashes rather than account rows, service
credentials or full API keys. Candidate and previous image identities remain in
the report. Exact trial containers and volumes are removed after verification;
cleanup failures are reported as failures. Preserve the report outside temporary
trial storage. No broad pruning or volume-removing Compose shutdown is used.

CI trials without `--previous-image` exercise fresh installation and same-image
recovery on both native architectures. A cross-version trial must use the actual
previous and candidate images. Real Plex authorization, network setup, physical
devices, email delivery and an unfamiliar operator following the guide remain
separate acceptance observations.

Keep the original trial reports with the release's verification materials. Matching
source archives have their own [distribution and retention policy](SOURCE_DISTRIBUTION.md);
expiring test logs do not authorize discarding required source materials.
