"""Read-only probes run by Keep's existing background worker."""
import json
import sqlite3

import background_jobs
import leaving_forecast
import media_services
from service_discovery import discover_collections, test_plex


SERVICES = ('plex', 'maintainerr', 'radarr', 'sonarr', 'tautulli', 'email')


def probe(service, getter, smtp_probe):
    if service == 'plex':
        test_plex(getter('PLEX_SERVER_URL'), getter('PLEX_ADMIN_TOKEN'),
                  getter('PLEX_MACHINE_IDENTIFIER'))
    elif service == 'maintainerr':
        available = discover_collections(getter('MAINTAINERR_URL'))
        selected = json.loads(getter('KEEP_COLLECTIONS') or '{}')
        if not isinstance(selected, dict) or any(int(cid) not in available for cid in selected):
            raise ValueError('Selected Maintainerr collection is missing')
    elif service in ('radarr', 'sonarr'):
        media_services.test_connection(service, getter)
    elif service == 'tautulli':
        leaving_forecast.tautulli_thresholds(getter)
    elif service == 'email':
        smtp_probe(getter)
    else:
        raise ValueError('Unsupported automatic connection check')


def run_due(store, getter, smtp_probe, logger, *, jobs=None, force=False):
    """Attempt each due service independently; never log credentials or responses."""
    completed = True
    for service in SERVICES:
        try:
            job_id = 'probe-' + service
            fingerprint = store.connection_fingerprint(service, getter)
            first_request = jobs and jobs.requested(job_id, first_attempt=True, scope=fingerprint)
            if not store.configured(service, getter):
                continue
            if not (force or first_request or store.automatic_due(service, getter)):
                continue
            def check():
                try:
                    probe(service, getter, smtp_probe)
                    passed = True
                except Exception:
                    passed = False
                try:
                    before, after = store.record_automatic_check(service, fingerprint, passed)
                except sqlite3.Error:
                    raise background_jobs.RetryUnstarted('Connection check persistence is unavailable') from None
                if after == 2:
                    logger.warning('%s automatic connection check failed twice', service.title())
                elif before and not after:
                    logger.info('%s automatic connection check recovered', service.title())
                return passed
            if jobs is None:
                passed = check()
            else:
                passed = jobs.run(job_id, check, interval=store.automatic_interval(service), scope=fingerprint,
                         result_fn=lambda passed: ('success', 'Completed') if passed
                             else ('failed', 'Connection unavailable'))
            completed = completed and passed
        except Exception:
            completed = False
            logger.warning('%s automatic connection check could not be recorded; retrying', service.title())
    states = store.automatic_states(getter)
    return completed and all(not store.configured(service, getter) or states[service]['kind'] == 'success'
                             for service in SERVICES)
