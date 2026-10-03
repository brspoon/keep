"""Read-only probes run by Keep's existing background worker."""
import json

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


def run_due(store, getter, smtp_probe, logger):
    """Attempt each due service independently; never log credentials or responses."""
    for service in SERVICES:
        try:
            if not store.automatic_due(service, getter):
                continue
            fingerprint = store.connection_fingerprint(service, getter)
            try:
                probe(service, getter, smtp_probe)
                passed = True
            except Exception:
                passed = False
            before, after = store.record_automatic_check(service, fingerprint, passed)
            if after == 2:
                logger.warning('%s automatic connection check failed twice', service.title())
            elif before and not after:
                logger.info('%s automatic connection check recovered', service.title())
        except Exception:
            logger.warning('%s automatic connection check could not be recorded; retrying', service.title())
