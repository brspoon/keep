# Patched Python 3.14 and zlib runtime; verified fixes require regression evidence.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS package-manager

FROM dhi.io/python:3.14-alpine3.24-dev@sha256:b718c87cdd7bb7dc88d6bbe347f81123b9cf6f2dac6eec6d4828c2cd8262582d AS dependencies
WORKDIR /app
COPY requirements.txt .
RUN python -m venv /venv \
    && /venv/bin/python -m pip install --no-cache-dir -r requirements.txt \
    && /venv/bin/python -m pip check \
    && /venv/bin/python -m pip uninstall --yes pip \
    && python -c "from pathlib import Path; [p.unlink() for p in Path('/venv').rglob('*.pyc')]" \
    && mkdir -p /app/data && chmod 700 /app/data && chown 10001:10001 /app/data
COPY scripts/build_patched_zlib.py /tmp/build_patched_zlib.py
RUN ["python", "/tmp/build_patched_zlib.py"]
COPY scripts/alpine_expat_sources.py /tmp/alpine_expat_sources.py
RUN ["python", "/tmp/alpine_expat_sources.py", "--prepare-packages", "--output", "/opt/expat"]

FROM dhi.io/python:3.14-alpine3.24@sha256:b945ad65f9dcea58d20d119a7a7d650517cb9d27ad26031ac5a6d3ceeaa972f7
USER 0
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/venv/bin:$PATH"
WORKDIR /app
# Installation tools are temporary build inputs, absent from every final layer.
RUN --mount=from=package-manager,source=/sbin/apk,target=/sbin/apk \
    --mount=from=package-manager,source=/usr/lib/libapk.so.3.0.0,target=/usr/lib/libapk.so.3.0.0 \
    --mount=from=dependencies,source=/opt/expat,target=/tmp/expat \
    ["/sbin/apk", "add", "--no-network", "--repositories-file", "/dev/null", "--keys-dir", "/tmp/expat/keys", "--no-cache", "--upgrade", "/tmp/expat/expat-2.9.0-r0.apk", "/tmp/expat/libexpat-2.9.0-r0.apk"]
COPY --from=dependencies /opt/expat/EXPAT_SECURITY.json /app/EXPAT_SECURITY.json
COPY --from=dependencies /venv /venv
# Replace the file behind the runtime's existing libz.so.1 SONAME alias.
COPY --from=dependencies /opt/zlib/lib/libz.so.1.3.2 /usr/lib/libz.so.1.3.2
COPY --from=dependencies /opt/zlib/ZLIB_SECURITY.json /app/ZLIB_SECURITY.json
COPY --from=dependencies /opt/zlib/ZLIB_LICENSE.txt /app/ZLIB_LICENSE.txt
COPY scripts/patch_python_runtime.py scripts/python_security_patches.json /tmp/security-patches/
RUN ["python", "/tmp/security-patches/patch_python_runtime.py"]
RUN ["python", "-c", "import shutil; shutil.rmtree('/tmp/security-patches')"]
COPY --from=dependencies --chown=10001:10001 /app/data /app/data
RUN ["python", "-c", "import os; os.chmod('/app/data', 0o700)"]
RUN ["python", "-c", "import pathlib, shutil, sysconfig; p=pathlib.Path(sysconfig.get_path('stdlib')) / 'ensurepip'; shutil.rmtree(p) if p.exists() else None"]
COPY app.py api_v1.py email_templates.py artwork_cache.py background_jobs.py connection_settings.py connection_monitor.py deployment_transport.py media_services.py service_discovery.py onboarding.py seerr.py title_details.py leaving_forecast.py portable_backup.py VERSION ./
COPY static ./static
COPY templates ./templates
COPY LICENSE ./LICENSE
COPY THIRD_PARTY.md ./THIRD_PARTY.md
COPY docs/PYTHON_LICENSE.txt /app/PYTHON_LICENSE.txt
COPY docs/licenses /app/licenses
USER 10001:10001
EXPOSE 5000
ENTRYPOINT []
CMD ["gunicorn", "--no-control-socket", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--timeout", "60", "app:app"]
