# Vendor-fixed runtime packages; every native candidate must pass zero-finding gates.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS package-manager

FROM dhi.io/python:3.14-alpine3.24-dev@sha256:b718c87cdd7bb7dc88d6bbe347f81123b9cf6f2dac6eec6d4828c2cd8262582d AS dependencies
USER 0
WORKDIR /app
COPY scripts/alpine_expat_sources.py scripts/alpine_zlib_sources.py scripts/dhi_python_packages.py scripts/install_runtime_packages.py scripts/patch_python_runtime.py scripts/python_security_patches.json /opt/runtime-build-tools/
RUN ["python", "-B", "/opt/runtime-build-tools/install_runtime_packages.py", "--prepare"]
# Keep the original cp314 build environment; final native gates verify its
# installed wheels against the upgraded runtime, including CFFI and Argon2.
COPY requirements.txt .
RUN python -m venv /venv \
    && /venv/bin/python -m pip install --no-cache-dir -r requirements.txt \
    && /venv/bin/python -m pip check \
    && /venv/bin/python -m pip uninstall --yes pip \
    && python -c "from pathlib import Path; [p.unlink() for p in Path('/venv').rglob('*.pyc')]" \
    && mkdir -p /app/data && chmod 700 /app/data && chown 10001:10001 /app/data

FROM dhi.io/python:3.14-alpine3.24@sha256:b945ad65f9dcea58d20d119a7a7d650517cb9d27ad26031ac5a6d3ceeaa972f7
USER 0
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/venv/bin:$PATH"
WORKDIR /app
# Installation tools and packages are read-only inputs, absent from final layers.
# Install and remove new ensurepip/cache bytes before the layer is captured.
RUN --mount=from=package-manager,source=/sbin/apk,target=/sbin/apk \
    --mount=from=package-manager,source=/usr/lib/libapk.so.3.0.0,target=/usr/lib/libapk.so.3.0.0 \
    --mount=from=dependencies,source=/opt/runtime-packages,target=/opt/runtime-packages \
    --mount=from=dependencies,source=/opt/runtime-build-tools,target=/opt/runtime-build-tools \
    ["python", "-B", "/opt/runtime-build-tools/install_runtime_packages.py", "--install"]
COPY --from=dependencies /opt/runtime-packages/expat/EXPAT_SECURITY.json /app/EXPAT_SECURITY.json
COPY --from=dependencies /opt/runtime-packages/zlib/ZLIB_SECURITY.json /app/ZLIB_SECURITY.json
COPY --from=dependencies /opt/runtime-packages/python/PYTHON_SECURITY.json /app/PYTHON_SECURITY.json
COPY --from=dependencies /venv /venv
COPY --from=dependencies --chown=10001:10001 /app/data /app/data
RUN ["python", "-c", "import os; os.chmod('/app/data', 0o700)"]
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
