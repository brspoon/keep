# Vendor-fixed runtime packages; every native candidate must pass zero-finding gates.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS package-manager

FROM dhi.io/python:3.14-alpine3.24-dev@sha256:b718c87cdd7bb7dc88d6bbe347f81123b9cf6f2dac6eec6d4828c2cd8262582d AS runtime-inputs
USER 0
WORKDIR /app
ENV KEEP_EXPAT_BUILD_IMAGE=dhi.io/python:3.14-alpine3.24-dev@sha256:b718c87cdd7bb7dc88d6bbe347f81123b9cf6f2dac6eec6d4828c2cd8262582d
COPY scripts/alpine_expat_sources.py scripts/alpine_zlib_sources.py scripts/alpine_musl_sources.py scripts/dhi_python_packages.py scripts/dhi_certificate_packages.py scripts/certificate_trust_checks.py scripts/bootstrap_build_pip.py scripts/install_runtime_packages.py scripts/patch_python_runtime.py scripts/python_security_patches.json scripts/build_patched_expat.py scripts/expat_security_patches.json /opt/runtime-build-tools/
COPY scripts/build_patched_expat.py scripts/expat_security_patches.json scripts/alpine_expat_sources.py /opt/scripts/
COPY docs/expat-build.json /opt/docs/expat-build.json
RUN ["python", "-B", "/opt/runtime-build-tools/install_runtime_packages.py", "--prepare"]
RUN --mount=from=package-manager,source=/sbin/apk,target=/sbin/apk \
    --mount=from=package-manager,source=/usr/lib/libapk.so.3.0.0,target=/usr/lib/libapk.so.3.0.0 \
    ["python", "-B", "/opt/runtime-build-tools/install_runtime_packages.py", "--install-build-musl"]
RUN --mount=from=package-manager,source=/sbin/apk,target=/sbin/apk \
    --mount=from=package-manager,source=/usr/lib/libapk.so.3.0.0,target=/usr/lib/libapk.so.3.0.0 \
    ["python", "-B", "/opt/runtime-build-tools/install_runtime_packages.py", "--install-certificates"]

# Preparatory output cannot pass the final library-hash gate or publish an image.
FROM runtime-inputs AS expat-preparation
RUN ["python", "-B", "/opt/scripts/build_patched_expat.py", "--preparation", "--output", "/opt/expat-preparation"]

FROM runtime-inputs AS dependencies
RUN ["python", "-B", "/opt/scripts/build_patched_expat.py", "--output", "/opt/runtime-packages/expat-patched"]
# Keep the original cp314 compiler environment with matching updated libc headers;
# final native gates verify its wheels, including CFFI and Argon2.
COPY requirements.txt .
RUN python -m venv --without-pip /venv \
    && python -B /opt/runtime-build-tools/bootstrap_build_pip.py --python /venv/bin/python \
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
    --mount=from=dependencies,source=/opt/scripts,target=/opt/scripts \
    --mount=from=dependencies,source=/opt/docs,target=/opt/docs \
    ["python", "-B", "/opt/runtime-build-tools/install_runtime_packages.py", "--install"]
COPY --from=dependencies /opt/runtime-packages/expat/EXPAT_SECURITY.json /app/EXPAT_SECURITY.json
COPY --from=dependencies /opt/runtime-packages/expat-patched/EXPAT_PATCHED_SECURITY.json /app/EXPAT_PATCHED_SECURITY.json
COPY docs/expat-build.json /app/EXPAT_BUILD.json
COPY --from=dependencies /opt/runtime-packages/zlib/ZLIB_SECURITY.json /app/ZLIB_SECURITY.json
COPY --from=dependencies /opt/runtime-packages/python/PYTHON_SECURITY.json /app/PYTHON_SECURITY.json
COPY --from=dependencies /opt/runtime-packages/certificates/CA_CERTIFICATES_SECURITY.json /app/CA_CERTIFICATES_SECURITY.json
COPY --from=dependencies /opt/runtime-packages/musl/MUSL_SECURITY.json /app/MUSL_SECURITY.json
COPY --from=dependencies /venv /venv
COPY --from=dependencies --chown=10001:10001 /app/data /app/data
RUN ["python", "-c", "import os; os.chmod('/app/data', 0o700)"]
COPY app.py api_v1.py email_templates.py artwork_cache.py background_jobs.py release_updates.py notifications.py notification_settings.py notifications_app.py notifications_routes.py pushover.py connection_settings.py connection_monitor.py deployment_transport.py media_services.py service_discovery.py onboarding.py seerr.py title_details.py leaving_forecast.py portable_backup.py helper_retirement.py VERSION ./
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
