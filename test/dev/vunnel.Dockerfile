# syntax=docker/dockerfile:1
#
# Dev image for vunnel. Unlike the release vunnel/Dockerfile (which expects a
# prebuilt wheel), this image installs vunnel from a bind-mounted source
# checkout using standard pip. Developers only need `docker` on the host — no
# uv, hatchling, or Python toolchain required.
#
# Usage:
#   docker build -f test/dev/vunnel.Dockerfile -t grype-dev/vunnel:local $VUNNEL_PATH
#   docker run --rm -v $PWD/data:/data grype-dev/vunnel:local run <provider>
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# - git: needed by some vunnel providers (e.g. ubuntu) and by
#   uv-dynamic-versioning during `pip install .`
# - ca-certificates: TLS for providers that hit HTTPS endpoints
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Prevent "dubious ownership" errors when providers inspect repos whose
# ownership differs from the container user.
RUN git config --system safe.directory '*'

# uv-dynamic-versioning infers the package version from git tags during the
# PEP 517 build. A bind-mounted or shallow source tree may lack tags, so this
# bypass forces a synthetic dev version. See
# https://github.com/ninoseki/uv-dynamic-versioning#environment-variables
ENV UV_DYNAMIC_VERSIONING_BYPASS=0.0.0.dev0

WORKDIR /src
COPY . /src

RUN pip install --no-cache-dir /src

ENTRYPOINT ["vunnel"]
