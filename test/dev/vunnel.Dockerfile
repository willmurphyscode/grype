# syntax=docker/dockerfile:1
#
# Dev image for vunnel. Mirrors the way vunnel itself is developed:
#
#   - install with uv (against vunnel's committed uv.lock — same toolchain
#     the vunnel Taskfile/Makefile use)
#   - pre-install the binny-managed toolchain (binny, task, and everything
#     else in vunnel/.binny.yaml) so vunnel's Makefile (which delegates to
#     its Taskfile, which depends on .tool/binny + .tool/task) works
#     unchanged inside the container — without any runtime network
#
# Developers only need docker on the host. The first invocation of
# `make <target>` against a bind-mounted vunnel checkout works on a clean
# laptop with no uv, no Python, no go-task, and no host-installed binny.
#
# Usage:
#   docker build -f test/dev/vunnel.Dockerfile -t grype-dev/vunnel:local $VUNNEL_PATH
#   # default entrypoint runs `vunnel` — used by `grype db-builder pull`:
#   docker run --rm -v $PWD/data:/data grype-dev/vunnel:local run <provider>
#   # vunnel's own dev targets (must mask /src/.tool so the host's
#   # arch-specific binaries don't shadow the linux ones baked here):
#   docker run --rm \
#     -v $VUNNEL_PATH:/src -v /src/.tool \
#     -w /src \
#     --entrypoint with-tools \
#     grype-dev/vunnel:local make unit
#
# Build context note: this Dockerfile expects to be built with $VUNNEL_PATH
# as the context and -f pointing at this file. A sibling
# vunnel.Dockerfile.dockerignore overrides vunnel's repo-local .dockerignore
# (which is tuned for the release image and excludes everything except
# /dist).
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# git: required by some providers (ubuntu) and by uv-dynamic-versioning at install time.
# ca-certificates: TLS for providers that hit HTTPS endpoints.
# curl: used to install binny at image build time.
# make: lets us invoke vunnel's Makefile (which delegates to its Taskfile).
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates curl make \
 && rm -rf /var/lib/apt/lists/*

# Prevent "dubious ownership" errors when providers inspect repos owned by a
# different uid/gid (e.g. host bind mounts).
RUN git config --system safe.directory '*'

# Install uv — vunnel uses uv for build/install/run/tests, so the dev image
# uses the same toolchain rather than a pip shim.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# Project venv lives outside /src so it survives bind-mounting source at run time.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv
# Use the system Python; don't try to download one.
ENV UV_PYTHON_DOWNLOADS=never
# uv-dynamic-versioning normally infers the package version from git tags; a
# bind-mounted or shallow source tree may lack tags, so bypass with a synthetic
# dev version.
ENV UV_DYNAMIC_VERSIONING_BYPASS=0.0.0.dev0

WORKDIR /src
COPY . /src

# Install vunnel + locked deps. --frozen requires uv.lock, which vunnel commits.
RUN uv sync --frozen

# Pre-install the .binny.yaml toolchain (binny, task, chronicle, crane, glow,
# grype, grype-db, oras) so `task tools` (the dependency of every other vunnel
# task) is a no-op at runtime. The toolchain is moved to /opt/vunnel-tool so
# the with-tools entrypoint can seed a fresh /src/.tool volume from it
# without colliding with whatever the host has in its own .tool/ (which is
# usually a different arch).
RUN curl -sSfL https://raw.githubusercontent.com/anchore/binny/main/install.sh | sh -s -- -b /src/.tool \
 && /src/.tool/binny install -v \
 && mv /src/.tool /opt/vunnel-tool

# Entrypoint wrapper: when /src/.tool is empty (callers pass `-v /src/.tool`
# to mask the host's .tool/ with an anonymous volume), seed it from
# /opt/vunnel-tool and exec the user command.
RUN { \
      printf '%s\n' '#!/bin/sh'; \
      printf '%s\n' 'set -eu'; \
      printf '%s\n' 'if [ -d /src/.tool ] && [ -z "$(ls -A /src/.tool 2>/dev/null)" ]; then'; \
      printf '%s\n' '  cp -a /opt/vunnel-tool/. /src/.tool/'; \
      printf '%s\n' 'fi'; \
      printf '%s\n' 'exec "$@"'; \
    } > /usr/local/bin/with-tools \
 && chmod +x /usr/local/bin/with-tools

# Make installed scripts (vunnel, pytest, ruff, mypy, ...) available without
# explicit `uv run`, so vunnel's Taskfile commands work inside the container.
ENV PATH="/opt/venv/bin:${PATH}"

# Default entrypoint runs `vunnel` (used by `grype db-builder pull`). Dev
# workflows that need .tool/ seeded should set --entrypoint with-tools.
ENTRYPOINT ["vunnel"]
