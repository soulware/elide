#!/usr/bin/env bash
# Deploy the Elide coordinator to Fly.io at a resolved elide release version.
#
#   ./deploy.sh            deploy the latest release
#   ./deploy.sh v0.1.2     deploy a specific tag
#
# Resolves the version to a concrete tag and passes it as the ELIDE_VERSION
# build-arg the Dockerfile requires. Any extra arguments pass through to
# `fly deploy`.
set -euo pipefail

repo="soulware/elide"
cd "$(dirname "$0")"

version=""
case "${1:-}" in
  ""|-*) ;;
  *) version="$1"; shift ;;
esac

if [ -z "$version" ]; then
  version="$(curl -fsIL -o /dev/null -w '%{url_effective}' \
    "https://github.com/${repo}/releases/latest" | sed 's#.*/tag/##')"
  [ -n "$version" ] || { echo "could not resolve latest release of ${repo}" >&2; exit 1; }
fi

echo "deploying elide ${version}"
exec fly deploy --build-arg "ELIDE_VERSION=${version}" "$@"
