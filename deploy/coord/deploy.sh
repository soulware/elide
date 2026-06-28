#!/usr/bin/env bash
# Deploy the Elide coordinator to Fly.io at a resolved elide release version.
#
#   ./deploy.sh            deploy the latest release
#   ./deploy.sh latest     same, stated explicitly
#   ./deploy.sh v0.1.2     deploy a specific tag
#
# Resolves the version to a concrete tag, checks the release assets exist, and
# passes the tag as the ELIDE_VERSION build-arg the Dockerfile requires. Any
# extra arguments pass through to `fly deploy`.
set -euo pipefail

repo="soulware/elide"
assets=(
  elide-x86_64-unknown-linux-gnu
  elide-coordinator-x86_64-unknown-linux-gnu
  elide-import-x86_64-unknown-linux-gnu
)
cd "$(dirname "$0")"

version=""
case "${1:-}" in
  ""|-*) ;;
  latest) shift ;;
  *) version="$1"; shift ;;
esac

if [ -z "$version" ]; then
  version="$(curl -fsIL -o /dev/null -w '%{url_effective}' \
    "https://github.com/${repo}/releases/latest" | sed 's#.*/tag/##')"
  [ -n "$version" ] || { echo "could not resolve latest release of ${repo}" >&2; exit 1; }
fi

for asset in "${assets[@]}"; do
  curl -fsIL -o /dev/null "https://github.com/${repo}/releases/download/${version}/${asset}" \
    || { echo "release ${version} of ${repo} not found (missing ${asset})" >&2; exit 1; }
done

echo "deploying elide ${version}"
exec fly deploy --build-arg "ELIDE_VERSION=${version}" "$@"
