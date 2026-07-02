#!/usr/bin/env bash
# Deploy the Elide attestation authority (coord B) to Fly.io at a resolved
# elide release version.
#
#   ./deploy.sh            deploy the newest version tag's release
#   ./deploy.sh latest     same, stated explicitly
#   ./deploy.sh v0.1.2     deploy a specific tag
#
# `latest` is the highest v* tag on the remote (hyphenated prerelease tags
# excluded), so a tag whose release is still building fails the asset check
# below instead of silently deploying the previous release.
#
# Resolves the version to a concrete tag, checks the release assets exist, and
# passes the tag as the ELIDE_VERSION build-arg the Dockerfile requires. Any
# extra arguments pass through to `fly deploy`.
set -euo pipefail

repo="soulware/elide"
assets=(
  elide-x86_64-unknown-linux-gnu
  elide-coordinator-x86_64-unknown-linux-gnu
)
cd "$(dirname "$0")"

version=""
case "${1:-}" in
  ""|-*) ;;
  latest) shift ;;
  *) version="$1"; shift ;;
esac

if [ -z "$version" ]; then
  version="$(git ls-remote --tags --refs "https://github.com/${repo}.git" 'v*' \
    | awk -F/ '$NF !~ /-/ {print $NF}' | sort -V | tail -n 1)"
  [ -n "$version" ] || { echo "could not resolve latest tag of ${repo}" >&2; exit 1; }
fi

for asset in "${assets[@]}"; do
  curl -fsIL -o /dev/null "https://github.com/${repo}/releases/download/${version}/${asset}" \
    || { echo "release ${version} of ${repo} not found (missing ${asset})" >&2; exit 1; }
done

echo "deploying elide-attest ${version}"
exec fly deploy --build-arg "ELIDE_VERSION=${version}" "$@"
