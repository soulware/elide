#!/usr/bin/env bash
# One-step quickstart: provision and deploy a standalone Elide coordinator on
# Fly.io. Creates the Fly app (Fly generates the name), creates a Tigris
# bucket targeting it (which sets the AWS_* keypair secrets), writes fly.toml
# from fly.toml.example, and deploys the newest elide release.
#
#   ./launch.sh [region] [org]
#
# Prompts for the region if not given, and for the org when the account has
# several. Pass both when there is no tty to prompt on. Echoes each fly
# command before running it — the same commands docs/quickstart.md documents
# as the manual path.
#
# fly.toml is written as soon as the app exists, so its presence means a
# launch has happened here — and launch fails fast on it, so it never creates
# resources twice. If a step fails, finish with the remaining commands by hand
# (fly.toml has the app and bucket names), or destroy the app and remove
# fly.toml to start over.
set -euo pipefail
cd "$(dirname "$0")"

run() { echo "+ $*" >&2; "$@"; }

command -v fly >/dev/null 2>&1 \
  || { echo "fly CLI not found — install it: https://fly.io/docs/flyctl/install/" >&2; exit 1; }
fly auth whoami >/dev/null 2>&1 \
  || { echo "not logged in to Fly — run: fly auth login" >&2; exit 1; }
if [ -e fly.toml ]; then
  {
    echo "fly.toml already exists — a launch has happened here:"
    sed -n 's/^app = "\(.*\)"/  app:    \1/p; s/^ *DATA_BUCKET = "\(.*\)"/  bucket: \1/p' fly.toml
    echo "redeploy it with ./deploy.sh, or remove fly.toml to launch a new deployment"
  } >&2
  exit 1
fi

region="${1:-}"
if [ -z "$region" ] && [ -t 0 ]; then
  read -rp "Fly region [iad] (https://fly.io/docs/reference/regions/): " region
fi
region="${region:-iad}"

# fly apps create's stdout is captured below, so flyctl cannot prompt for the
# org itself — resolve it here and pass it explicitly.
org="${2:-}"
if [ -z "$org" ]; then
  slugs="$(fly orgs list --json | grep -o '"[^"]*" *:' | sed 's/" *:$//; s/^"//')"
  if [ "$(echo "$slugs" | wc -l)" -eq 1 ]; then
    org="$slugs"
  elif [ -t 0 ]; then
    first="$(echo "$slugs" | head -n 1)"
    echo "Fly orgs:" $slugs
    read -rp "Org [${first}]: " org
    org="${org:-$first}"
  else
    echo "multiple Fly orgs and no tty to prompt on — pass one: ./launch.sh [region] [org]" >&2
    exit 1
  fi
fi

created="$(run fly apps create --generate-name --json -o "$org")"
app="$(printf '%s' "$created" | grep -o '"Name": *"[^"]*"' | head -n 1 | sed 's|.*"\([^"]*\)"$|\1|')"
[ -n "$app" ] || { echo "could not parse the app name out of fly apps create --json:" >&2; printf '%s\n' "$created" >&2; exit 1; }
bucket="${app}-data"

sed -e "s|^app = .*|app = \"${app}\"|" \
    -e "s|^primary_region = .*|primary_region = \"${region}\"|" \
    -e "s|DATA_BUCKET = .*|DATA_BUCKET = \"${bucket}\"|" \
    fly.toml.example > fly.toml
echo "wrote fly.toml: app ${app}, region ${region}, bucket ${bucket}"

run fly storage create -a "$app" -n "$bucket"
run fly deploy

cat <<EOF

Deployed: app ${app}, bucket ${bucket}.

Create a volume and put a filesystem on it:

  fly ssh console
  elide volume create --size 1G vol1
  elide volume list
  mkfs.ext4 /dev/ublkb0
  mkdir -p /mnt/vol1 && mount -o discard /dev/ublkb0 /mnt/vol1
EOF
