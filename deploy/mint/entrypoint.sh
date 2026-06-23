#!/bin/sh
set -e

# When BRIDGE_AUTH is set, bridge the colocated demo auth UDS onto 6PN TCP 8086
# so an off-Fly coordinator can reach /v1/login + /v1/discharge during
# enrollment. This puts the open demo issuer on the private network — demo-tier,
# opt-in. Unset (default) keeps auth in-container only. socat connects to the
# socket per request, so it tolerates mint creating it just after start.
if [ -n "$BRIDGE_AUTH" ]; then
  socat TCP6-LISTEN:8086,fork,reuseaddr UNIX-CONNECT:/data/mint_data/auth.sock &
fi

exec mint serve
