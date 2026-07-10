#!/bin/sh
set -eu

# ublk is a loadable module in Fly's guest kernel; the volume processes the
# coordinator spawns open /dev/ublk-control, so load it before serving.
modprobe ublk_drv 2>/dev/null || true

# No enrollment: the coordinator signs S3 with AWS_ACCESS_KEY_ID /
# AWS_SECRET_ACCESS_KEY from the environment and serves immediately. Create
# volumes over fly ssh:
#   elide volume create <name> …
#
# Peer fetch between machines rides on the invocation, not coord.toml:
# machine identity exists only at runtime, and one image serves every
# machine. Bind the machine's own 6PN address (reachable only over the
# private network) and advertise its per-machine DNS name — peers dial the
# host as a URL host, where a raw fdaa: address literal would be malformed.
exec elide-coordinator serve \
  --peer-fetch-listen "[${FLY_PRIVATE_IP}]:8443" \
  --peer-fetch-host "${FLY_MACHINE_ID}.vm.${FLY_APP_NAME}.internal"
