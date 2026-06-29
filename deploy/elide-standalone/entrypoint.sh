#!/bin/sh
set -eu

# ublk is a loadable module in Fly's guest kernel; the volume processes the
# coordinator spawns open /dev/ublk-control, so load it before serving.
modprobe ublk_drv 2>/dev/null || true

# No enrollment: the coordinator signs S3 with AWS_ACCESS_KEY_ID /
# AWS_SECRET_ACCESS_KEY from the environment and serves immediately. Create
# volumes over fly ssh:
#   elide volume create <name> …
exec elide-coordinator serve
