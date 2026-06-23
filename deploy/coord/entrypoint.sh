#!/bin/sh
set -eu

# ublk is a loadable module in Fly's guest kernel; the volume processes the
# coordinator spawns open /dev/ublk-control, so load it before serving.
modprobe ublk_drv 2>/dev/null || true

# The daemon waits for enrollment itself (and for mint to come up), staying as
# PID 1 so `fly ssh` enrollment works and SIGTERM is clean. Enrol once over
# fly ssh:
#   elide login --subject <operator>
#   elide coord enroll <invite>          # config via ELIDE_COORD_CONFIG
# then 'mint enroll approve <coord-sub>' on the mint app.
exec elide-coordinator serve
