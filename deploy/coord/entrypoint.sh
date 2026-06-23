#!/bin/sh
set -eu

# ublk is a loadable module in Fly's guest kernel; the volume processes the
# coordinator spawns open /dev/ublk-control, so load it before serving.
modprobe ublk_drv 2>/dev/null || true

CONFIG=/app/coord.toml
# The last credential `elide coord enroll` writes (the daemon's startup gate
# requires all four). Its presence means enrollment finished — path matches
# data_dir in coord.toml.
ENROLLED=/data/elide_data/credentials/volume-ro/_intermediate

# The coordinator refuses to serve until enrolled. Stay up so the operator can
# `fly ssh` in and enrol; once the credentials land on the volume, hand off to
# the daemon as PID 1 for a clean SIGTERM on deploy/stop.
while [ ! -e "$ENROLLED" ]; do
  echo "elide-coord: not enrolled. fly ssh in and run:"
  echo "    elide login --subject <operator>"
  echo "    elide coord enroll --config $CONFIG <invite>"
  echo "  then 'mint enroll approve <coord-sub>' on the mint app."
  sleep 15
done

exec elide-coordinator serve --config "$CONFIG"
