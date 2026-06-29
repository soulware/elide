#!/bin/sh
set -eu

# The discharge authority waits for enrollment itself (and for mint to come
# up), staying as PID 1 so `fly ssh` enrollment works and SIGTERM is clean.
# Enrol once over fly ssh:
#   elide login --subject <operator>
#   elide coord enroll --attestation <invite>   # config via ELIDE_COORD_CONFIG
# then 'mint enroll approve <coord-sub>' on the mint app.
exec elide-coordinator attest
