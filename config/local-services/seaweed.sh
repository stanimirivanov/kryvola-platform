#!/bin/sh
set -eu
# The pinned upstream entrypoint drops from root to seaweed (UID 1000).
# Keep the host credential file private; copy it to the owned data volume first.
cp /fixture/s3.json /data/fixture-s3.json
chown 1000:1000 /data/fixture-s3.json
chmod 600 /data/fixture-s3.json
exec /entrypoint.sh "$@"
