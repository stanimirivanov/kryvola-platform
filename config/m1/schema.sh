#!/bin/sh
set -eu
export SQL_PASSWORD="$(cat /run/m1-secrets/pg-temporal)"
for db in temporal temporal_visibility; do
 temporal-sql-tool --plugin postgres12 --ep postgres -u m1_temporal -p 5432 --db "$db" setup-schema -v 0.0
 folder=temporal
 if [ "$db" = temporal_visibility ]; then folder=visibility; fi
 temporal-sql-tool --plugin postgres12 --ep postgres -u m1_temporal -p 5432 --db "$db" update-schema -d "/etc/temporal/schema/postgresql/v12/$folder/versioned"
done
