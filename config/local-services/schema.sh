#!/bin/sh
# Adapted from temporalio/samples-server dd5a3b5e88f8a89c044c31bf094ddc5a20d0a778
# compose/scripts/setup-postgres.sh (MIT). Fresh fixture databases only.
set -eu
for db in temporal temporal_visibility; do
  temporal-sql-tool --plugin postgres12 --ep postgres -u temporal_fixture -p 5432 --db "$db" create
  temporal-sql-tool --plugin postgres12 --ep postgres -u temporal_fixture -p 5432 --db "$db" setup-schema -v 0.0
  folder=temporal
  if [ "$db" = temporal_visibility ]; then folder=visibility; fi
  temporal-sql-tool --plugin postgres12 --ep postgres -u temporal_fixture -p 5432 --db "$db" update-schema -d "/etc/temporal/schema/postgresql/v12/$folder/versioned"
done
