#!/bin/bash
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -d guacamole_db -f /docker-entrypoint-initdb.d/02-guacamole-schema.sql
