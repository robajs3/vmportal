#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -d postgres <<-EOSQL
    CREATE DATABASE guacamole_db;
    CREATE DATABASE app_db;
    CREATE USER vmportal_app WITH PASSWORD 'nasza20042';
    GRANT ALL PRIVILEGES ON DATABASE app_db TO vmportal_app;
EOSQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -d app_db <<-EOSQL
    GRANT ALL ON SCHEMA public TO vmportal_app;
EOSQL
