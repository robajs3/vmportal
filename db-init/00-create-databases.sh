#!/bin/bash
# Uruchamiane tylko przy pierwszym starcie kontenera (pusty katalog pgdata).
# Wszystkie wartości pochodzą ze zmiennych środowiskowych (docker-compose.yml <- .env).
set -e

: "${APP_DB_USER:?brak APP_DB_USER}"
: "${APP_DB_PASSWORD:?brak APP_DB_PASSWORD}"

# psql -v + :'zmienna' / :"zmienna" => poprawne cytowanie hasła i nazwy roli
# (hasło może zawierać apostrofy i inne znaki specjalne)
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -d postgres \
     -v app_user="$APP_DB_USER" -v app_password="$APP_DB_PASSWORD" <<-'EOSQL'
    CREATE DATABASE guacamole_db;
    CREATE DATABASE app_db;
    CREATE USER :"app_user" WITH PASSWORD :'app_password';
    GRANT ALL PRIVILEGES ON DATABASE app_db TO :"app_user";
EOSQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -d app_db \
     -v app_user="$APP_DB_USER" <<-'EOSQL'
    GRANT ALL ON SCHEMA public TO :"app_user";
EOSQL
