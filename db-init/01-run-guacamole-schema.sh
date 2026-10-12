#!/bin/bash
# Ładuje schemat Guacamole i ustawia hasło (oraz login) admina Guacamole z .env,
# zamiast domyślnego guacadmin/guacadmin z pliku schematu.
set -e

: "${GUAC_ADMIN_USER:?brak GUAC_ADMIN_USER}"
: "${GUAC_ADMIN_PASSWORD:?brak GUAC_ADMIN_PASSWORD}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -d guacamole_db \
     -f /docker-entrypoint-initdb.d/02-guacamole-schema.sql

# Guacamole: hash = SHA-256(hasło + HEX_WIELKIMI_LITERAMI(sól)), sól = 32 losowe bajty
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -d guacamole_db \
     -v guac_user="$GUAC_ADMIN_USER" -v guac_password="$GUAC_ADMIN_PASSWORD" <<-'EOSQL'
    UPDATE guacamole_entity SET name = :'guac_user'
     WHERE name = 'guacadmin' AND type = 'USER';

    WITH s AS (
        SELECT decode(replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''), 'hex') AS salt
    )
    UPDATE guacamole_user u
       SET password_salt = s.salt,
           password_hash = sha256(convert_to(:'guac_password' || upper(encode(s.salt, 'hex')), 'UTF8')),
           password_date = CURRENT_TIMESTAMP
      FROM s, guacamole_entity e
     WHERE u.entity_id = e.entity_id
       AND e.type = 'USER'
       AND e.name = :'guac_user';
EOSQL
