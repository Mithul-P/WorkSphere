#!/bin/sh
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set=app_password="$APP_DB_PASSWORD" --set=owner_password="$OWNER_DB_PASSWORD" <<'SQL'
CREATE ROLE worksphere_owner LOGIN PASSWORD :'owner_password' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE ROLE worksphere_app LOGIN PASSWORD :'app_password' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE ROLE worksphere_readonly NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER DATABASE worksphere OWNER TO worksphere_owner;
ALTER SCHEMA public OWNER TO worksphere_owner;
ALTER ROLE worksphere_app CONNECTION LIMIT 100;
ALTER ROLE worksphere_owner CONNECTION LIMIT 10;
ALTER ROLE worksphere_app SET statement_timeout='5s';
ALTER ROLE worksphere_app SET idle_in_transaction_session_timeout='10s';
ALTER ROLE worksphere_app SET lock_timeout='3s';
ALTER ROLE worksphere_readonly SET statement_timeout='5s';
ALTER ROLE worksphere_readonly SET default_transaction_read_only=on;
GRANT worksphere_readonly TO worksphere_owner;
REVOKE CREATE,TEMPORARY ON DATABASE worksphere FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL

