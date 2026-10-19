-- Run as the bootstrap database administrator against worksphere, never from the API.
-- Roles are created by scripts/init-db.sh (or the temporary local runner).
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='worksphere_readonly') THEN CREATE ROLE worksphere_readonly NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE; END IF; END $$;
ALTER ROLE worksphere_owner NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE CONNECTION LIMIT 10;
ALTER ROLE worksphere_app NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE CONNECTION LIMIT 100;
ALTER ROLE worksphere_readonly NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE worksphere_app SET statement_timeout='5s';
ALTER ROLE worksphere_app SET idle_in_transaction_session_timeout='10s';
ALTER ROLE worksphere_app SET lock_timeout='3s';
ALTER ROLE worksphere_readonly SET statement_timeout='5s';
ALTER ROLE worksphere_readonly SET default_transaction_read_only=on;
GRANT worksphere_readonly TO worksphere_owner;
REVOKE CREATE,TEMPORARY ON DATABASE worksphere FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
-- Table grants and column-safe security_invoker views are managed transactionally
-- by migrations 001-006. The readonly role intentionally has no login/password.
-- Production postgresql.conf: password_encryption='scram-sha-256', ssl=on,
-- log_connections=on, log_disconnections=on, log_parameter_max_length_on_error=0.
-- Use a narrow hostssl pg_hba.conf rule for the API host; no public database port.
