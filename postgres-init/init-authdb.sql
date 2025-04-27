-- ./postgres-init/init-authdb.sql
-- Creates the database needed by the Go auth service.
-- This script runs automatically only when the PostgreSQL container
-- initializes its data volume for the first time.

CREATE DATABASE authdb;

-- You can add other commands here if needed, for example:
-- CREATE USER authuser WITH PASSWORD 'somepassword';
-- GRANT ALL PRIVILEGES ON DATABASE authdb TO authuser;