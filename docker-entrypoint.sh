#!/bin/sh
set -e

PG_HOST="${POSTGRES_HOST:-postgres}"
PG_USER="${POSTGRES_USER:-postgres}"

echo "Waiting for PostgreSQL at ${PG_HOST}..."
until pg_isready -h "$PG_HOST" -U "$PG_USER" -q; do
  sleep 1
done

echo "Running migrations..."
mix ecto.create --quiet 2>/dev/null || true
mix ecto.migrate --quiet

echo "Loading seeds..."
mix run apps/lakehouse_iam/priv/repo/seeds.exs

echo "Starting Phoenix..."
exec "$@"
