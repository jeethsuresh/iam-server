#!/bin/sh
set -eu

# DOKS can inherit a billion-file limit. BEAM sizes startup tables from it,
# exhausting small containers before application code runs.
file_limit=$(ulimit -n)
if [ "$file_limit" = unlimited ] || [ "$file_limit" -gt 65536 ]; then
  ulimit -n 65536
fi

exec "$@"
