#!/bin/sh

set -eu

data_dir=/wallet-conformance-test/data

mkdir -p "$data_dir"

if [ "$(id -u)" -ne 0 ]; then
  if ! test -w "$data_dir" || ! test -x "$data_dir"; then
    cat >&2 <<EOF
Unable to write to $data_dir as UID $(id -u).
Create the host directory with write and execute permissions for the user running
the container, or run the container with --user "\$(id -u):\$(id -g)".
EOF
    exit 1
  fi

  exec ./bin/wct "$@"
fi

if ! chown -R node:node "$data_dir"; then
  cat >&2 <<EOF
Unable to make $data_dir writable by the non-root node user.
If this is a host bind mount, make the directory writable before starting the
container, or run it with --user "\$(id -u):\$(id -g)".
EOF
  exit 1
fi

if ! su-exec node test -w "$data_dir" || ! su-exec node test -x "$data_dir"; then
  cat >&2 <<EOF
$data_dir is not writable by the non-root node user.
For a host bind mount, fix its ownership or permissions, or run the container
with --user "\$(id -u):\$(id -g)".
EOF
  exit 1
fi

exec su-exec node ./bin/wct "$@"
