#!/usr/bin/env bash
set -euo pipefail
root=$(mktemp -d "${TMPDIR:-/tmp}/revhub-update-test.XXXXXX")
trap 'rm -rf "$root"' EXIT
repo=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$root/etc/revhub" "$root/usr/local/bin" "$root/systemd"
printf 'original-state\n' > "$root/etc/revhub/state.json"
printf 'credentials\n' > "$root/etc/revhub/credentials.json"
printf 'unit\n' > "$root/systemd/revhub.service"
printf '#!/bin/sh\necho old\n' > "$root/usr/local/bin/revhub"
printf '#!/bin/sh\necho new\n' > "$root/new"
chmod +x "$root/usr/local/bin/revhub" "$root/new"
printf '1\n' | PUB_IP=127.0.0.1 REVHUB_TEST_ROOT="$root" REVHUB_LOCAL_BIN="$root/new" bash "$repo/install.sh" > "$root/log" 2>&1
[ "$("$root/usr/local/bin/revhub" version)" = new ]
[ "$(cat "$root/etc/revhub/state.json")" = original-state ]
[ "$(cat "$root/etc/revhub/credentials.json")" = credentials ]
[ "$(cat "$root/systemd/revhub.service")" = unit ]
compgen -G "$root/etc/revhub/update-backup-*/revhub" >/dev/null
printf 'update preserved settings and saved old binary\n'
mkdir -p "$root/fakebin"
printf '#!/bin/sh\ncase "$1" in restart) [ "$("$REVHUB_TEST_ROOT/usr/local/bin/revhub" version)" = old ];; *) exit 0;; esac\n' > "$root/fakebin/systemctl"
chmod +x "$root/fakebin/systemctl"
printf '#!/bin/sh\necho old\n' > "$root/usr/local/bin/revhub"
if printf '1\n' | PATH="$root/fakebin:$PATH" PUB_IP=127.0.0.1 REVHUB_TEST_ROOT="$root" REVHUB_TEST_SYSTEMCTL=1 REVHUB_LOCAL_BIN="$root/new" bash "$repo/install.sh" > "$root/rollback.log" 2>&1; then
  printf 'update should fail when restart fails\n' >&2; exit 1
fi
[ "$("$root/usr/local/bin/revhub" version)" = old ]
[ "$(cat "$root/etc/revhub/state.json")" = original-state ]
grep -q 'старый бинарь восстановлен' "$root/rollback.log"
printf 'failed restart restored the old binary\n'
