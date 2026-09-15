#!/bin/sh
# Verify that the file-access analyzer reports every outcome for both
# backends:
#   opened  (err=0)           - readable file
#   denied  (err=EACCES=13)   - mode 0000 file, opened by an unprivileged uid
#   failed  (err=ENOENT=2)    - path that does not exist
#   failed  (err=ENOTDIR=20)  - regular file used as a path component

set -e

RUNTIMEXRAY_BIN="$1"
FIXTURE_BIN="$2"
BACKEND="$3"

if [ -z "$RUNTIMEXRAY_BIN" ] || [ -z "$FIXTURE_BIN" ] || [ -z "$BACKEND" ]; then
    echo "Usage: $0 <runtimexray> <fixture> <ptrace|ebpf>"
    exit 125
fi

if [ "$BACKEND" = "ebpf" ] && [ "$(id -u)" -ne 0 ]; then
    if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true 2>/dev/null; then
        echo "Skipping eBPF file-access test: root or passwordless sudo required."
        exit 125
    fi
    RUN_PREFIX="sudo -n"
else
    RUN_PREFIX=""
fi

DIR=/tmp/rxray_file_access_test
rm -rf "$DIR"
mkdir -p "$DIR"
chmod 0755 "$DIR"

# opened: world-readable file
: > "$DIR/secret_opened"
chmod 0644 "$DIR/secret_opened"

# denied: mode 0000, unreadable by the dropped uid inside the fixture
: > "$DIR/secret_denied"
chmod 0000 "$DIR/secret_denied"

# failed / ENOENT: not created

# failed / ENOTDIR: regular file used as if it were a directory
: > "$DIR/secret_notdir"
chmod 0644 "$DIR/secret_notdir"

if ! $RUN_PREFIX "$RUNTIMEXRAY_BIN" trace --backend "$BACKEND" \
        --json "$DIR/trace.json" \
        --min-severity High \
        "$FIXTURE_BIN" "$DIR" > "$DIR/trace.log" 2>&1; then
    echo "trace failed"
    $RUN_PREFIX cat "$DIR/trace.log"
    exit 1
fi

# The eBPF path writes trace.json as root; make it readable so the
# python check below (running as the invoking user) can open it.
if [ -n "$RUN_PREFIX" ]; then
    sudo -n chmod 0644 "$DIR/trace.json"
fi

python3 - "$DIR/trace.json" <<'PY'
import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

found = {}
for finding in data.get("findings", []):
    if finding.get("type") != "sensitive_file":
        continue
    d = finding.get("details", {})
    found[(d.get("outcome"), d.get("err"))] = d.get("path", "?")

expected = [
    ("opened", 0),
    ("denied", 13),   # EACCES
    ("failed",  2),   # ENOENT
    ("failed", 20),   # ENOTDIR
]

missing = [e for e in expected if e not in found]
if missing:
    print("missing outcomes:")
    for o, e in missing:
        print("  outcome=%-7s err=%s" % (o, e))
    print("found instead:")
    for k in sorted(found):
        print("  outcome=%-7s err=%-3s path=%s" % (k[0], k[1], found[k]))
    sys.exit(1)

for o, e in expected:
    print("  outcome=%-7s err=%-3s path=%s" % (o, e, found[(o, e)]))
PY

echo "PASS ($BACKEND)"