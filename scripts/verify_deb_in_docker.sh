#!/bin/bash
set -euo pipefail

echo "========================================================"
echo "      BoundaryX DEB Package Verification in Docker       "
echo "========================================================"

EXPECTED_SHA256="dc4d9f1fca2e2a4c9775abf10c0516bcdf47bb9a21dba814ee95ad63ab05f058"
DEB_URL="https://github.com/yut3ev/BoundaryX/releases/download/v0.1.1/BoundaryX_0.1.0_amd64.deb"
DEB_FILE="/tmp/BoundaryX_0.1.0_amd64.deb"
if [ -d "/workspace" ]; then
    DEB_FILE="/workspace/BoundaryX_0.1.0_amd64.deb"
fi

echo "[1/5] Installing base download tools (curl, ca-certificates)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates python3 > /dev/null

echo "[1/5] Downloading published release DEB..."
if [ ! -f "$DEB_FILE" ]; then
    curl -sSL "$DEB_URL" -o "$DEB_FILE"
fi

echo "[2/5] Verifying SHA-256 checksum..."
ACTUAL_SHA256=$(sha256sum "$DEB_FILE" | awk '{print $1}')
echo "  Expected: $EXPECTED_SHA256"
echo "  Actual:   $ACTUAL_SHA256"

if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    echo "[-] FATAL: SHA-256 checksum mismatch!"
    exit 1
fi
echo "[+] SHA-256 checksum MATCHED!"

echo "[3/5] Installing package with apt-get..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq "$DEB_FILE"

echo "[4/5] Locating installed files..."
which boundaryx-desktop
ls -la /usr/bin/boundaryx-desktop

# Find the installed sidecar engine
ENGINE_BIN=$(find /usr -name "boundaryx-engine" -type f 2>/dev/null | head -n 1)
if [ -z "$ENGINE_BIN" ]; then
    echo "[-] Searching package contents for engine..."
    dpkg -L boundaryx-desktop
    echo "[-] FATAL: boundaryx-engine not found in package!"
    exit 1
fi
echo "[+] Found bundled engine at: $ENGINE_BIN"
chmod +x "$ENGINE_BIN"

echo "[5/5] Testing Engine IPC (Bidirectional Protocol)..."

# Test 1: Ping via stdin/stdout NDJSON
PING_REQ='{"request_id":"test-1","command":"ping","payload":{}}'
PING_RESP=$(echo "$PING_REQ" | "$ENGINE_BIN" --ipc 2>/dev/null | head -n 1)
echo "  Ping request:  $PING_REQ"
echo "  Ping response: $PING_RESP"
if ! echo "$PING_RESP" | grep -q '"pong":true'; then
    echo "[-] Ping failed!"
    exit 1
fi
echo "  [+] Ping test PASSED."

# Test 2: Program Creation, Scope Rule & In-Scope/Out-of-Scope Target Enforcement
# Create python test script to run full multi-turn IPC session
python3 - "$ENGINE_BIN" << 'PYEOF'
import json
import subprocess
import sys

engine_bin = sys.argv[1]
print(f"[*] Starting interactive IPC session with {engine_bin}")

proc = subprocess.Popen(
    [engine_bin, "--ipc"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1
)

def send_recv(req):
    req_line = json.dumps(req) + "\n"
    proc.stdin.write(req_line)
    proc.stdin.flush()
    while True:
        resp_line = proc.stdout.readline()
        if not resp_line:
            raise RuntimeError("Engine terminated unexpectedly")
        resp_line = resp_line.strip()
        if not resp_line:
            continue
        data = json.loads(resp_line)
        if data.get("request_id") == req.get("request_id"):
            return data

# 1. Ping
res = send_recv({"request_id": "p1", "command": "ping", "payload": {}})
assert res.get("success") is True, f"Ping failed: {res}"
assert res.get("data", {}).get("pong") is True, f"Pong false: {res}"
print(f"  [+] Step 1: IPC ping responsive: {res['data']}")

# 2. Create program
res = send_recv({
    "request_id": "p2",
    "command": "programs.create",
    "payload": {
        "name": "Audit Security Program",
        "description": "Bug bounty scope validation test"
    }
})
assert res.get("success") is True, f"programs.create failed: {res}"
program = res["data"]
prog_id = program["id"]
print(f"  [+] Step 2: Program created with ID {prog_id}: {program['name']}")

# 3. Create in-scope rule (*.target.corp)
res = send_recv({
    "request_id": "p3",
    "command": "scope.create_rule",
    "payload": {
        "program_id": prog_id,
        "rule_type": "include",
        "matcher_type": "domain",
        "pattern": "*.target.corp",
        "wildcard": True
    }
})
assert res.get("success") is True, f"scope.create_rule failed: {res}"
print(f"  [+] Step 3: Scope rule '*.target.corp' created (ID: {res['data']['id']}).")

# 4. Check target in-scope (app.target.corp)
res = send_recv({
    "request_id": "p4",
    "command": "scope.evaluate",
    "payload": {
        "program_id": prog_id,
        "target": "https://app.target.corp/api/v1"
    }
})
assert res.get("success") is True, f"scope.evaluate failed: {res}"
assert res["data"]["is_in_scope"] is True, f"Expected is_in_scope True: {res}"
print(f"  [+] Step 4: 'https://app.target.corp/api/v1' successfully verified IN-SCOPE.")

# 5. Check target out-of-scope (https://attacker.org)
res = send_recv({
    "request_id": "p5",
    "command": "scope.evaluate",
    "payload": {
        "program_id": prog_id,
        "target": "https://attacker.org/exfil"
    }
})
assert res.get("success") is True, f"scope.evaluate failed: {res}"
assert res["data"]["is_in_scope"] is False, f"Expected is_in_scope False: {res}"
print(f"  [+] Step 5: 'https://attacker.org/exfil' successfully REJECTED as OUT-OF-SCOPE.")

# 6. Shutdown engine cleanly
proc.stdin.close()
proc.wait(timeout=5)
print(f"  [+] Step 6: Engine process shutdown cleanly with exit code {proc.returncode}.")
PYEOF

echo "========================================================"
echo "    [SUCCESS] ALL VERIFICATION CHECKS PASSED FOR DEB!   "
echo "========================================================"
