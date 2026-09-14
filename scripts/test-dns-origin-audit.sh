#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# test-dns-origin-audit.sh — prove the detector still detects.
#
# WHY THIS EXISTS
# ---------------
# The fault this estate spent six months chasing was not a broken detector. It
# was a detector nobody could run. `dns-origin-audit.sh` needs a Cloudflare
# credential, so it was never executed end to end, and it shipped with two
# defects that a single run would have caught:
#
#   1. An unreadable SSL/TLS mode was printed with `echo`, not `report`. The
#      audit therefore exited CLEAN while every zone could have been sitting on
#      'Full' — the mode that let Cloudflare trust a stranger's certificate and
#      proxy their redirect to Joshua's visitors. The documented token scope
#      could not read that setting at all, so this would have been the permanent
#      state, reported as success, forever.
#   2. CNAME/MX/NS targets were resolved with `dig +short | tail -1`, keeping one
#      IPv4 answer and discarding the rest plus every AAAA. A target pointing at
#      both a live origin and the dead box passed or failed on answer ORDER.
#
# Both are regression-tested below. An unverifiable detector is how the fault it
# looks for survived six months, so this runs in CI ahead of the real audit and
# needs NO credential and NO network: the Cloudflare API is a local mock and
# `dig` is a stub on PATH.
#
# USAGE
#   ./scripts/test-dns-origin-audit.sh
#
# EXIT CODES
#   0  every control behaved as expected
#   1  at least one control failed — the detector is not trustworthy
#   2  preflight error (missing python3/jq/curl)

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT="$HERE/dns-origin-audit.sh"
WORK="$(mktemp -d)"
export WORK
MOCK_PID=""

cleanup() {
  [[ -n "$MOCK_PID" ]] && kill "$MOCK_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

for bin in python3 jq curl; do
  command -v "$bin" >/dev/null 2>&1 || { echo "error: $bin not found" >&2; exit 2; }
done
[[ -x "$AUDIT" ]] || { echo "error: $AUDIT not executable" >&2; exit 2; }

PASS=0
FAIL=0

# ---- the mock Cloudflare API -------------------------------------------
# One zone. What it answers for settings/ssl and dns_records is driven by files
# in $WORK, so a single server serves every fixture below.
cat > "$WORK/mock.py" <<'PY'
import json, os, re, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
WORK = os.environ["WORK"]
ZID = "z1"

def fixture(name, default):
    p = os.path.join(WORK, name)
    if not os.path.exists(p):
        return default
    with open(p) as f:
        return f.read().strip()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        p = self.path
        if p.startswith("/zones?"):
            body = {"result": [{"id": ZID, "name": "jewell.nexus"}],
                    "result_info": {"total_pages": 1}}
        elif re.match(r"^/zones/" + ZID + r"/settings/ssl$", p):
            mode = fixture("ssl_mode", "strict")
            # "DENY" reproduces a token lacking Zone Settings:Read — the exact
            # condition the audit used to treat as a pass.
            if mode == "DENY":
                self.send_response(403)
                self.end_headers()
                return
            body = {"result": {"value": mode}}
        elif p.startswith("/zones/" + ZID + "/dns_records"):
            recs = json.loads(fixture("records", "[]"))
            body = {"result": recs, "result_info": {"total_pages": 1}}
        else:
            self.send_response(404)
            self.end_headers()
            return
        b = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

srv = HTTPServer(("127.0.0.1", 0), H)
with open(os.path.join(WORK, "port"), "w") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()
PY

python3 "$WORK/mock.py" &
MOCK_PID=$!

# Wait for the port file rather than sleeping a guessed interval.
for _ in $(seq 1 100); do
  [[ -s "$WORK/port" ]] && break
  sleep 0.1
done
[[ -s "$WORK/port" ]] || { echo "error: mock API did not start" >&2; exit 2; }
PORT="$(cat "$WORK/port")"
export CF_API="http://127.0.0.1:$PORT"

# Confirm the mock is actually serving before trusting any result below. A
# connection-refused reply looks exactly like a clean audit to `|| echo unknown`.
curl -fsS --max-time 5 "$CF_API/zones?per_page=50&page=1" >/dev/null 2>&1 \
  || { echo "error: mock API not answering on $CF_API" >&2; exit 2; }

# ---- the dig stub ------------------------------------------------------
# Answers from $WORK/dig_a and $WORK/dig_aaaa so the CNAME-target controls need
# no resolver. ORDER MATTERS and is the point of control 8.
mkdir -p "$WORK/bin"
cat > "$WORK/bin/dig" <<'DIG'
#!/usr/bin/env bash
for arg in "$@"; do
  case "$arg" in
    A)    cat "$WORK/dig_a" 2>/dev/null; exit 0 ;;
    AAAA) cat "$WORK/dig_aaaa" 2>/dev/null; exit 0 ;;
  esac
done
exit 0
DIG
chmod +x "$WORK/bin/dig"

# ---- allow-list fixture -----------------------------------------------
# Deliberately NOT the repo's own file: this must test the logic, not today's
# estate inventory, or the controls change meaning whenever the estate does.
cat > "$WORK/allowed-origins.txt" <<'ALLOW'
deny 65.181.113.13
suffix github.io
ALLOW
export ALLOWLIST="$WORK/allowed-origins.txt"

# ---- harness ----------------------------------------------------------
# want_rc: expected exit code. Then, optionally:
#   +TEXT  output MUST contain TEXT
#   -TEXT  output MUST NOT contain TEXT
# Extra `env` arguments for one check (e.g. -u to unset a variable). Reset by
# check() itself, so it can never leak into the following control.
CHECK_ENV=()

check() {
  local name="$1" want_rc="$2"; shift 2
  local out rc ok=1 spec
  out="$(PATH="$WORK/bin:$PATH" env ${CHECK_ENV[@]+"${CHECK_ENV[@]}"} "$AUDIT" 2>&1)"
  rc=$?
  CHECK_ENV=()
  if [[ "$rc" -ne "$want_rc" ]]; then
    ok=0
    printf 'FAIL %s\n     expected exit %s, got %s\n' "$name" "$want_rc" "$rc"
  fi
  for spec in "$@"; do
    case "$spec" in
      +*) if ! grep -qF -- "${spec#+}" <<<"$out"; then
            ok=0; printf 'FAIL %s\n     output missing: %s\n' "$name" "${spec#+}"
          fi ;;
      -*) if grep -qF -- "${spec#-}" <<<"$out"; then
            ok=0; printf 'FAIL %s\n     output must NOT contain: %s\n' "$name" "${spec#-}"
          fi ;;
    esac
  done
  if [[ "$ok" -eq 1 ]]; then
    PASS=$((PASS + 1)); printf 'ok   %s\n' "$name"
  else
    FAIL=$((FAIL + 1)); printf '     --- output ---\n%s\n     --------------\n' "$out"
  fi
}

echo "== dns-origin-audit.sh self-test =="
echo "mock API: $CF_API"
echo

export CLOUDFLARE_API_TOKEN="test-token-not-a-real-credential"
unset ALLOWED_ORIGIN_IPS

# 1. An invalid scope must refuse to run rather than silently auditing nothing.
AUDIT_SCOPE=garbage check "invalid scope exits 2" 2 "+AUDIT_SCOPE must be"

# 2. A missing credential must fail loud. It must never look like a clean run.
CHECK_ENV=(-u CLOUDFLARE_API_TOKEN -u CF_API_TOKEN)
AUDIT_SCOPE=all check "missing token exits 2" 2 "+CLOUDFLARE_API_TOKEN not set"

# 3. THE INCIDENT. A record on the dead box must be reported, and the verdict of
#    an origins-only run must not claim anything about SSL.
echo '65.181.113.13' > "$WORK/dig_a"
: > "$WORK/dig_aaaa"
echo 'strict' > "$WORK/ssl_mode"
cat > "$WORK/records" <<'R'
[{"type":"A","name":"mail.jewell.nexus","content":"65.181.113.13","proxied":true}]
R
AUDIT_SCOPE=origins check "dead-box A record is a finding" 1 \
  "+DENIED origin 65.181.113.13" "-Full (strict)"

# 4. REGRESSION, defect 1. An unreadable SSL mode must be a FINDING. This is the
#    control that would have caught the `echo`-not-`report` defect: before the
#    fix this exited 0, so 36 zones could have sat on 'Full' reporting success.
echo 'DENY' > "$WORK/ssl_mode"
AUDIT_SCOPE=ssl check "unreadable SSL mode is a finding, not a pass" 1 \
  "+could not be read" "+Zone Settings:Read"

# 5. 'full' is the mode that caused the incident. It must fail.
echo 'full' > "$WORK/ssl_mode"
AUDIT_SCOPE=ssl check "SSL mode 'full' is a finding" 1 "+is 'full', not 'strict'"

# 6. 'strict' is the only passing mode, and an ssl-only verdict must not claim
#    anything about record origins.
echo 'strict' > "$WORK/ssl_mode"
: > "$WORK/records"
AUDIT_SCOPE=ssl check "SSL mode 'strict' passes" 0 \
  "+Every zone is on Full (strict)" "+Record origins NOT examined"

# 7. THE DECISIVE CONTROL — why the workflow is split into two jobs.
#    This is the real Phase-2 situation: the incident is fixed (the record is on
#    an owned origin) but the 36-zone certificate programme has not finished, so
#    the zone is still on 'full'. `origins` MUST be able to go green while `ssl`
#    stays honestly red. If these ever share an exit code, closure condition B
#    is unreachable until Phase 4 and a permanently-red gate stops being read.
echo 'full' > "$WORK/ssl_mode"
cat > "$WORK/records" <<'R'
[{"type":"A","name":"mail.jewell.nexus","content":"69.72.149.237","proxied":false}]
R
export ALLOWED_ORIGIN_IPS="69.72.149.237"
AUDIT_SCOPE=origins check "origins goes GREEN while the zone is on 'full'" 0 \
  "+RESULT [origins]: clean" "+SSL/TLS mode NOT examined"
AUDIT_SCOPE=ssl check "ssl stays RED for the same fixture" 1 "+is 'full', not 'strict'"

# 8. REGRESSION, defect 2. The dead box is the FIRST of two A answers, and there
#    is an unlisted AAAA. `dig +short | tail -1` reported this fixture CLEAN —
#    a silent miss on the exact incident, decided purely by answer order.
echo 'strict' > "$WORK/ssl_mode"
printf '65.181.113.13\n69.72.149.237\n' > "$WORK/dig_a"
printf '2001:db8::dead\n' > "$WORK/dig_aaaa"
cat > "$WORK/records" <<'R'
[{"type":"CNAME","name":"webmail.jewell.nexus","content":"mail.jewell.nexus","proxied":true}]
R
AUDIT_SCOPE=origins check "CNAME target: every A and AAAA answer is checked" 1 \
  "+resolves to DENIED 65.181.113.13" "+2001:db8::dead"

# 9. A target that stopped resolving is dangling too — how SPF and mail break
#    silently. Empty answers must not read as clean.
: > "$WORK/dig_a"
: > "$WORK/dig_aaaa"
AUDIT_SCOPE=origins check "CNAME target that does not resolve is a finding" 1 \
  "+does not resolve"

# 10. NEGATIVE CONTROL. Everything correct must actually pass, or the controls
#     above prove only that the script always complains.
echo 'strict' > "$WORK/ssl_mode"
printf '69.72.149.237\n' > "$WORK/dig_a"
: > "$WORK/dig_aaaa"
AUDIT_SCOPE=all check "all-clean fixture passes in scope=all" 0 \
  "+RESULT [all]: clean"

# 11. A trusted CNAME suffix is allowed without resolving it at all. Kept as a
#     control because allow-listing a MULTI-TENANT suffix (github.io, pages.dev)
#     proves no ownership — a known, recorded weakness, not a fixed one.
cat > "$WORK/records" <<'R'
[{"type":"CNAME","name":"docs.jewell.nexus","content":"hyperpolymath.github.io","proxied":true}]
R
: > "$WORK/dig_a"
AUDIT_SCOPE=origins check "allow-listed CNAME suffix passes" 0 \
  "+RESULT [origins]: clean"

# 12. Without ALLOWED_ORIGIN_IPS every origin must read as unlisted. The absent
#     secret must fail loud, never quietly pass — the allow-list file cannot
#     carry origin IPs because this repository is public.
unset ALLOWED_ORIGIN_IPS
cat > "$WORK/records" <<'R'
[{"type":"A","name":"mail.jewell.nexus","content":"69.72.149.237","proxied":false}]
R
AUDIT_SCOPE=origins check "absent ALLOWED_ORIGIN_IPS fails loud" 1 \
  "+is not on the allow-list"

echo
echo "passed: $PASS   failed: $FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
echo "RESULT: the detector detects. All controls behaved as expected."
