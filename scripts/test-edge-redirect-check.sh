#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# test-edge-redirect-check.sh — prove the redirect follower still follows, and
# still refuses.
#
# WHY THIS EXISTS
# ---------------
# `edge-redirect-check.sh` used `curl -L`, which hands the whole redirect chain
# to whoever controls the Location header. The hostnames it is fed are precisely
# the ones suspected of dangling, so that let a hostile or stale host walk the CI
# runner into loopback or RFC1918 space, or downgrade a hop to plain HTTP
# (CWE-918; SonarCloud shell:S6506). It now follows redirects itself, one hop at
# a time, validating each hop before taking it.
#
# That fix has two failure modes, and they point in opposite directions:
#
#   1. It refuses too little — a private-space or plain-HTTP hop gets taken
#      anyway, and the vulnerability is still there behind a comment claiming it
#      is not.
#   2. It refuses too much — the walker stops following redirects, and the
#      script silently stops being an off-estate detector at all. THIS IS THE
#      DANGEROUS ONE. The estate's whole six-month fault was a detector that
#      reported success while checking nothing, so a "secure" version that
#      answers `clean` because it never looks is a regression dressed as a fix.
#
# Controls below cover both directions. Control 7 is the one that matters most:
# the walker must still traverse a redirect and report where it landed.
#
# Hermetic by construction, like the sibling suite: no network and no
# credential. `curl` is a stub on PATH, so every hop is scripted. All addresses
# are RFC 5737 / RFC 3849 documentation space or genuine RFC1918/loopback band
# boundaries — never estate infrastructure, because this repository is public.
#
# USAGE
#   ./scripts/test-edge-redirect-check.sh
#
# EXIT CODES
#   0  every control behaved as expected
#   1  at least one control failed — the follower is not trustworthy
#   2  preflight error

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUT="$HERE/edge-redirect-check.sh"
[[ -r "$SUT" ]] || { echo "preflight: cannot read $SUT" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok()   { printf 'ok   %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf 'FAIL %s\n       %s\n' "$1" "$2"; FAIL=$((FAIL + 1)); }

# --- Extract the SHIPPED functions -------------------------------------------
#
# These controls must test the code that actually runs, not a copy of it that can
# drift. So the two functions are lifted out of the real script by name.
#
# An extraction that silently found nothing would make every control below pass
# vacuously — the exact absence-shaped failure this incident kept producing — so
# the extraction is itself asserted before anything is run.

sed -n '/^is_private_ip() {$/,/^}$/p; /^walk_redirects() {$/,/^}$/p' \
    "$SUT" > "$WORK/sut.bash"

for fn in is_private_ip walk_redirects; do
  grep -q "^${fn}() {$" "$WORK/sut.bash" \
    || { echo "preflight: did not extract ${fn}() from $SUT" >&2; exit 2; }
done
bash -n "$WORK/sut.bash" \
  || { echo "preflight: extracted functions do not parse" >&2; exit 2; }

# --- A scripted curl, so every hop is ours -----------------------------------
#
# The stub emits exactly what walk_redirects reads: `http_code remote_ip
# redirect_url`. STUB_MODE picks the scenario; the call counter lets a scenario
# answer differently on the second hop.

mkdir -p "$WORK/bin"
cat > "$WORK/bin/curl" <<'STUB'
#!/usr/bin/env bash
n=$(( $(cat "$STUB_COUNT" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$STUB_COUNT"
case "${STUB_MODE:-ok200}" in
  ok200)     echo "200 203.0.113.10" ;;
  noanswer)  exit 7 ;;
  private)   echo "301 10.0.0.5 https://moved.example.com/" ;;
  loop)      echo "301 203.0.113.10 https://next-${n}.example.com/" ;;
  onehop)    if [[ "$n" == 1 ]]; then echo "301 203.0.113.10 https://final.example.com/"
             else echo "200 203.0.113.11"; fi ;;
  *) echo "stub: unknown STUB_MODE '${STUB_MODE:-}'" >&2; exit 99 ;;
esac
STUB
chmod +x "$WORK/bin/curl"
export PATH="$WORK/bin:$PATH"
export STUB_COUNT="$WORK/calls"

# shellcheck disable=SC2034  # both are read by the functions sourced below
TIMEOUT=20
MAX_HOPS=5
# shellcheck source=/dev/null
source "$WORK/sut.bash"

# Stub control: the stub must be the curl we actually get, or every walk control
# below is measuring the real network instead of the scenario.
[[ "$(command -v curl)" == "$WORK/bin/curl" ]] \
  || { echo "preflight: stub curl is not on PATH first" >&2; exit 2; }

run_walk() { export STUB_MODE="$1"; : > "$STUB_COUNT"; walk_redirects "$2"; }

echo "--- is_private_ip: addresses that MUST be refused"
for ip in 10.0.0.1 127.0.0.1 0.0.0.0 169.254.1.1 192.168.1.1 \
          172.16.0.1 172.24.0.1 172.31.255.254 \
          100.64.0.1 100.90.0.1 100.115.0.1 100.127.255.254 \
          ::1 fe80::1 fd00::1 fc00::1; do
  if is_private_ip "$ip"; then ok "private: $ip"
  else bad "private: $ip" "read as public, so a hop into it would be taken"; fi
done

echo "--- is_private_ip: addresses that MUST be allowed (band boundaries)"
# 172.15/172.32 and 100.63/100.128 sit one address outside RFC1918 and CGNAT.
# They are the off-by-one that a hand-written case pattern gets wrong, and a
# false positive here would make the walker refuse legitimate estate hosts.
for ip in 203.0.113.10 198.51.100.7 192.0.2.1 \
          172.15.255.254 172.32.0.1 100.63.255.254 100.128.0.1 \
          2001:db8::1; do
  if is_private_ip "$ip"; then
    bad "public: $ip" "read as private, so the walker would refuse a valid hop"
  else ok "public: $ip"; fi
done

echo "--- walk_redirects"

# 1. A plain-HTTP hop is refused without any request being made at all.
if ! run_walk ok200 "http://insecure.example.com/" \
   && [[ "$WALK_BLOCKED" == *"non-https"* ]] \
   && [[ "$(cat "$STUB_COUNT")" == "" ]]; then
  ok "refuses a non-https hop, and refuses it before connecting"
else
  bad "refuses a non-https hop" "blocked='${WALK_BLOCKED:-}' calls='$(cat "$STUB_COUNT")'"
fi

# 2. A hop whose peer is in private space is refused, and reported as such.
if ! run_walk private "https://rebound.example.com/" \
   && [[ "$WALK_BLOCKED" == *"private space"* ]]; then
  ok "refuses a hop into private space"
else
  bad "refuses a hop into private space" "rc=0 or wrong reason: '${WALK_BLOCKED:-}'"
fi

# 3. An endless chain is bounded, not followed forever.
if ! run_walk loop "https://loop.example.com/" \
   && [[ "$WALK_BLOCKED" == *"longer than $MAX_HOPS hops"* ]]; then
  ok "refuses a chain longer than MAX_HOPS"
else
  bad "refuses a chain longer than MAX_HOPS" "blocked='${WALK_BLOCKED:-}'"
fi

# 4. MAX_HOPS is a bound, not a slogan: the request count must be finite and
#    match it. A walker that gave up on hop 1 would also "pass" control 3.
calls="$(cat "$STUB_COUNT")"
if [[ "$calls" -ge 2 && "$calls" -le $((MAX_HOPS + 2)) ]]; then
  ok "bounded chain actually made $calls requests (MAX_HOPS=$MAX_HOPS)"
else
  bad "bounded chain request count" "made $calls requests, expected 2..$((MAX_HOPS + 2))"
fi

# 5. A terminal 200 succeeds and carries its code out.
if run_walk ok200 "https://fine.example.com/" \
   && [[ "$WALK_CODE" == "200" && -z "$WALK_BLOCKED" ]]; then
  ok "a plain 200 passes through with its code"
else
  bad "a plain 200 passes through" "code='${WALK_CODE:-}' blocked='${WALK_BLOCKED:-}'"
fi

# 6. A host that does not answer is reported as 000 — 'no answer', never as a
#    refusal, because the two mean different things to the operator reading the
#    report.
if run_walk noanswer "https://silent.example.com/" \
   && [[ "$WALK_CODE" == "000" && -z "$WALK_BLOCKED" ]]; then
  ok "a host that does not answer reports 000, not a refusal"
else
  bad "a host that does not answer reports 000" "code='${WALK_CODE:-}' blocked='${WALK_BLOCKED:-}'"
fi

# 7. THE ONE THAT MATTERS: it must still FOLLOW a redirect and say where it
#    landed. Every control above is satisfied by a walker that refuses
#    everything; only this one fails if the detector has been secured into
#    uselessness.
if run_walk onehop "https://start.example.com/" \
   && [[ "$WALK_CODE" == "200" \
      && "$WALK_FINAL" == "https://final.example.com/" \
      && -z "$WALK_BLOCKED" ]]; then
  ok "still follows a redirect and reports the destination"
else
  bad "still follows a redirect and reports the destination" \
      "code='${WALK_CODE:-}' final='${WALK_FINAL:-}' blocked='${WALK_BLOCKED:-}'"
fi

echo
printf 'passed: %s   failed: %s\n' "$PASS" "$FAIL"
if [[ "$FAIL" -eq 0 ]]; then
  echo "RESULT: the follower follows, and refuses what it must."
  exit 0
fi
echo "RESULT: $FAIL control(s) failed. Do not trust the redirect follower."
exit 1
