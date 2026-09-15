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

sed -n '/^is_ip_literal() {$/,/^}$/p; /^is_private_ip() {$/,/^}$/p; /^url_host_port() {$/,/^}$/p; /^resolve_public() {$/,/^}$/p; /^walk_redirects() {$/,/^}$/p; /^login_surface() {$/,/^}$/p; /^LOGIN_PREFIXES=/p; /^DNS_FALLBACKS=/p' \
    "$SUT" > "$WORK/sut.bash"

for fn in is_ip_literal is_private_ip url_host_port resolve_public walk_redirects login_surface; do
  grep -q "^${fn}() {$" "$WORK/sut.bash" \
    || { echo "preflight: did not extract ${fn}() from $SUT" >&2; exit 2; }
done

# LOGIN_PREFIXES is lifted from the script as well, so the login controls below
# run against the real prefix list rather than a copy that can drift from it.
grep -q '^LOGIN_PREFIXES=' "$WORK/sut.bash" \
  || { echo "preflight: did not extract LOGIN_PREFIXES from $SUT" >&2; exit 2; }

# DNS_FALLBACKS is lifted too. If it were missing the loop in resolve_public
# would run with an unset variable under `set -u` and every control would die
# the same way, which reads as a harness fault rather than as the missing
# symbol it is — so it is asserted by name like the functions above.
grep -q '^DNS_FALLBACKS=' "$WORK/sut.bash" \
  || { echo "preflight: did not extract DNS_FALLBACKS from $SUT" >&2; exit 2; }
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
# walk_redirects asks curl for -w; the login-surface body fetch does not. Serve
# each its own shape, or the body controls silently measure the walk's output
# instead of a page. An unset STUB_BODY fails LOUDLY rather than defaulting: a
# stub with a permissive default cannot report that it was never configured.
# Record every --resolve pin, so a control can assert the connection was PINNED
# to the validated address rather than merely that the address was validated.
prev=""
for a in "$@"; do
  [[ "$prev" == "--resolve" ]] && echo "$a" >> "$STUB_RESOLVE"
  prev="$a"
done
has_w=0
for a in "$@"; do [[ "$a" == "-w" ]] && has_w=1; done
if [[ "$has_w" == 0 ]]; then
  case "${STUB_BODY:-none}" in
    m_webmail) printf '<title>Webmail Login</title>\n' ;;
    m_cpanel)  printf '<title>cPanel Login</title>\n' ;;
    m_name)    printf '<form><input name=pass></form>\n' ;;
    m_id)      printf '<form><input id="login_password"></form>\n' ;;
    benign) printf '<html><title>A2ML</title><p>nothing to log into</p></html>\n' ;;
    none)   echo "stub: a body was fetched but STUB_BODY is unset" >&2; exit 98 ;;
    *)      echo "stub: unknown STUB_BODY '${STUB_BODY}'" >&2; exit 97 ;;
  esac
  exit 0
fi
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

# --- A scripted dig, so every RESOLUTION is ours too --------------------------
#
# Resolution now happens BEFORE any request, which is the whole point of the
# fix. That makes dig part of the system under test: without a stub these
# controls would resolve real names on the network, and the private-address
# cases could not be expressed at all.
#
# dig is called as `dig +short +time=5 +tries=2 <host> <TYPE>`, so the record
# type is the last argument.
cat > "$WORK/bin/dig" <<'DSTUB'
#!/usr/bin/env bash
n=$(( $(cat "$DIG_COUNT" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$DIG_COUNT"
rtype="${!#}"
# Was an explicit @resolver passed? The fallback path adds one and the system
# resolver path does not, so a scenario can answer differently for the two —
# which is what the retry control needs in order to mean anything.
atres=""
for a in "$@"; do case "$a" in @*) atres="${a#@}" ;; esac; done
case "${STUB_DIG:-public}" in
  public)   [[ "$rtype" == "A" ]] && echo "203.0.113.10" ;;
  private)  [[ "$rtype" == "A" ]] && echo "10.0.0.5" ;;
  # A public answer FIRST and a private one second: the case that a
  # check-only-the-pinned-address implementation would wave through.
  mixed)    [[ "$rtype" == "A" ]] && { echo "203.0.113.10"; echo "192.168.1.9"; } ;;
  # dig +short prints CNAME targets as trailing-dot lines before the address.
  cname)    [[ "$rtype" == "A" ]] && { echo "target.example.com."; echo "203.0.113.10"; } ;;
  # Public A, private AAAA — refused only if AAAA is looked at at all.
  v6priv)   if [[ "$rtype" == "A" ]]; then echo "203.0.113.10"; else echo "fd00::1"; fi ;;
  # `dig +short` writes its OWN diagnostics to STDOUT and exits non-zero. The
  # token `127.0.0.53#53:` matches the private-address pattern, which is how a
  # runner's systemd-resolved timeout became a false "resolves to a private
  # address" finding against a hostname that was never resolved at all.
  digerr)   echo ";; communications error to 127.0.0.53#53: timed out"; exit 9 ;;
  # The same failure with a diagnostic that does NOT look private. This is the
  # direction no exclusion list could have caught: the token would have been
  # accepted and PINNED as though it were an address, curl would reject the
  # malformed --resolve, and the host would be reported `no answer` — the
  # detector reporting clean for a host it never looked at.
  digerrpub) echo ";; communications error to 8.8.8.8#53: connection refused"; exit 9 ;;
  # System resolver errors, the first fallback answers. Without the retry a
  # single flaky resolver turns the daily check permanently red, and a red that
  # is always red is a red nobody reads.
  digfb)    if [[ -n "$atres" ]]; then
              [[ "$rtype" == "A" ]] && echo "203.0.113.10"
              exit 0
            else
              echo ";; communications error to 127.0.0.53#53: timed out"; exit 9
            fi ;;
  none)     : ;;
  *) echo "stub: unknown STUB_DIG '${STUB_DIG}'" >&2; exit 96 ;;
esac
exit 0
DSTUB
chmod +x "$WORK/bin/dig"
export PATH="$WORK/bin:$PATH"
export STUB_COUNT="$WORK/calls"
export STUB_RESOLVE="$WORK/pins"
export DIG_COUNT="$WORK/digs"

# shellcheck disable=SC2034  # both are read by the functions sourced below
TIMEOUT=20
MAX_HOPS=5
# shellcheck source=/dev/null
source "$WORK/sut.bash"

# Stub control: the stub must be the curl we actually get, or every walk control
# below is measuring the real network instead of the scenario.
[[ "$(command -v curl)" == "$WORK/bin/curl" ]] \
  || { echo "preflight: stub curl is not on PATH first" >&2; exit 2; }
[[ "$(command -v dig)" == "$WORK/bin/dig" ]] \
  || { echo "preflight: stub dig is not on PATH first" >&2; exit 2; }

# STUB_DIG is the third argument, defaulting to a public answer, so every
# control written before resolution existed keeps its old meaning. Both
# counters are reset here: a control that asserts "zero requests" is only
# meaningful if the count started at zero.
run_walk() {
  export STUB_MODE="$1"
  export STUB_DIG="${3:-public}"
  : > "$STUB_COUNT"; : > "$STUB_RESOLVE"; : > "$DIG_COUNT"
  walk_redirects "$2"
}

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
echo "--- login_surface"

# This function had NO control in either suite until now, and the live sweep
# cannot supply one: no webmail./cpanel./webdisk./whm. hostname answers anywhere
# in the estate, so every real run skips it entirely. A green sweep has therefore
# never been evidence about this code at all — which is exactly the shape of
# fault this whole workflow exists to prevent.

# The 4th argument is the caller's --resolve pin. login_surface refuses to
# fetch without one (that refusal is control 23), so every control that means
# to exercise the body fetch has to supply it.
run_login() {
  export STUB_BODY="$1"
  : > "$STUB_COUNT"; : > "$DIG_COUNT"
  login_surface "$2" "$3" "$4" "${5:-webmail.example.com:443:203.0.113.10}"
}

# 8a-8d. One control per marker in the detection regex, each fixture matching
#        exactly ONE alternative. A single fixture that matched several would
#        let any one marker be deleted with the suite still green — measured:
#        an earlier fixture matched 2 of the 4, and a mutant that blinded one
#        of them survived at 36/36.
for m in m_webmail m_cpanel m_name m_id; do
  if run_login "$m" "webmail.example.com" 200 "https://webmail.example.com/"; then
    ok "detects login marker: $m"
  else
    bad "detects login marker: $m" "this marker no longer fires; a real login page would read as clean"
  fi
done

# 9. An ordinary page on the same hostname is NOT reported. Without this, a
#    function that returned 0 unconditionally would still pass control 8.
if ! run_login benign "webmail.example.com" 200 "https://webmail.example.com/"; then
  ok "does not report an ordinary page as a login form"
else
  bad "does not report an ordinary page" "a page with no login markers was flagged"
fi

# 10. THE CONTROL FOR THIS COMMIT: the body is fetched from the URL the caller
#     already walked and validated, in exactly ONE request. The previous version
#     re-walked the chain itself, so it issued two or more requests per host and
#     clobbered the WALK_* globals while the caller was still holding them.
run_login m_webmail "webmail.example.com" 200 "https://webmail.example.com/" || true
if [[ "$(cat "$STUB_COUNT")" == "1" ]]; then
  ok "fetches the body in one request, from the caller's already-validated URL"
else
  bad "fetches the body in one request" \
      "made $(cat "$STUB_COUNT") request(s) — it is walking the chain a second time"
fi

# 11. A non-200 response is never body-fetched: no request at all. STUB_BODY is
#     unset so a stray fetch also fails loudly instead of being served a page.
unset STUB_BODY; : > "$STUB_COUNT"
if ! login_surface "webmail.example.com" 301 "https://webmail.example.com/" \
     "webmail.example.com:443:203.0.113.10" \
   && [[ "$(cat "$STUB_COUNT")" == "" ]]; then
  ok "does not fetch a body for a non-200 response"
else
  bad "does not fetch a body for a non-200 response" "calls='$(cat "$STUB_COUNT")'"
fi

# 12. A hostname outside LOGIN_PREFIXES is never body-fetched either.
unset STUB_BODY; : > "$STUB_COUNT"
if ! login_surface "www.example.com" 200 "https://www.example.com/" \
     "www.example.com:443:203.0.113.10" \
   && [[ "$(cat "$STUB_COUNT")" == "" ]]; then
  ok "does not fetch a body for a host outside LOGIN_PREFIXES"
else
  bad "does not fetch a body outside LOGIN_PREFIXES" "calls='$(cat "$STUB_COUNT")'"
fi

echo
echo "--- resolution: validated BEFORE the connection, and PINNED into it"

# 13. THE CONTROL THIS COMMIT EXISTS FOR. A private DNS answer must cause ZERO
#     http requests. The previous version validated `%{remote_ip}`, which curl
#     only populates AFTER the request has been sent — so it rejected a private
#     peer one request too late, when the connection to the private service had
#     already been made. Asserting the refusal REASON alone still passes against
#     that version; only the request count tells the two apart.
if ! run_walk ok200 "https://rebind.example.com/" private \
   && [[ "$WALK_BLOCKED" == *"private address"* ]] \
   && [[ "$(cat "$STUB_COUNT")" == "" ]]; then
  ok "a private DNS answer causes NO http request at all"
else
  bad "a private DNS answer causes no http request" \
      "blocked='${WALK_BLOCKED:-}' calls='$(cat "$STUB_COUNT")'"
fi

# 14. EVERY answer is checked, not just the one that gets pinned. A resolver
#     answering public-then-private would otherwise leave the private address
#     reachable on a retry or a reordering.
if ! run_walk ok200 "https://mixed.example.com/" mixed \
   && [[ "$WALK_BLOCKED" == *"192.168.1.9"* ]] \
   && [[ "$(cat "$STUB_COUNT")" == "" ]]; then
  ok "refuses when ANY answer is private, not just the first"
else
  bad "refuses when any answer is private" \
      "blocked='${WALK_BLOCKED:-}' calls='$(cat "$STUB_COUNT")'"
fi

# 15. AAAA is looked at too. A v4-only check passes a host whose v6 answer is
#     private, and curl prefers v6 wherever it has one.
if ! run_walk ok200 "https://v6.example.com/" v6priv \
   && [[ "$WALK_BLOCKED" == *"fd00::1"* ]]; then
  ok "refuses a private AAAA answer"
else
  bad "refuses a private AAAA answer" "blocked='${WALK_BLOCKED:-}'"
fi

# 16. A name with no address is 'no answer' (000), never a refusal — and again
#     with no request made, because there was nothing to connect to. The two
#     outcomes mean different things to whoever reads the report.
if run_walk ok200 "https://nxdomain.example.com/" none \
   && [[ "$WALK_CODE" == "000" && -z "$WALK_BLOCKED" ]] \
   && [[ "$(cat "$STUB_COUNT")" == "" ]]; then
  ok "a name with no address is 000, not a refusal, and makes no request"
else
  bad "a name with no address is 000" \
      "code='${WALK_CODE:-}' blocked='${WALK_BLOCKED:-}' calls='$(cat "$STUB_COUNT")'"
fi

# 17. `dig +short` prints CNAME targets as trailing-dot lines ahead of the
#     address. Those are not addresses: one fed to is_private_ip reads as
#     public, and pinning it would hand curl a hostname to resolve again —
#     undoing the pin entirely.
if run_walk ok200 "https://aliased.example.com/" cname \
   && [[ "$WALK_CODE" == "200" && -z "$WALK_BLOCKED" ]] \
   && [[ "$(cat "$STUB_RESOLVE")" == "aliased.example.com:443:203.0.113.10" ]]; then
  ok "strips CNAME lines and pins the address, not the alias"
else
  bad "strips CNAME lines and pins the address" \
      "code='${WALK_CODE:-}' pin='$(cat "$STUB_RESOLVE")' blocked='${WALK_BLOCKED:-}'"
fi

# 18. VALIDATION IS NOT THE DEFENCE ON ITS OWN: the approved address has to be
#     PINNED into the connection, or DNS can answer differently between the
#     check and the connect (TOCTOU / DNS rebinding). This asserts the pin
#     actually reached curl.
run_walk ok200 "https://pinned.example.com/" public
if [[ "$(cat "$STUB_RESOLVE")" == "pinned.example.com:443:203.0.113.10" ]]; then
  ok "the validated address is pinned into the connection with --resolve"
else
  bad "the validated address is pinned into the connection" \
      "recorded pins: '$(cat "$STUB_RESOLVE")'"
fi

# 19. --resolve is keyed on host AND port, so a non-443 URL must pin its own
#     port. A pin naming 443 for a :9443 URL simply never applies, and curl
#     resolves normally — the defence disappears without any error.
run_walk ok200 "https://odd.example.com:9443/" public
if [[ "$(cat "$STUB_RESOLVE")" == "odd.example.com:9443:203.0.113.10" ]]; then
  ok "pins the port the URL actually uses, not an assumed 443"
else
  bad "pins the port the URL actually uses" "recorded pins: '$(cat "$STUB_RESOLVE")'"
fi

echo
echo "--- url_host_port"

# 20. Parsing controls, for the same reason as 19: a parse error here does not
#     fail loudly, it produces a pin that never matches. The userinfo cases are
#     the ones that matter for safety — the host is what follows the LAST '@',
#     and reading the userinfo as the host would pin an attacker-chosen name
#     while curl connected to the real one.
while read -r url want_host want_port; do
  if url_host_port "$url" \
     && [[ "$URL_HOST" == "$want_host" && "$URL_PORT" == "$want_port" ]]; then
    ok "parses $url -> $want_host:$want_port"
  else
    bad "parses $url" "got '${URL_HOST:-}':'${URL_PORT:-}', want '$want_host':'$want_port'"
  fi
done <<'CASES'
https://a.example.com/ a.example.com 443
https://a.example.com:8443/x?y=1 a.example.com 8443
https://[2001:db8::1]/ 2001:db8::1 443
https://[2001:db8::1]:8443/ 2001:db8::1 8443
https://user:pw@real.example.com/ real.example.com 443
https://evil.example.com@real.example.com/ real.example.com 443
CASES

# 21. A URL with no host is refused rather than yielding an empty pin.
if ! url_host_port "https:///path"; then
  ok "refuses a URL with no host"
else
  bad "refuses a URL with no host" "accepted, host='${URL_HOST:-}'"
fi

echo
echo "--- login_surface does not resolve a second time"

# 22. The other half of the SSRF finding, and it was MY defect: the body fetch
#     re-resolved the final URL independently, so an address validated during
#     the walk could be replaced by a private one before the body was fetched.
#     It now reuses the caller's pin, so it must make NO dig call of its own.
run_login m_webmail "webmail.example.com" 200 "https://webmail.example.com/" || true
if [[ "$(cat "$DIG_COUNT")" == "" ]]; then
  ok "login_surface performs no second DNS resolution"
else
  bad "login_surface performs no second DNS resolution" \
      "made $(cat "$DIG_COUNT") dig call(s) — the pin is being bypassed"
fi

# 23. With no pin it refuses outright rather than fetching something nobody
#     validated. This is what makes controls 11 and 12 honest: they now pass a
#     pin, so they still fail for the reason they claim.
: > "$STUB_COUNT"
if ! login_surface "webmail.example.com" 200 "https://webmail.example.com/" "" \
   && [[ "$(cat "$STUB_COUNT")" == "" ]]; then
  ok "refuses to fetch a body with no pin from the caller"
else
  bad "refuses to fetch a body with no pin" "calls='$(cat "$STUB_COUNT")'"
fi

# 24. And the body fetch itself must carry the pin. Control 22 proves
#     login_surface does not call `dig`; it does NOT prove the pin is used,
#     because curl re-resolves internally where the dig stub cannot see it.
#     Dropping `--resolve` from this one curl restores the original defect
#     verbatim and is invisible to every other control here.
: > "$STUB_RESOLVE"
run_login m_webmail "webmail.example.com" 200 "https://webmail.example.com/" \
    "webmail.example.com:443:203.0.113.10" || true
if [[ "$(cat "$STUB_RESOLVE")" == "webmail.example.com:443:203.0.113.10" ]]; then
  ok "the body fetch is pinned to the caller's validated address"
else
  bad "the body fetch is pinned to the caller's validated address" \
      "recorded pins: '$(cat "$STUB_RESOLVE")'"
fi


# --- A dig diagnostic is not a DNS answer ------------------------------------
#
# 25. `dig +short` writes its own diagnostics to STDOUT. The previous filter was
#     a BLACKLIST (drop trailing-dot CNAME lines), so those words reached the
#     private-address check, where the token `127.0.0.53#53:` matches `127.*`.
#     Every token below is checked individually because resolve_public
#     word-splits the answer text, so the unit of the defect is the TOKEN.
for tok in 203.0.113.10 192.0.2.1 0.0.0.0 255.255.255.255 2001:db8::1 fd00::1 ::1; do
  if is_ip_literal "$tok"; then
    ok "accepts the address literal $tok"
  else
    bad "accepts the address literal $tok" "rejected a real address"
  fi
done
for tok in ';;' communications error to '127.0.0.53#53:' timed out \
           'target.example.com.' '8.8.8.8#53:' '' 'connection' '1.2.3' '1.2.3.4.5' \
           '999.1.1.1' 'cafe:' 'no' 'servers' 'could' 'be' 'reached'; do
  if is_ip_literal "$tok"; then
    bad "rejects the non-address token '$tok'" \
        "a dig diagnostic token was accepted as an address"
  else
    ok "rejects the non-address token '$tok'"
  fi
done

# 26. THE REGRESSION. A resolver that times out must not be reported as a
#     hostname resolving into private space. Before the fix this produced
#     `refused: <host> resolves to private address 127.0.0.53#53:` — a finding
#     naming an estate hostname for a fault in the runner's own resolver.
dig_rc=0; run_walk ok200 "https://timeout.example.com/" digerr || dig_rc=$?
if [[ "${WALK_BLOCKED:-}" != *"private address"* ]]; then
  ok "a resolver timeout is not reported as a private-address refusal"
else
  bad "a resolver timeout is not reported as a private-address refusal" \
      "blocked='${WALK_BLOCKED:-}'"
fi

# 27. And it is reported as its OWN kind AND as a finding (non-zero return), so
#     the report loop labels it DNS UNRESOLVABLE instead of passing it over.
#     WALK_CODE legitimately stays 000 here — no request was made — so the code
#     is NOT the discriminator; the return is. "We could not look" recorded as a
#     clean answer is the failure that hid mail.jewell.nexus for six months.
if [[ "${WALK_KIND:-}" == "unresolved" && "$dig_rc" -ne 0 ]]; then
  ok "an unresolvable hostname is reported as unresolved, not as no answer"
else
  bad "an unresolvable hostname is reported as unresolved, not as no answer" \
      "kind='${WALK_KIND:-}' rc='$dig_rc'"
fi

# 28. Nothing was connected to. A name we could not resolve must cost zero
#     HTTP requests, or the refusal happened after the connection again.
if [[ -z "$(cat "$STUB_COUNT")" ]]; then
  ok "an unresolvable hostname causes zero HTTP requests"
else
  bad "an unresolvable hostname causes zero HTTP requests" \
      "made $(cat "$STUB_COUNT") request(s)"
fi

# 29. The direction an exclusion list could never have caught: a diagnostic
#     naming a PUBLIC resolver. `8.8.8.8#53:` is not private, so the old code
#     would have pinned it, curl would have rejected the malformed --resolve,
#     and the host would have been reported `no answer` — clean, for a host
#     never looked at. Assert both halves: no pin, and not a clean answer.
run_walk ok200 "https://pubdiag.example.com/" digerrpub || true
if [[ -z "$(cat "$STUB_RESOLVE")" && "${WALK_KIND:-}" == "unresolved" ]]; then
  ok "a public-looking diagnostic is not pinned as an address"
else
  bad "a public-looking diagnostic is not pinned as an address" \
      "pins='$(cat "$STUB_RESOLVE")' kind='${WALK_KIND:-}'"
fi

# 30. The retry is real: the system resolver errors, a fallback answers, and
#     the walk proceeds normally. Without this, control 26's cure would turn
#     every transient resolver hiccup into a permanent daily red — a red that
#     is always red is a red nobody reads, which is how this estate got here.
run_walk ok200 "https://fallback.example.com/" digfb || true
if [[ "${WALK_CODE:-}" == "200" && "${WALK_KIND:-}" != "unresolved" \
   && "$(cat "$STUB_RESOLVE")" == "fallback.example.com:443:203.0.113.10" ]]; then
  ok "a resolver that errors falls through to the next one and still resolves"
else
  bad "a resolver that errors falls through to the next one and still resolves" \
      "code='${WALK_CODE:-}' kind='${WALK_KIND:-}' pins='$(cat "$STUB_RESOLVE")'"
fi

# 31. The fan-out is BOUNDED to the error cases. A definitive empty answer
#     (NXDOMAIN) must stop at the system resolver: exactly two queries, A and
#     AAAA. Most estate hostnames do not exist, so a fallback storm here would
#     triple the query count of every daily run for no information at all.
run_walk noanswer "https://gone.example.com/" none || true
if [[ "$(cat "$DIG_COUNT")" == "2" ]]; then
  ok "a definitive NXDOMAIN costs two queries, not a fallback storm"
else
  bad "a definitive NXDOMAIN costs two queries, not a fallback storm" \
      "made $(cat "$DIG_COUNT") dig call(s)"
fi

printf 'passed: %s   failed: %s\n' "$PASS" "$FAIL"
if [[ "$FAIL" -eq 0 ]]; then
  echo "RESULT: the follower follows, and refuses what it must."
  exit 0
fi
echo "RESULT: $FAIL control(s) failed. Do not trust the redirect follower."
exit 1
