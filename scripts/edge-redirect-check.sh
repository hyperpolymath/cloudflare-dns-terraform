#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# edge-redirect-check.sh — fail if any estate hostname sends visitors off-estate.
#
# The companion to dns-origin-audit.sh, and deliberately credential-free so it
# can run anywhere, including from a laptop during an incident.
#
# dns-origin-audit.sh asks "is every record aimed somewhere we own?" by reading
# the Cloudflare API. This script asks the question a visitor asks: "if I open
# this hostname, where do I end up?" It needs no token because it only makes the
# request a browser would make. The two together cover both the configuration
# and its observable effect.
#
# On 2026-09-08 this check would have caught mail.jewell.nexus, which was
# proxied — so its public DNS looked entirely innocent — while the edge was
# fetching from a dead shared-hosting origin and proxying that stranger's
# redirect to an adult site.
#
# USAGE
#   ./scripts/edge-redirect-check.sh                 # domains.csv + common subdomains
#   ./scripts/edge-redirect-check.sh host [host...]  # explicit hosts
#
# EXIT CODES
#   0  every hostname stayed on an estate domain
#   1  at least one hostname left the estate, or served a login form from a
#      hostname that is not on the approved-login-hosts.txt list
#   2  usage/preflight error
#
# FILES
#   domains.csv                the estate's zones, one domain per line
#   approved-login-hosts.txt   "login <hostname>" — a login form on this exact
#                              hostname is expected, so it is the service
#                              working rather than a finding. Exact hostnames
#                              only: no suffixes, no patterns. Absent file =
#                              nothing approved, which is the fail-safe default.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CSV="${DOMAINS_CSV:-$REPO_ROOT/domains.csv}"
TIMEOUT="${TIMEOUT:-20}"
MAX_HOPS="${MAX_HOPS:-5}"

command -v curl >/dev/null 2>&1 || { echo "error: curl not found" >&2; exit 2; }
command -v dig  >/dev/null 2>&1 || { echo "error: dig not found (install bind9-dnsutils)" >&2; exit 2; }

# Subdomains worth probing. webmail/cpanel/mail/ftp are cPanel proxy subdomains:
# a shared-hosting box answers them whether or not our account still lives there,
# which is what turned webmail.jewell.nexus into a credential-capture surface
# pointed at a server the family no longer controlled.
SUBS="${SUBS:-@ www mail webmail cpanel ftp}"

declare -a HOSTS=()
declare -a APEXES=()

if [[ $# -gt 0 ]]; then
  HOSTS=("$@")
  for h in "$@"; do APEXES+=("$h"); done
else
  [[ -f "$CSV" ]] || { echo "error: $CSV not found" >&2; exit 2; }
  while IFS=, read -r domain _rest; do
    domain="$(echo "$domain" | tr -d '"' | xargs 2>/dev/null || true)"
    [[ -z "$domain" || "$domain" == "domain" ]] && continue
    APEXES+=("$domain")
    for s in $SUBS; do
      if [[ "$s" == "@" ]]; then HOSTS+=("$domain"); else HOSTS+=("$s.$domain"); fi
    done
  done < "$CSV"
fi

# A final URL is acceptable if its host ends in one of our own apex domains.
on_estate() {
  local url="$1" host apex
  host="$(echo "$url" | sed -E 's#^[a-zA-Z]+://##; s#[/?].*$##; s#:[0-9]+$##')"
  [[ -z "$host" ]] && return 1
  for apex in "${APEXES[@]}"; do
    [[ "$host" == "$apex" || "$host" == *".$apex" ]] && return 0
  done
  return 1
}

# --- Redirect following, done by us rather than by curl -L ---------------------
#
# This script's entire job is to follow redirects, so `curl -L` looks like the
# obvious tool. It is the wrong one HERE, for a reason specific to this script:
# the hostnames fed in are exactly the ones suspected of being dangling or
# hostile. `curl -L` hands the whole chain to whoever controls the Location
# header, which can walk the runner into loopback or RFC1918 space on the CI
# machine, or downgrade the hop to plain HTTP (CWE-918; SonarCloud shell:S6506).
# The cure is not to stop following redirects — that would delete the detector —
# but to follow them one hop at a time and validate each hop before taking it.
#
# Enforced on EVERY hop, not just the last: scheme must be https, and the peer
# must not be in private, loopback, link-local or CGNAT space. Bounded by
# MAX_HOPS so a redirect loop cannot hang the job.
#
# Why the peer check alone was NOT enough, and what replaced it: `%{remote_ip}`
# is only populated AFTER curl has sent the request, so validating it rejected a
# private peer one request too late — the connection to the private service had
# already happened. Validation therefore has to precede the connection, and the
# approved address has to be PINNED into it, or DNS can answer differently
# between the check and the connect (TOCTOU / DNS rebinding).
#
# So every hop now goes: resolve -> validate EVERY answer -> pin the approved
# address with `curl --resolve host:port:addr` AND `--noproxy '*'`. BOTH are
# required, and the second is not belt-and-braces. A `--resolve` pin binds a
# hostname to an address only for a DIRECT connection. If HTTPS_PROXY,
# https_proxy or ALL_PROXY is set in the environment, curl does not resolve
# the host at all - it CONNECTs to the proxy and hands it the HOSTNAME, which
# the proxy resolves itself. The pin is then not a pin: every validation above
# it still runs, still passes, and guards nothing, while the request goes
# wherever the proxy's DNS points. That is the estate's recurring trap of a
# comment asserting a property the code does not guarantee, so the flag is
# here and a control asserts it on EVERY curl invocation.
# With both, curl cannot connect anywhere else whatever DNS says next. The
# `%{remote_ip}` check is kept below purely as an assertion that the pin was
# honoured.

is_private_ip() {
  case "$1" in
    10.*|127.*|0.*|169.254.*|192.168.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[0-1][0-9].*|100.12[0-7].*) return 0 ;;
    ::1|fe80:*|fc??:*|fd??:*|fc:*|fd:*) return 0 ;;
    *) ;;
  esac
  return 1
}

# url_host_port URL -> sets URL_HOST, URL_PORT. Returns 1 if there is no host.
# Needed because --resolve is keyed on host AND port, so the port has to be the
# one curl will actually use, not an assumed 443.
url_host_port() {
  local rest="${1#https://}"
  URL_HOST=""; URL_PORT=""
  rest="${rest%%/*}"          # drop path
  rest="${rest%%\?*}"         # drop query on a path-less URL
  rest="${rest%%#*}"          # drop fragment
  rest="${rest##*@}"          # drop userinfo — the host is AFTER the last @
  case "$rest" in
    \[*\]:*) URL_HOST="${rest%%\]:*}"; URL_HOST="${URL_HOST#\[}"
             URL_PORT="${rest##*\]:}" ;;
    \[*\])   URL_HOST="${rest#\[}";    URL_HOST="${URL_HOST%\]}"
             URL_PORT="443" ;;
    *:*)     URL_HOST="${rest%%:*}";   URL_PORT="${rest##*:}" ;;
    *)       URL_HOST="$rest";         URL_PORT="443" ;;
  esac
  [[ -n "$URL_HOST" && "$URL_PORT" =~ ^[0-9]+$ ]] || return 1
  return 0
}

# is_ip_literal TOKEN -> 0 if TOKEN is a bare IPv4 or IPv6 address literal.
#
# `dig +short` writes its OWN diagnostics to STDOUT, not to stderr:
#
#     ;; communications error to 127.0.0.53#53: timed out
#
# Those words are neither addresses nor CNAME targets, so the previous filter —
# a BLACKLIST that dropped trailing-dot CNAME lines — passed them straight
# through to the private-address check, where the token `127.0.0.53#53:` matches
# `127.*`. The hostname was then reported as "resolves to a private address"
# having never been resolved at all. That is a false FINDING, and it is exactly
# what the edge job reported for one hostname on a GitHub runner whose
# systemd-resolved stub timed out.
#
# The reason this is a whitelist rather than one more exclusion is the OTHER
# direction, which is worse and which no exclusion list would have caught: a
# diagnostic token that does not happen to look private — a resolver at
# 8.8.8.8, say — would have been accepted as the address to PIN. curl would
# then reject the malformed `--resolve`, the request would fail, and the host
# would be reported `000 no answer`: the detector answering "clean" for a host
# it never looked at. An exclusion list can only ever chase the diagnostics dig
# happens to emit today. A shape test admits addresses and nothing else.
is_ip_literal() {
  local s="$1" o a b c d extra colons
  case "$s" in
    ''|*[!0-9a-fA-F.:]*) return 1 ;;
  esac
  case "$s" in
    *:*)
      # IPv6: hex digits and colons only (established above), and at least two
      # colons — every real IPv6 literal has two, and no bare word does.
      colons="${s//[!:]/}"
      [[ "${#colons}" -ge 2 ]] || return 1
      return 0 ;;
  esac
  IFS=. read -r a b c d extra <<< "$s"
  [[ -z "$extra" && -n "$d" ]] || return 1
  for o in "$a" "$b" "$c" "$d"; do
    case "$o" in ''|*[!0-9]*) return 1 ;; esac
    [[ $((10#$o)) -le 255 ]] || return 1
  done
  return 0
}

# Resolvers consulted in order: the system resolver first, the public ones ONLY
# if it errors. A normal NXDOMAIN therefore still costs exactly one query per
# record type, and the fan-out is bounded to the error cases that need it.
DNS_FALLBACKS="${DNS_FALLBACKS:-1.1.1.1 8.8.8.8}"

# resolve_public HOST -> sets RESOLVE_IP, RESOLVE_BLOCKED. Returns:
#   0  resolved, every answer is public; RESOLVE_IP is the address to pin
#   1  no address at all, and a resolver said so definitively (NXDOMAIN or no
#      records) — the caller reports this as 000, not as a refusal, and
#      CRUCIALLY makes no HTTP request
#   2  refused; RESOLVE_BLOCKED says which answer was private
#   3  could not resolve: EVERY resolver errored. This is neither an answer nor
#      a definitive absence of one, so the caller must report it as its own
#      thing. "We could not look" recorded as "clean" is the precise failure
#      that hid mail.jewell.nexus for six months, so it must never collapse
#      into the 000 branch.
#
# EVERY answer is checked, not just the one we pin. A resolver that returns a
# public address first and a private one second would otherwise leave a private
# address reachable on any retry or by reordering.
resolve_public() {
  local host="$1" ip line rtype r out rc_q answers
  RESOLVE_IP=""; RESOLVE_BLOCKED=""
  for r in "" $DNS_FALLBACKS; do
    answers=""; rc_q=0
    for rtype in A AAAA; do
      if [[ -n "$r" ]]; then
        out="$(dig +short +time=5 +tries=2 "@$r" "$host" "$rtype" 2>/dev/null)" || rc_q=1
      else
        out="$(dig +short +time=5 +tries=2 "$host" "$rtype" 2>/dev/null)" || rc_q=1
      fi
      while read -r line; do
        is_ip_literal "$line" && answers="$answers $line"
      done <<< "$out"
    done
    # Any literal answer is a definitive reply: validate all of them and stop.
    if [[ -n "$answers" ]]; then
      for ip in $answers; do
        if is_private_ip "$ip"; then
          RESOLVE_BLOCKED="refused: $host resolves to private address $ip"
          return 2
        fi
      done
      for ip in $answers; do RESOLVE_IP="$ip"; break; done
      return 0
    fi
    # No literals AND both queries exited cleanly: a real absence of records.
    [[ "$rc_q" -eq 0 ]] && return 1
    # Otherwise this resolver errored — try the next one.
  done
  return 3
}

# walk_redirects URL -> sets WALK_CODE, WALK_FINAL, WALK_BLOCKED, WALK_PIN
#   WALK_BLOCKED non-empty  => the chain was refused, and why
#   WALK_CODE 000           => the hostname did not answer at all
#   WALK_PIN                => the --resolve pin used for WALK_FINAL, so a
#                              caller can re-fetch that exact URL without
#                              resolving it a second time
walk_redirects() {
  local url="$1" hop=0 code ip redir rc
  WALK_CODE="000"; WALK_FINAL="$url"; WALK_BLOCKED=""; WALK_PIN=""; WALK_KIND="refused"
  while :; do
    case "$url" in
      https://*) ;;
      *) WALK_BLOCKED="refused non-https hop: $url"; return 1 ;;
    esac
    if ! url_host_port "$url"; then
      WALK_BLOCKED="refused unparseable hop: $url"; return 1
    fi
    resolve_public "$URL_HOST"; rc=$?
    if [[ "$rc" -eq 2 ]]; then
      WALK_BLOCKED="$RESOLVE_BLOCKED (hop: $url)"; return 1
    fi
    if [[ "$rc" -eq 3 ]]; then
      # Every resolver errored. Reported as its own KIND, never as 000: an
      # unanswerable question must not be recorded as a reassuring answer.
      WALK_KIND="unresolved"
      WALK_BLOCKED="DNS for $URL_HOST could not be resolved by the system resolver or any of: $DNS_FALLBACKS — NOT CHECKED, which is not the same as clean (hop: $url)"
      return 1
    fi
    if [[ "$rc" -eq 1 ]]; then
      # No address: nothing to connect to, and nothing was connected to.
      WALK_CODE="000"; return 0
    fi
    WALK_PIN="$URL_HOST:$URL_PORT:$RESOLVE_IP"
    read -r code ip redir < <(curl -sS -o /dev/null --max-time "$TIMEOUT" \
        --proto '=https' --max-redirs 0 --noproxy '*' --resolve "$WALK_PIN" \
        -w '%{http_code} %{remote_ip} %{redirect_url}' "$url" 2>/dev/null \
        || echo "000 - -")
    # Assertion, not the defence. The pin above is the defence; this can only
    # fire if --resolve was ignored, so if it ever does, something is wrong
    # with the tool rather than with the hostname.
    if [[ -n "$ip" && "$ip" != "-" ]] && is_private_ip "$ip"; then
      WALK_BLOCKED="refused hop into private space: $url -> $ip"
      return 1
    fi
    if [[ "$code" == "000" ]]; then WALK_CODE="000"; return 0; fi
    WALK_CODE="$code"; WALK_FINAL="$url"
    case "$code" in 30[0-8]) ;; *) return 0 ;; esac
    if [[ -z "$redir" || "$redir" == "-" ]]; then return 0; fi
    hop=$((hop + 1))
    if [[ "$hop" -gt "$MAX_HOPS" ]]; then
      WALK_BLOCKED="refused chain longer than $MAX_HOPS hops (last: $url)"
      return 1
    fi
    url="$redir"
  done
}

# A cPanel proxy subdomain that answers with a login form is worse than a
# redirect: the visitor types a mail password into it. The box answers these
# names whether or not our account still lives there, so the form may be
# collecting credentials on a server we do not control. This is the finding
# that dns-origin-audit.sh would catch from the Content column, reproduced
# here so the credential-free fallback catches it too when no token exists.
LOGIN_PREFIXES="webmail cpanel webdisk whm"

# --- the approved-login-host policy ------------------------------------------
#
# A login form on a cPanel service name is a finding only if the service is not
# SUPPOSED to be there, and login_surface cannot tell the two apart by itself.
# Without a policy it reports every login form it finds, so the first legitimate
# webmail host in this estate (33 reseller cPanel accounts, so: when, not if)
# would turn the daily check permanently red — and a gate that is red every day
# for a known-good reason is a gate nobody reads.
#
# The list is EXACT hostnames, one `login <hostname>` line each, in
# approved-login-hosts.txt beside allowed-origins.txt. No suffixes and no
# patterns, on purpose: a suffix on a shared platform approves anyone's host,
# not ours — the defect recorded for the origin allow-list in #41.
APPROVED_LOGIN_HOSTS_FILE="${APPROVED_LOGIN_HOSTS_FILE:-$REPO_ROOT/approved-login-hosts.txt}"
APPROVED_LOGIN_HOSTS=()

# load_approved_login_hosts — read APPROVED_LOGIN_HOSTS_FILE into the array.
#
# A MISSING file yields an empty list, which approves nothing. That is both the
# fail-safe direction (an unapproved host is reported, never silently excused)
# and the estate's measured state today: no webmail./cpanel./webdisk./whm.
# hostname answers anywhere. It is deliberately NOT a preflight error: refusing
# to run would delete the off-estate detector over a policy file, and a detector
# that will not look is the failure this whole workflow exists to prevent.
#
# A MALFORMED entry is exit 2, because the readings of `login *.jewell.nexus`
# are "approve every hostname that matches" and "approve nothing", and guessing
# between them is how a policy becomes a hole. Shape-validated as a single
# hostname, so a wildcard, a suffix and a bare kind word all fail loudly here
# instead of silently never matching the hostname they were meant to approve.
load_approved_login_hosts() {
  APPROVED_LOGIN_HOSTS=()
  [[ -f "$APPROVED_LOGIN_HOSTS_FILE" ]] || return 0
  local line kind val
  while IFS= read -r line; do
    line="${line%%#*}"
    line="$(echo "$line" | xargs 2>/dev/null || true)"
    [[ -z "$line" ]] && continue
    kind="${line%% *}"
    val="${line#* }"
    case "$kind" in
      login)
        val="${val,,}"
        if [[ ! "$val" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]; then
          echo "error: $APPROVED_LOGIN_HOSTS_FILE: '$val' is not a hostname." >&2
          echo "hint:  approval is per EXACT hostname, one line per service, e.g." >&2
          echo "         login webmail.jewell.nexus" >&2
          echo "       A wildcard ('login *.jewell.nexus') would approve every host" >&2
          echo "       that matches it, including a stranger's — the multi-tenant" >&2
          echo "       mistake this list must not repeat. Refusing rather than" >&2
          echo "       guessing which reading was meant." >&2
          exit 2
        fi
        APPROVED_LOGIN_HOSTS+=("$val") ;;
      *)
        echo "warn: ignoring unrecognised approved-login-hosts.txt line: $line" >&2 ;;
    esac
  done < "$APPROVED_LOGIN_HOSTS_FILE"
}

# is_approved_login_host HOST -> 0 when a login form on HOST is expected.
# Exact match on the whole hostname; approving `jewell.nexus` approves the apex
# and nothing under it.
is_approved_login_host() {
  local host="${1,,}" entry
  for entry in "${APPROVED_LOGIN_HOSTS[@]+"${APPROVED_LOGIN_HOSTS[@]}"}"; do
    [[ "$host" == "$entry" ]] && return 0
  done
  return 1
}

# host_of_url URL -> prints the host (no port), lowercased; returns 1 if there
# is none. THIN WRAPPER ON PURPOSE: it goes through url_host_port, the same
# parser the walk used to build the pin, so the host that is JUDGED and the host
# that is FETCHED are the same string from the same parser reading the same URL.
# Two parsers — or two URLs — is the #43 defect: the prefix test read the probe
# host while the body fetch read the final URL, so after a redirect this
# function declined to look at the credential surface it had just walked into,
# and would have body-checked a project homepage it was never asked about.
#
# The https check is an ASSERTION OF THE CONTRACT, not a defence: url_host_port
# already yields no host at all for a non-https URL (its port field ends up
# non-numeric), so removing this line kills no control — measured, mutant M8.
# It is here so that a future caller which hands over a URL the walk never
# validated gets a refusal rather than a hostname, and it is labelled as that
# rather than as a guard, because a comment claiming a property the code does
# not establish is this estate's most-repeated defect.
host_of_url() {
  local url="$1"
  [[ "$url" == https://* ]] || return 1
  url_host_port "$url" || return 1
  printf '%s' "${URL_HOST,,}"
}

# login_surface PROBE_HOST CODE FINAL_URL PIN -> 0 means FINDING.
#
#   PROBE_HOST  the hostname the sweep started from. Used ONLY to describe a
#               finding in which the chain moved host; never to decide one.
#   CODE        the status of the last hop.
#   FINAL_URL   where the chain landed. The host judged is this URL's host,
#               because the question is "what is served where the visitor
#               lands?" — and because that is the host about to be fetched.
#   PIN         the --resolve pin the walk built for FINAL_URL. Without one
#               this function refuses to fetch at all.
#
# Sets LOGIN_STATE for the caller's report:
#   finding   a login form on a host nobody approved — the actual signal
#   expected  an approved login host serving a login form — the service working
#   absent    an approved login host serving no login form — not a finding
#   none      nothing to report
#
# The old version walked the chain a second time and clobbered the caller's
# WALK_* globals; this one fetches the caller's already-validated URL exactly
# once, through the caller's pin.
login_surface() {
  local probe="$1" code="$2" final="$3" pin="$4"
  local judged="" matched="" prefix body="" pin_host=""
  LOGIN_STATE="none"; LOGIN_NOTE=""
  [[ "$code" == "200" ]] || return 1

  # ONE HOST, READ ONCE. This is the whole of #43: the guard and its consumer
  # must ask their question about the same value, and this is that value — the
  # host of the URL the caller walked and validated, which is the URL about to
  # be fetched.
  judged="$(host_of_url "$final")" || return 1

  # The body is fetched only for a cPanel service NAME — still gated on the
  # name, but on the name that is about to be fetched.
  for prefix in $LOGIN_PREFIXES; do
    if [[ "$judged" == "$prefix."* ]]; then matched="$prefix"; break; fi
  done
  [[ -n "$matched" ]] || return 1

  # Reuse the caller's pin rather than resolving $final again. An independent
  # second resolution was the defect here: the address validated during the
  # walk could be replaced by a private one before this fetch. With the pin
  # there is no second resolution to poison — and it has to belong to the URL
  # being fetched, or the fetch would go out through a pin that validated a
  # different address.
  [[ -n "$pin" ]] || return 1
  # Case-insensitively: the walk builds the pin from the URL it was handed, and a
  # Location header may spell the host in any case, while hostnames are
  # case-insensitive and this function compares lower-cased ones. Comparing
  # byte-for-byte here would refuse to fetch a real credential surface whose
  # redirect happened to capitalise it — a false negative produced by the
  # assertion meant to make the fetch safer, which is why control 45 exists.
  pin_host="${pin%%:*}"
  [[ "${pin_host,,}" == "$judged" ]] || return 1

  body="$(curl -sS --max-time "$TIMEOUT" --proto '=https' --max-redirs 0 \
               --noproxy '*' --resolve "$pin" "$final" 2>/dev/null || true)"

  # cPanel/Webmail login markers. Kept broad on purpose: a false positive
  # costs one manual look, a false negative costs a mailbox.
  if grep -qiE 'webmail login|cpanel login|name="?pass(word)?"?|id="?login_password' \
       <<< "$body"; then
    if is_approved_login_host "$judged"; then
      LOGIN_STATE="expected"
      return 1                       # an approved service working is not a finding
    fi
    LOGIN_STATE="finding"
    if [[ "$probe" != "$judged" ]]; then
      LOGIN_NOTE="at $judged, reached by redirect; not an approved login host"
    else
      LOGIN_NOTE="not an approved login host"
    fi
    return 0
  fi

  # A login-prefixed name serving no login form is not a finding whether or not
  # it is approved. See approved-login-hosts.txt: the list says a form here is
  # legitimate, not that one must exist.
  if is_approved_login_host "$judged"; then LOGIN_STATE="absent"; fi
  return 1
}

load_approved_login_hosts
login_hosts_note=""
[[ -f "$APPROVED_LOGIN_HOSTS_FILE" ]] \
  || login_hosts_note=" ($APPROVED_LOGIN_HOSTS_FILE absent — nothing is pre-approved)"

FINDINGS=0
echo "== edge redirect check — $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
echo "hostnames: ${#HOSTS[@]}"
echo "approved login hosts: ${#APPROVED_LOGIN_HOSTS[@]}$login_hosts_note"
echo

for h in "${HOSTS[@]}"; do
  # A refused chain is a FINDING, never a silent skip: the hostnames fed to this
  # script are the ones suspected of dangling, so "it tried to send us somewhere
  # we refuse to go" is precisely the signal we are looking for.
  if ! walk_redirects "https://$h/"; then
    # Two different facts, two different labels. "We refuse to follow this
    # chain" and "we could not resolve this name at all" are both findings,
    # but conflating them would let a resolver outage read as an estate
    # problem — and, far worse, invite someone to dismiss a real refusal as
    # flaky DNS.
    if [[ "$WALK_KIND" == "unresolved" ]]; then
      printf '  %-34s -- DNS UNRESOLVABLE: %s\n' "$h" "$WALK_BLOCKED"
    else
      printf '  %-34s -- REFUSED REDIRECT CHAIN: %s\n' "$h" "$WALK_BLOCKED"
    fi
    FINDINGS=$((FINDINGS + 1))
    continue
  fi
  code="$WALK_CODE"; final="$WALK_FINAL"; pin="$WALK_PIN"

  # A hostname that does not resolve or does not answer is not a finding. The
  # danger is a hostname that answers and sends the visitor somewhere else.
  if [[ "$code" == "000" ]]; then
    printf '  %-34s no answer\n' "$h"
    continue
  fi

  if on_estate "$final"; then
    if login_surface "$h" "$code" "$final" "$pin"; then
      printf '  %-34s %s LOGIN FORM served here — %s\n' "$h" "$code" "$LOGIN_NOTE"
      FINDINGS=$((FINDINGS + 1))
    elif [[ "$LOGIN_STATE" == "expected" ]]; then
      printf '  %-34s %s ok (approved login host — login form served, as expected)\n' "$h" "$code"
    elif [[ "$LOGIN_STATE" == "absent" ]]; then
      printf '  %-34s %s ok (approved login host — no login form served today)\n' "$h" "$code"
    else
      printf '  %-34s %s ok\n' "$h" "$code"
    fi
  else
    printf '  %-34s %s LEAVES ESTATE -> %s\n' "$h" "$code" "$final"
    FINDINGS=$((FINDINGS + 1))
  fi
done

echo
if [[ "$FINDINGS" -gt 0 ]]; then
  echo "RESULT: $FINDINGS finding(s)."
  echo "LEAVES ESTATE = a visitor opening that hostname lands somewhere we do not own."
  echo "REFUSED REDIRECT CHAIN = a hop we declined to follow (non-https, private"
  echo "                 address, unparseable, or too many hops). The chain is the"
  echo "                 finding; it is not a tooling failure."
  echo "DNS UNRESOLVABLE = every resolver errored, so this hostname was NOT CHECKED."
  echo "                 It is reported rather than passed over, because an"
  echo "                 unanswered question is not a clean answer."
  echo "LOGIN FORM     = that hostname serves a password field and is NOT on the"
  echo "                 approved-login-hosts.txt list. If its origin is a server we"
  echo "                 have left, the password goes to a stranger. Worse than a"
  echo "                 redirect, so fix it first — or add the hostname to that list,"
  echo "                 explicitly, if a login form there is intended."
  echo "Check the Cloudflare DNS Content column for those names: a proxied record"
  echo "hides its origin, so the public A record will look innocent."
  exit 1
fi
echo "RESULT: clean. No estate hostname sends visitors off-estate."
