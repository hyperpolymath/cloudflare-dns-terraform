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
#      hostname that should not have one
#   2  usage/preflight error

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
# address with `curl --resolve host:port:addr`. curl then cannot connect
# anywhere else, whatever DNS says next. The `%{remote_ip}` check is kept below
# purely as an assertion that the pin was honoured.

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

# resolve_public HOST -> sets RESOLVE_IP, RESOLVE_BLOCKED. Returns:
#   0  resolved, every answer is public; RESOLVE_IP is the address to pin
#   1  no address at all — the caller reports this as 000, not as a refusal,
#      and CRUCIALLY makes no HTTP request
#   2  refused; RESOLVE_BLOCKED says which answer was private
#
# EVERY answer is checked, not just the one we pin. A resolver that returns a
# public address first and a private one second would otherwise leave a private
# address reachable on any retry or by reordering.
resolve_public() {
  local host="$1" ip answers
  RESOLVE_IP=""; RESOLVE_BLOCKED=""
  answers="$( { dig +short +time=5 +tries=2 "$host" A
                dig +short +time=5 +tries=2 "$host" AAAA; } 2>/dev/null \
              | grep -v '\.$' || true )"
  [[ -n "$answers" ]] || return 1
  for ip in $answers; do
    if is_private_ip "$ip"; then
      RESOLVE_BLOCKED="refused: $host resolves to private address $ip"
      return 2
    fi
  done
  RESOLVE_IP="$(head -1 <<< "$answers")"
  return 0
}

# walk_redirects URL -> sets WALK_CODE, WALK_FINAL, WALK_BLOCKED, WALK_PIN
#   WALK_BLOCKED non-empty  => the chain was refused, and why
#   WALK_CODE 000           => the hostname did not answer at all
#   WALK_PIN                => the --resolve pin used for WALK_FINAL, so a
#                              caller can re-fetch that exact URL without
#                              resolving it a second time
walk_redirects() {
  local url="$1" hop=0 code ip redir rc
  WALK_CODE="000"; WALK_FINAL="$url"; WALK_BLOCKED=""; WALK_PIN=""
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
    if [[ "$rc" -eq 1 ]]; then
      # No address: nothing to connect to, and nothing was connected to.
      WALK_CODE="000"; return 0
    fi
    WALK_PIN="$URL_HOST:$URL_PORT:$RESOLVE_IP"
    read -r code ip redir < <(curl -sS -o /dev/null --max-time "$TIMEOUT" \
        --proto '=https' --max-redirs 0 --resolve "$WALK_PIN" \
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

login_surface() {
  local host="$1" code="$2" final="$3" pin="$4" prefix body
  [[ "$code" == "200" ]] || return 1
  for prefix in $LOGIN_PREFIXES; do
    if [[ "$host" == "$prefix."* ]]; then
      # Reuse the caller's pin rather than resolving $final again. An
      # independent second resolution was the defect here: the address
      # validated during the walk could be replaced by a private one before
      # this fetch. With the pin there is no second resolution to poison.
      # No pin means the caller never validated this URL, so refuse to fetch.
      [[ -n "$pin" ]] || return 1
      body="$(curl -sS --max-time "$TIMEOUT" --proto '=https' --max-redirs 0 \
                   --resolve "$pin" "$final" 2>/dev/null || true)"
      # cPanel/Webmail login markers. Kept broad on purpose: a false positive
      # costs one manual look, a false negative costs a mailbox.
      if grep -qiE 'webmail login|cpanel login|name="?pass(word)?"?|id="?login_password' \
           <<< "$body"; then
        return 0
      fi
      return 1
    fi
  done
  return 1
}

FINDINGS=0
echo "== edge redirect check — $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
echo "hostnames: ${#HOSTS[@]}"
echo

for h in "${HOSTS[@]}"; do
  # A refused chain is a FINDING, never a silent skip: the hostnames fed to this
  # script are the ones suspected of dangling, so "it tried to send us somewhere
  # we refuse to go" is precisely the signal we are looking for.
  if ! walk_redirects "https://$h/"; then
    printf '  %-34s -- REFUSED REDIRECT CHAIN: %s\n' "$h" "$WALK_BLOCKED"
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
      printf '  %-34s %s LOGIN FORM served here\n' "$h" "$code"
      FINDINGS=$((FINDINGS + 1))
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
  echo "LOGIN FORM     = that hostname serves a password field; if its origin is a"
  echo "                 server we have left, the password goes to a stranger. Worse"
  echo "                 than a redirect, so fix it first."
  echo "Check the Cloudflare DNS Content column for those names: a proxied record"
  echo "hides its origin, so the public A record will look innocent."
  exit 1
fi
echo "RESULT: clean. No estate hostname sends visitors off-estate."
