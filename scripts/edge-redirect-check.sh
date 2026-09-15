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
# Honest limit: this validates the address curl actually connected to, reported
# by %{remote_ip} after the fact. It is not a DNS-rebinding defence — nothing
# short of pinning the resolved address into the connection is. It closes the
# open-redirect-into-private-space path, which is the one a dangling estate
# hostname creates.

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

# walk_redirects URL -> sets WALK_CODE, WALK_FINAL, WALK_BLOCKED
#   WALK_BLOCKED non-empty  => the chain was refused, and why
#   WALK_CODE 000           => the hostname did not answer at all
walk_redirects() {
  local url="$1" hop=0 code ip redir
  WALK_CODE="000"; WALK_FINAL="$url"; WALK_BLOCKED=""
  while :; do
    case "$url" in
      https://*) ;;
      *) WALK_BLOCKED="refused non-https hop: $url"; return 1 ;;
    esac
    read -r code ip redir < <(curl -sS -o /dev/null --max-time "$TIMEOUT" \
        --proto '=https' --max-redirs 0 \
        -w '%{http_code} %{remote_ip} %{redirect_url}' "$url" 2>/dev/null \
        || echo "000 - -")
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
  local host="$1" code="$2" final="$3" prefix body
  [[ "$code" == "200" ]] || return 1
  for prefix in $LOGIN_PREFIXES; do
    if [[ "$host" == "$prefix."* ]]; then
      # $final is the last URL of a chain the caller already walked hop by hop,
      # so its scheme and peer address are already validated. Fetch it directly
      # rather than walking again: a second walk doubles the requests and
      # clobbers the WALK_* globals the caller is still holding.
      body="$(curl -sS --max-time "$TIMEOUT" --proto '=https' --max-redirs 0 \
                   "$final" 2>/dev/null || true)"
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
  code="$WALK_CODE"; final="$WALK_FINAL"

  # A hostname that does not resolve or does not answer is not a finding. The
  # danger is a hostname that answers and sends the visitor somewhere else.
  if [[ "$code" == "000" ]]; then
    printf '  %-34s no answer\n' "$h"
    continue
  fi

  if on_estate "$final"; then
    if login_surface "$h" "$code" "$final"; then
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
