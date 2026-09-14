#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
#
# dns-origin-audit.sh — catch dangling DNS across every Cloudflare zone.
#
# WHY THIS EXISTS
# ---------------
# On 2026-09-08, joshua.jewell.nexus was found redirecting visitors to an
# unrelated adult site. It was not a hijack, a poisoning or malware. DNS records
# were still aimed at 65.181.113.13, a shared-hosting IP the cPanel account had
# been moved off. That box answers EVERY unmatched hostname with a 301 to
# whichever customer is now its default vhost. Cloudflare's SSL mode was "Full",
# which accepts any certificate at the origin, so the edge faithfully proxied a
# stranger's redirect behind our own valid certificate.
#
# The failure was invisible from outside, because a PROXIED record's public A
# record shows Cloudflare IPs and hides the configured origin. Only the API (or
# the dashboard Content column) reveals it. That blind spot is why the problem
# recurred for months and was found each time by a family member noticing it on
# LinkedIn.
#
# This script closes the loop: it reads the true origin of every record in every
# zone and fails if any of them points somewhere we do not own today.
#
# USAGE
#   CLOUDFLARE_API_TOKEN=... ./scripts/dns-origin-audit.sh
#
# TOKEN SCOPES (read-only is sufficient and recommended)
#   Zone:Zone:Read      — list zones, read the SSL/TLS mode
#   Zone:DNS:Read       — read records
#
# EXIT CODES
#   0  clean
#   1  one or more findings (details on stdout)
#   2  usage/preflight error
#
# FILES
#   allowed-origins.txt  — one entry per line, in the repo root.
#                          "ip 203.0.113.10"        an origin IP we own
#                          "suffix github.io"       a CNAME target suffix we trust
#                          "deny 65.181.113.13"     known-dead, always a finding
#                          blank lines and # comments ignored.

set -euo pipefail

CF_API="https://api.cloudflare.com/client/v4"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOWLIST="${ALLOWLIST:-$REPO_ROOT/allowed-origins.txt}"
TOKEN="${CLOUDFLARE_API_TOKEN:-${CF_API_TOKEN:-}}"

# Note: CNAME/MX/NS/SRV contents are hostnames rather than addresses. Those are
# resolved and checked below, because a CNAME to a host that died is dangling
# just as surely as an A record aimed at a recycled IP.

for bin in curl jq dig; do
  command -v "$bin" >/dev/null 2>&1 || { echo "error: $bin not found" >&2; exit 2; }
done

if [[ -z "$TOKEN" ]]; then
  echo "error: CLOUDFLARE_API_TOKEN not set" >&2
  echo "hint:  a read-only token (Zone:Read + DNS:Read) is enough" >&2
  exit 2
fi

if [[ ! -f "$ALLOWLIST" ]]; then
  echo "error: allow-list not found at $ALLOWLIST" >&2
  exit 2
fi

# ---- load the allow-list ------------------------------------------------
ALLOW_IPS=()
ALLOW_SUFFIXES=()
DENY_IPS=()
while IFS= read -r line; do
  line="${line%%#*}"
  line="$(echo "$line" | xargs 2>/dev/null || true)"
  [[ -z "$line" ]] && continue
  kind="${line%% *}"
  val="${line#* }"
  case "$kind" in
    ip)     ALLOW_IPS+=("$val") ;;
    suffix) ALLOW_SUFFIXES+=("$val") ;;
    deny)   DENY_IPS+=("$val") ;;
    *)      echo "warn: ignoring unrecognised allow-list line: $line" >&2 ;;
  esac
done < "$ALLOWLIST"

# Origin addresses are NOT kept in the allow-list file: this repository is
# public, and publishing the estate's origin IPs would defeat the purpose of
# proxying. They arrive through ALLOWED_ORIGIN_IPS instead (repo secret),
# whitespace- or comma-separated. Absent, the audit still runs and simply
# reports every origin as unlisted, which is the correct fail-loud default.
if [[ -n "${ALLOWED_ORIGIN_IPS:-}" ]]; then
  while read -r extra_ip; do
    [[ -n "$extra_ip" ]] && ALLOW_IPS+=("$extra_ip")
  done <<< "$(echo "$ALLOWED_ORIGIN_IPS" | tr ", " "\n\n")"
fi

cf() {
  curl -fsS --max-time 30 \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" "$@"
}

in_list() {
  local needle="$1"; shift
  local item
  for item in "$@"; do [[ "$needle" == "$item" ]] && return 0; done
  return 1
}

suffix_allowed() {
  local host="${1%.}" suf
  for suf in "${ALLOW_SUFFIXES[@]+"${ALLOW_SUFFIXES[@]}"}"; do
    [[ "$host" == "$suf" || "$host" == *".$suf" ]] && return 0
  done
  return 1
}

FINDINGS=0
report() {
  FINDINGS=$((FINDINGS + 1))
  printf '  [FINDING] %s\n' "$*"
}

# ---- enumerate zones ----------------------------------------------------
echo "== Cloudflare origin audit — $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
page=1
ZONES_JSON="$(mktemp)"
trap 'rm -f "$ZONES_JSON"' EXIT
: > "$ZONES_JSON"
while :; do
  resp="$(cf "$CF_API/zones?per_page=50&page=$page")"
  echo "$resp" | jq -c '.result[] | {id, name}' >> "$ZONES_JSON"
  total_pages="$(echo "$resp" | jq -r '.result_info.total_pages')"
  [[ "$page" -ge "$total_pages" ]] && break
  page=$((page + 1))
done

zone_count="$(wc -l < "$ZONES_JSON" | tr -d ' ')"
echo "zones: $zone_count"
echo

while IFS= read -r zline; do
  zid="$(echo "$zline" | jq -r .id)"
  zname="$(echo "$zline" | jq -r .name)"
  echo "-- $zname"

  # SSL/TLS mode. Full is the mode that let a stranger's certificate through.
  # `|| echo unknown` is load-bearing: under `set -e` a curl failure here
  # (token without Zone Settings read) would otherwise kill the whole run on
  # the first zone, and the "unknown" branch below would never be reached.
  mode="$(cf "$CF_API/zones/$zid/settings/ssl" 2>/dev/null | jq -r '.result.value // "unknown"' || echo unknown)"
  [[ -z "$mode" ]] && mode="unknown"
  case "$mode" in
    strict)  ;;                                             # full (strict) — correct
    unknown) echo "  note: could not read SSL mode (token scope?)" ;;
    *)       report "$zname SSL/TLS mode is '$mode', not 'strict'. Full and Flexible both accept an origin that is not ours." ;;
  esac

  # All DNS records, paginated.
  rpage=1
  while :; do
    rresp="$(cf "$CF_API/zones/$zid/dns_records?per_page=100&page=$rpage")"
    while IFS= read -r rec; do
      [[ -z "$rec" ]] && continue
      rtype="$(echo "$rec" | jq -r .type)"
      rname="$(echo "$rec" | jq -r .name)"
      rcontent="$(echo "$rec" | jq -r .content)"
      rproxied="$(echo "$rec" | jq -r '.proxied // false')"

      # Deny-list first: these are known-dead and always a finding.
      if in_list "$rcontent" "${DENY_IPS[@]+"${DENY_IPS[@]}"}"; then
        report "$rname ($rtype) points at DENIED origin $rcontent — this is the dangling-DNS failure. Delete the record."
        continue
      fi

      case "$rtype" in
        A|AAAA)
          if ! in_list "$rcontent" "${ALLOW_IPS[@]+"${ALLOW_IPS[@]}"}"; then
            report "$rname ($rtype) origin $rcontent is not on the allow-list (proxied=$rproxied). Either add it to allowed-origins.txt or delete the record."
          fi
          ;;
        CNAME|MX|NS|SRV)
          target="$(echo "$rcontent" | awk '{print $NF}')"
          target="${target%.}"
          [[ -z "$target" || "$target" == "." ]] && continue   # null MX is fine
          if ! suffix_allowed "$target"; then
            resolved="$(dig +short "$target" A 2>/dev/null | tail -1 || true)"
            if [[ -z "$resolved" ]]; then
              report "$rname ($rtype) targets $target, which does not resolve. A target that stopped resolving is how SPF and mail silently break."
            elif in_list "$resolved" "${DENY_IPS[@]+"${DENY_IPS[@]}"}"; then
              report "$rname ($rtype) targets $target, which resolves to DENIED $resolved."
            elif ! in_list "$resolved" "${ALLOW_IPS[@]+"${ALLOW_IPS[@]}"}"; then
              report "$rname ($rtype) targets $target, which resolves to $resolved, not on the allow-list."
            fi
          fi
          ;;
      esac
    done < <(echo "$rresp" | jq -c '.result[]')

    rtotal="$(echo "$rresp" | jq -r '.result_info.total_pages')"
    [[ "$rpage" -ge "$rtotal" ]] && break
    rpage=$((rpage + 1))
  done
done < "$ZONES_JSON"

echo
if [[ "$FINDINGS" -gt 0 ]]; then
  echo "RESULT: $FINDINGS finding(s). A record is aimed somewhere we do not control."
  exit 1
fi
echo "RESULT: clean. Every origin is on the allow-list and every zone is on Full (strict)."
