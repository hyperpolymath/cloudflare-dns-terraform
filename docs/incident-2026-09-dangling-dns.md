<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
-->

# Incident: jewell.nexus subdomains redirecting off-estate (2026-09-08)

## Summary

Subdomains of `jewell.nexus` were sending visitors to an unrelated adult site.
This had recurred for months and every previous remedy failed, because every
remedy was aimed at the wrong thing.

**There was no hijack, no DNS poisoning and no malware.** Anti-virus and
VirusTotal returned clean results because there was nothing infected to find.

Two ordinary misconfigurations combined:

1. **Dangling DNS.** Records still pointed at `65.181.113.13`, a shared-hosting
   IP the cPanel account had been migrated away from. That box answers *every*
   unmatched hostname with `301 -> https://amsterdamescortmodels.com/`, because
   that customer's WordPress is now its default vhost.
2. **Cloudflare SSL/TLS mode set to Full.** Full accepts *any* certificate at
   the origin. The edge connected to the stranger's server, accepted a
   certificate reading `CN=amsterdamescortmodels.com`, and proxied the
   stranger's redirect to our visitors behind our own valid certificate.

The dangling record aimed it. Full pulled the trigger. Under Full (strict) the
edge would have refused the origin and shown an error page instead.

## Evidence

| Probe | Result |
|---|---|
| Any hostname resolved to `65.181.113.13` over HTTPS | `301 -> amsterdamescortmodels.com` |
| An invented hostname that never existed on the box | Same `301`. Confirms default vhost, not an attack on us |
| Same box, port 80 | `200 OK` for every hostname, no redirect |
| Certificate presented for SNI `jewell.nexus` | `CN=amsterdamescortmodels.com` only. Our account is gone from that box |
| Redirect response headers | `x-redirect-by: WordPress`, `server: LiteSpeed` |
| `mail.jewell.nexus` through the Cloudflare edge | `200`, final URL `amsterdamescortmodels.com`, `x-turbo-charged-by: LiteSpeed` |
| RIPE for `65.181.113.0/24` | netname `WHG-FRA1-3`, WHG Hosting Services Ltd (World Host Group), GB |

The port-80 control is what proves the SSL mode. The dead box only redirects
over HTTPS. Cloudflare returned that redirect, so the edge fetched over HTTPS
against a mismatched certificate, which only Full permits. Flexible would have
proxied the port-80 `200`; Full (strict) would have returned a 526.

## Why it kept coming back

`Full` was not an accident. The estate notes carry an unclosed TODO dated
2026-03-16 02:20 UTC: *"jewell.nexus temporarily on SSL full — switch back to
strict after AutoSSL issues certs (~24h)"*. The switch back never happened, and
the zone sat in Full for roughly six months.

That is worth naming precisely, because the same trap is waiting on the way out.
Full (strict) with no valid origin certificate returns 526 to everything,
*including* the challenge fetch cPanel AutoSSL uses to validate the domain. So
AutoSSL cannot issue, and the tempting fix is to drop to Full "temporarily". The
way out is a Cloudflare Origin CA certificate, which Cloudflare trusts
immediately with no validation round-trip. See the plan's step 1.2a.

## Why it was invisible

A **proxied** record's public A record shows Cloudflare addresses. The
configured origin is hidden from `dig` and from every external scanner. Deleting
the two obviously-broken subdomain records therefore missed `mail`, `webmail`,
`ftp` and the `_dc-*` records, which stayed pointed at the dead box.

The origin is visible in exactly two places: the Cloudflare dashboard **Content
column**, and the API's record `content` field. `scripts/dns-origin-audit.sh`
reads the second one.

## The report to send

One recipient, not forty. The operator of the misconfigured server is our own
hosting group, which makes this a routine misconfiguration report rather than an
abuse accusation. Reporting the adult site's owner would be misreporting: they
are another customer on a shared box and their WordPress is behaving normally.

- **To:** `abuse@worldhost.group` (RIPE abuse contact for `65.181.113.0/24`)
- **Cc:** Verpex support, referencing reseller account the reseller account (named in the private handover note)
- **Subject:** Default vhost on s4936.fra1.stableserver.net (65.181.113.13)
  serves a customer redirect for unmatched hostnames

> Hello,
>
> This is a configuration report about one of your Frankfurt shared servers,
> not an abuse complaint about a customer.
>
> `65.181.113.13` (rDNS `s4936.fra1.stableserver.net`) answers any hostname
> resolved to it over HTTPS with `301 -> https://amsterdamescortmodels.com/`,
> including hostnames that have never existed on the server. That customer has
> done nothing wrong; their site has simply become the default vhost.
>
> Reproduction, using a hostname invented on the spot:
>
>     curl -sI --resolve zzz-not-a-real-vhost.example.org:443:65.181.113.13 \
>          -k https://zzz-not-a-real-vhost.example.org/
>
> The effect on customers is that any domain whose DNS still points at this
> address after a migration sends its visitors to an unrelated adult site. In
> our case this reached a family member's personal site and recurred for months
> before the cause was understood.
>
> Could you please point the default vhost at a neutral page or a 404 rather
> than at a customer site? That single change removes the failure mode for
> every domain that has ever been hosted there.
>
> FYI for your migration checklist: the box also still answers `webmail.` for
> domains whose accounts have left it.
>
> Separately, could you confirm which server our reseller accounts occupy now?
> Reseller account the reseller account (named in the private handover note).
>
> Thank you.

## What stops it recurring

1. Delete every record whose Content is `65.181.113.13` (by content, not by
   name — that is what previous attempts missed).
2. Set SSL/TLS to **Full (strict)** explicitly on every zone. Not Full, and not
   Automatic, which settles on Full against an origin like this one.
3. Read the Cloudflare **Audit Log** to identify the actor that re-adds records.
   If it names a hosting-partner integration, disconnecting it ends the loop.
4. Install Cloudflare Origin CA certificates so a recycled IP cannot impersonate
   our origin even if a record is wrong.
5. Run `scripts/dns-origin-audit.sh` and `scripts/edge-redirect-check.sh` daily
   (`.github/workflows/dns-origin-audit.yml`).

## Local automation: ruled out

Checked and cleared as the cause of the re-added records:

- `.github/workflows/auto-detect-new-domains.yml` runs weekly but only opens a
  pull request. It never runs `terraform apply`.
- This repository's Terraform manages no SSL/TLS mode setting, so it did not
  set Full.
- `meta-repos/burble/scripts/cf-ddns.sh` and `cf-bolt-dns.sh` hold
  `Zone:DNS:Edit` on `jewell.nexus` but write only `bolt.jewell.nexus` and its
  NAPTR/SRV records. No such cron is installed on the workstation.

That absence is itself evidence: it points the Audit Log check at the
hosting-partner integration rather than at a script of ours.
