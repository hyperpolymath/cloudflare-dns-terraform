<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->
<!-- TOPOLOGY.md — Project architecture map and completion dashboard -->
<!-- Last updated: 2026-02-19 -->

# Cloudflare DNS Terraform — Project Topology

## System Architecture

```
                        ┌─────────────────────────────────────────┐
                        │              OPERATOR / ADMIN           │
                        │        (Excel, CSV, Terraform CLI)      │
                        └───────────────────┬─────────────────────┘
                                            │
                                            ▼
                        ┌─────────────────────────────────────────┐
                        │           DATA SOURCE LAYER             │
                        │  ┌───────────┐  ┌───────────────────┐  │
                        │  │domains.csv│  │ terraform.tfvars  │  │
                        │  │(Domains,  │  │ (API Credentials) │  │
                        │  │ Config)   │  │                   │  │
                        │  └─────┬─────┘  └────────┬──────────┘  │
                        └────────│─────────────────│──────────────┘
                                 │                 │
                                 ▼                 ▼
                        ┌─────────────────────────────────────────┐
                        │           TERRAFORM ENGINE              │
                        │  ┌───────────┐  ┌───────────────────┐  │
                        │  │  main.tf  │  │ terraform.tfstate │  │
                        │  │ (Logic)   │  │ (Tracking file)   │  │
                        │  └─────┬─────┘  └────────┬──────────┘  │
                        └────────│─────────────────│──────────────┘
                                 │                 │
                                 ▼                 ▼
                        ┌─────────────────────────────────────────┐
                        │           CLOUDFLARE API                │
                        │  ┌───────────┐  ┌───────────┐  ┌───────┐│
                        │  │ DNS ZONES │  │ WAF / CF  │  │ WORKERS││
                        │  │ Records   │  │ Headers   │  │ SCRIPTS││
                        │  └───────────┘  └───────────┘  └───────┘│
                        └───────────────────┬─────────────────────┘
                                            │
                                            ▼
                        ┌─────────────────────────────────────────┐
                        │          DOMAIN ECOSYSTEM               │
                        │      (SPF, DMARC, CAA, SSHFP, MX)       │
                        └─────────────────────────────────────────┘

                        ┌─────────────────────────────────────────┐
                        │          REPO INFRASTRUCTURE            │
                        │  Extraction Scripts  .machine_readable/ │
                        │  auto-add-new-sites  contractiles/      │
                        └─────────────────────────────────────────┘
```

## Completion Dashboard

```
COMPONENT                          STATUS              NOTES
─────────────────────────────────  ──────────────────  ─────────────────────────────────
CORE INFRASTRUCTURE
  Terraform Logic (main.tf)         ██████████ 100%    Loop-based zone management stable
  Variables (variables.tf)          ██████████ 100%    Full parameterization active
  CSV Ingestion                     ██████████ 100%    domains.csv parsing verified

SECURITY & RECORDS
  Email Security (SPF/DMARC)        ██████████ 100%    Automatic TXT record generation
  Security Headers (Workers)        ██████████ 100%    WAF & Header workers stable
  CAA/SSHFP Records                 ██████████ 100%    Identity proofs automated

SCRIPTS & TOOLS
  Extraction Scripts                ████████░░  80%    API result parsing refined
  Auto-add new sites                ██████████ 100%    CLI trigger active
  Domain CSV Generator              ████████░░  80%    Batch formatting stable

REPO INFRASTRUCTURE
  contractiles/                     ██████████ 100%    Provisioning rules stable
  .machine_readable/                ██████████ 100%    STATE.a2ml tracking
  Documentation (Guides)            ██████████ 100%    Terraform & Excel workflow docs

─────────────────────────────────────────────────────────────────────────────
OVERALL:                            █████████░  ~90%   Infrastructure-as-Code stable
```

## Key Dependencies

```
domains.csv ──────► terraform plan ──────► terraform apply
     │                   │                      │
     ▼                   ▼                      ▼
Credentials ──────► API Checks ──────────► Cloudflare Zone
```

## Update Protocol

This file is maintained by both humans and AI agents. When updating:

1. **After completing a component**: Change its bar and percentage
2. **After adding a component**: Add a new row in the appropriate section
3. **After architectural changes**: Update the ASCII diagram
4. **Date**: Update the `Last updated` comment at the top of this file

Progress bars use: `█` (filled) and `░` (empty), 10 characters wide.
Percentages: 0%, 10%, 20%, ... 100% (in 10% increments).
