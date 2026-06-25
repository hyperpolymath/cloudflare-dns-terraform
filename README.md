<!--
SPDX-License-Identifier: CC-BY-SA-4.0
SPDX-FileCopyrightText: 2025-2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
-->

Infrastructure-as-code for managing DNS records across all hyperpolymath
domains.

# Features

- Manage **unlimited domains** from single CSV/Excel file

- **Consistent DNS structure** across all domains

- **Version controlled** changes

- **Preview before apply** (see exactly what will change)

- **Bulk updates** (change all domains at once)

- **Domain-specific customization** (keys, tunnel IDs, etc.)

- **Optional Web3/IPFS gateway hostnames** for direct
  [`https://ipfs.<domain`](https://ipfs.<domain)`>/` access

- **Optional edge consent/capability prefilters** when the origin
  already enforces the canonical policy

# Quick Start

## 1. Install Terraform

```bash
# Linux
wget https://releases.hashicorp.com/terraform/1.7.0/terraform_1.7.0_linux_amd64.zip
unzip terraform_1.7.0_linux_amd64.zip
sudo mv terraform /usr/local/bin/
```

## 2. Set Up Credentials

```bash
cp terraform.tfvars.example terraform.tfvars
```

`terraform.tfvars`:

```hcl
cloudflare_api_token  = "your-api-token-here"
cloudflare_account_id = "your-account-id-here"
```

## 3. Add Your Domains

Edit `domains.csv`. Key columns:

| Column | Description | Example |
|----|----|----|
| `domain` | Domain name | `wokelang.org` |
| `github_user` | GitHub username | `hyperpolymath` |
| `github_repo` | GitHub repo name | `wokelang` |
| `tunnel_id` | Cloudflare Tunnel ID | `abc123-def456` |
| `mx_primary` | Primary mail server | `mail.wokelang.org` |
| `enable_mail` | Enable MX records | `true`/`false` |
| `enable_tunnel` | Enable Cloudflare Tunnel | `true`/`false` |
| `enable_ssh` | Enable SSHFP records | `true`/`false` |
| `enable_github_pages` | Enable GitHub Pages CNAME | `true`/`false` |
| `enable_ipfs_gateway` | Enable Cloudflare Web3 IPFS hostname | `true`/`false` |
| `ipfs_dnslink` | Initial DNSLink for Web3 hostname | `/ipns/onboarding.ipfs.cloudflare.com` |
| `pages_project` | Cloudflare Pages project name | `wokelang` |

## 4. Deploy

```bash
# Initialize Terraform
terraform init

# Preview changes (DRY RUN)
terraform plan

# Apply changes
terraform apply
```

# DNS Records Created

## For EVERY Domain

`www`, `static`, `assets`, `cdn`, `discourse`, `zulip`, `chat`,
`conference`, `members`, `stfp`, `office`, `ci`, `status`, `logs`,
`api`, `auth`, `wasm`, `linkedin`, `rss` CNAMEs; SPF TXT; DMARC TXT; CAA
records.

## Conditional (based on CSV flags)

- **GitHub Pages**: `gh-pages` CNAME (if `enable_github_pages=true`)

- **Cloudflare Pages**: Custom domain setup (if `pages_project` set)

- **Web3/IPFS**: `ipfs.<domain>` hostname (if
  `enable_ipfs_gateway=true`)

- **Mail**: MX, MTA-STS, TLS-RPT (if `enable_mail=true`)

- **SSH**: SSHFP records (if `enable_ssh=true`)

- **Tunnel**: `*.internal` CNAMEs (if `enable_tunnel=true`)

# How to Get Domain-Specific Values

## SSH Fingerprints

```bash
ssh-keygen -r yourdomain.org | grep "SSHFP 1 2" | awk '{print $6}'
```

## Cloudflare Tunnel ID

```bash
cloudflared tunnel list
```

## TLSA Certificate Hash

```bash
openssl s_client -connect mail.yourdomain.org:25 -starttls smtp </dev/null 2>/dev/null | \
  openssl x509 -pubkey -noout | \
  openssl pkey -pubin -outform DER | \
  openssl dgst -sha256 -binary | \
  xxd -p -u -c 64
```

# Managing Domains

```bash
# Add domains: edit domains.csv, then:
terraform apply

# Preview changes first:
terraform plan && terraform apply

# Remove a domain: delete row from CSV, then:
terraform apply
```

# Advanced: Targeting Specific Domains

```bash
terraform apply -target='cloudflare_record.www["wokelang.org"]'
terraform destroy -target='data.cloudflare_zones.all["example.com"]'
```

# Files

- `main.tf` — Terraform configuration (DNS resource definitions)

- `variables.tf` — Variable declarations

- `domains.csv` — **Your data** (edit this in Excel/LibreOffice)

- `terraform.tfvars` — Credentials (API token) — **do not commit!**

- `terraform.tfstate` — Terraform state (auto-generated, don’t edit)

# Security Note

Add `terraform.tfvars` to `.gitignore` if storing API tokens.

# Troubleshooting

## "No zones found"

Domain isn’t added to Cloudflare yet. Add it at:
<https://dash.cloudflare.com>

## "Permission denied"

API token needs: Zone:DNS:Edit, Account:Cloudflare Pages:Edit,
Zone:Read, Web3 Hostnames Write (if using IPFS).

## "Record already exists"

Manually delete conflicting record in Cloudflare dashboard, then re-run
`terraform` `apply`.

# Architecture

See <a href="TOPOLOGY.md" class="md">TOPOLOGY</a> for a visual
architecture map and completion dashboard.

Wondering how this works? See [EXPLAINME.adoc](EXPLAINME.adoc).

# License

SPDX-License-Identifier: CC-BY-SA-4.0\
See [LICENSE](LICENSE).
