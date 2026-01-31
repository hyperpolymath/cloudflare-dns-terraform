# Cloudflare DNS Management via Terraform

Infrastructure-as-code for managing DNS records across all hyperpolymath domains.

## Features

- ✅ Manage **unlimited domains** from single CSV/Excel file
- ✅ **Consistent DNS structure** across all domains
- ✅ **Version controlled** changes
- ✅ **Preview before apply** (see exactly what will change)
- ✅ **Bulk updates** (change all domains at once)
- ✅ **Domain-specific customization** (keys, tunnel IDs, etc.)

## Quick Start

### 1. Install Terraform

```bash
# macOS
brew install terraform

# Linux
wget https://releases.hashicorp.com/terraform/1.7.0/terraform_1.7.0_linux_amd64.zip
unzip terraform_1.7.0_linux_amd64.zip
sudo mv terraform /usr/local/bin/
```

### 2. Set Up Credentials

```bash
# Copy example file
cp terraform.tfvars.example terraform.tfvars

# Edit with your API token
nano terraform.tfvars
```

**terraform.tfvars:**
```hcl
cloudflare_api_token  = "bEy8xJ8vDmHLh0wMcC52Z7Pyw42bQDasPiW7fQzc"
cloudflare_account_id = "b72dd54ed3ee66088950c82e0301edbb"
```

### 3. Add Your Domains

Edit `domains.csv` (open in Excel or any spreadsheet):

| Column | Description | Example |
|--------|-------------|---------|
| `domain` | Domain name | `wokelang.org` |
| `github_user` | GitHub username | `hyperpolymath` |
| `github_repo` | GitHub repo name | `wokelang` |
| `tunnel_id` | Cloudflare Tunnel ID | `abc123-def456` |
| `mx_primary` | Primary mail server | `mail.wokelang.org` |
| `mx_secondary` | Secondary mail server | `backup.mail.wokelang.org` |
| `admin_email` | Admin email | `jonathan.jewell@open.ac.uk` |
| `ssh_fp_sha256` | SSH fingerprint (SHA256) | `sha256:ABC123...` |
| `ssh_fp_sha256_backup` | Backup SSH fingerprint | `sha256:DEF456...` |
| `dkim_selector` | DKIM selector | `default` |
| `tlsa_cert_hash` | TLSA certificate hash | `d2abde240d7c...` |
| `enable_mail` | Enable MX records | `true`/`false` |
| `enable_tunnel` | Enable Cloudflare Tunnel | `true`/`false` |
| `enable_ssh` | Enable SSHFP records | `true`/`false` |
| `enable_github_pages` | Enable GitHub Pages CNAME | `true`/`false` |
| `pages_project` | Cloudflare Pages project name | `wokelang` |

### 4. Deploy

```bash
# Initialize Terraform
terraform init

# Preview changes (DRY RUN)
terraform plan

# Apply changes
terraform apply
```

## DNS Records Created

### For EVERY Domain:
- `www` → CNAME to root (proxied)
- `static` → CNAME to root (proxied)
- `assets` → CNAME to root (proxied)
- `cdn` → CNAME to root (proxied)
- `discourse` → CNAME to root (for forums)
- `zulip` → CNAME to root (for chat)
- `members` → CNAME to root (members area)
- `ci` → CNAME to root (CI/CD status)
- `status` → CNAME to root (status page)
- `logs` → CNAME to root (logs)
- `api` → CNAME to root (API gateway)
- `auth` → CNAME to root (auth service)
- `wasm` → CNAME to root (WASM proxy)
- `linkedin` → CNAME to root
- `rss` → CNAME to root
- SPF TXT record
- DMARC TXT record
- CAA records (Let's Encrypt, DigiCert, iodef)

### Conditional (based on CSV flags):
- **GitHub Pages:** `gh-pages` CNAME (if `enable_github_pages=true`)
- **Cloudflare Pages:** Custom domain setup (if `pages_project` set)
- **Mail:** MX, MTA-STS, TLS-RPT (if `enable_mail=true`)
- **SSH:** SSHFP records (if `enable_ssh=true`)
- **Tunnel:** `*.internal` CNAMEs (if `enable_tunnel=true`)

## How to Get Domain-Specific Values

### SSH Fingerprints

```bash
# On your server
ssh-keygen -r yourdomain.org | grep "SSHFP 1 2"
# Output: yourdomain.org IN SSHFP 1 2 <fingerprint>

# Extract just the fingerprint
ssh-keygen -r yourdomain.org | grep "SSHFP 1 2" | awk '{print $6}'
```

### Cloudflare Tunnel ID

```bash
# List tunnels
cloudflared tunnel list

# Or via API
curl -s -X GET "https://api.cloudflare.com/client/v4/accounts/YOUR_ACCOUNT_ID/cfd_tunnel" \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

### TLSA Certificate Hash

```bash
# Get certificate hash for SMTP
openssl s_client -connect mail.yourdomain.org:25 -starttls smtp </dev/null 2>/dev/null | \
  openssl x509 -pubkey -noout | \
  openssl pkey -pubin -outform DER | \
  openssl dgst -sha256 -binary | \
  xxd -p -u -c 64
```

## Adding More Domains

Just add a new row to `domains.csv` and run:

```bash
terraform apply
```

Terraform will only create records for the new domain, leaving existing ones untouched!

## Updating Existing Domains

Edit the CSV, then:

```bash
terraform plan  # Preview changes
terraform apply # Apply changes
```

## Removing a Domain

Delete the row from CSV, then:

```bash
terraform apply
```

Terraform will destroy all DNS records for that domain.

## Advanced: Targeting Specific Domains

```bash
# Apply changes only to wokelang.org
terraform apply -target='cloudflare_record.www["wokelang.org"]'

# Destroy only one domain's records
terraform destroy -target='data.cloudflare_zones.all["example.com"]'
```

## Excel Workflow

1. Open `domains.csv` in Excel
2. Add/edit domains as spreadsheet rows
3. **File → Save As → CSV (Comma delimited) (*.csv)**
4. Run `terraform apply`

## Terraform State

Terraform tracks what it created in `terraform.tfstate`. **Do NOT delete this file!**

To version control safely:
```bash
git add domains.csv main.tf variables.tf
git add terraform.tfvars  # WARNING: Contains API token!
git commit -m "Add new domain"
```

**Security Note:** Add `terraform.tfvars` to `.gitignore` if storing API tokens!

## Troubleshooting

### "No zones found"
Domain isn't added to Cloudflare yet. Add it at: https://dash.cloudflare.com

### "Permission denied"
API token needs these permissions:
- **Zone:DNS:Edit**
- **Account:Cloudflare Pages:Edit**
- **Zone:Read**

### "Record already exists"
Manually delete conflicting record in Cloudflare dashboard, then re-run `terraform apply`.

## Files

- `main.tf` - Terraform configuration (DNS resource definitions)
- `variables.tf` - Variable declarations
- `domains.csv` - **Your data** (edit this in Excel)
- `terraform.tfvars` - Credentials (API token)
- `terraform.tfstate` - Terraform state (auto-generated, don't edit)

## Example: Full wokelang.org Entry

```csv
domain,github_user,github_repo,tunnel_id,mx_primary,mx_secondary,admin_email,ssh_fp_sha256,ssh_fp_sha256_backup,dkim_selector,tlsa_cert_hash,enable_mail,enable_tunnel,enable_ssh,enable_github_pages,pages_project
wokelang.org,hyperpolymath,wokelang,abc123-tunnel,mail.wokelang.org,backup.mail.wokelang.org,jonathan.jewell@open.ac.uk,E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855,,default,d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971,true,true,true,false,wokelang
```

## Next Steps

1. **Populate domains.csv** with all your domains
2. **Get domain-specific values** (SSH fingerprints, tunnel IDs, etc.)
3. **Run terraform plan** to preview
4. **Run terraform apply** to deploy!

Your entire DNS infrastructure will be code! 🚀
