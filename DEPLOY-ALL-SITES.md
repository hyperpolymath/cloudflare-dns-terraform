# Deploy to ALL Your Websites - Complete Guide

## Goal: Set up security + DNS for ALL your domains

This will:
- ✅ Add security headers to ALL domains (FREE)
- ✅ Standardize DNS records across ALL domains
- ✅ Optionally add consent/capability gates
- ✅ Zero cost (uses FREE Transform Rules)

---

## Step 1: Get All Your Domains

### Option A: Via Cloudflare Dashboard
1. Go to: https://dash.cloudflare.com
2. You'll see a list of all domains
3. Copy the list to a text file

### Option B: Via API
```bash
export CLOUDFLARE_API_TOKEN='bEy8xJ8vDmHLh0wMcC52Z7Pyw42bQDasPiW7fQzc'

curl -s "https://api.cloudflare.com/client/v4/zones?per_page=100" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" | \
  python3 -c "import sys,json;[print(z['name']) for z in json.load(sys.stdin)['result']]"
```

### Option C: Automated Script
```bash
./generate-domains-csv.sh
```

---

## Step 2: Edit domains.csv

Open `domains.csv` in Excel or any spreadsheet app.

### Quick Template (copy this for each domain):

```csv
domain,github_user,github_repo,tunnel_id,mx_primary,mx_secondary,admin_email,ssh_fp_sha256,ssh_fp_sha256_backup,dkim_selector,tlsa_cert_hash,enable_mail,enable_tunnel,enable_ssh,enable_github_pages,enable_consent_gate,enable_capability_gate,pages_project
example.com,hyperpolymath,,,,,,,,default,,false,false,false,false,false,false,
```

### Fill in these columns:

| Column | Value | Notes |
|--------|-------|-------|
| `domain` | Your domain name | e.g., `wokelang.org` |
| `github_user` | `hyperpolymath` | Your GitHub username |
| `github_repo` | Repo name | If using GitHub Pages |
| `admin_email` | `jonathan.jewell@open.ac.uk` | For security contacts |
| `enable_github_pages` | `true` or `false` | If using GitHub Pages |
| `enable_consent_gate` | `false` | Keep false initially (FREE) |
| `enable_capability_gate` | `false` | Keep false initially (FREE) |
| `pages_project` | Project name | If using Cloudflare Pages |

### Leave blank:
- `tunnel_id` - Unless using Cloudflare Tunnel
- `mx_*` - Unless using email
- `ssh_*` - Unless using SSH
- `dkim_*` - Unless using email

---

## Step 3: Preview Changes (DRY RUN)

```bash
cd /var/mnt/eclipse/repos/cloudflare-dns-terraform

# Set credentials
export CLOUDFLARE_API_TOKEN='bEy8xJ8vDmHLh0wMcC52Z7Pyw42bQDasPiW7fQzc'

# Or use terraform.tfvars
cp terraform.tfvars.example terraform.tfvars
nano terraform.tfvars

# Initialize Terraform
terraform init

# Preview what will be created (NO CHANGES YET)
terraform plan
```

**Review the output carefully!**

You should see:
- `+` = Will create (new records)
- `~` = Will modify (existing records)
- `-` = Will delete (old records)

---

## Step 4: Deploy to ALL Domains

```bash
# Apply changes to ALL domains
terraform apply

# Type 'yes' when prompted
```

This will:
1. Add security headers to ALL domains (via Transform Rules - FREE)
2. Create standard DNS records (www, cdn, static, assets, etc.)
3. Add CAA records with critical flag (128)
4. Set up Cloudflare Pages domains (if specified)

---

## Step 5: Verify Security Headers

Test any domain:

```bash
# Check headers
curl -I https://your-domain.com

# Should see:
# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
# Content-Security-Policy: ...
# X-Frame-Options: DENY
# etc.
```

Online tests:
- https://securityheaders.com/?q=https://your-domain.com
- https://www.ssllabs.com/ssltest/analyze.html?d=your-domain.com

---

## Step 6: Deploy Workers (OPTIONAL - Only if Needed)

**Skip this if you don't need consent/capability gates** (saves worker requests)

### If you want consent gates:

1. Edit `domains.csv` and set `enable_consent_gate=true` for domains that need it
2. Deploy worker:
```bash
cd workers/
wrangler deploy consent-aware-http.js
```

3. Apply Terraform:
```bash
terraform apply
```

### If you want capability gates:

1. Edit `domains.csv` and set `enable_capability_gate=true` for domains with APIs
2. Deploy worker:
```bash
wrangler deploy http-capability-gateway.js
```

3. Apply Terraform:
```bash
terraform apply
```

---

## Cost Breakdown (All Domains):

### Guaranteed FREE:
- ✅ Transform Rules (security headers) - **FREE unlimited**
- ✅ DNS records - **FREE unlimited** (Cloudflare DNS)
- ✅ Cloudflare Pages - **FREE** (500 builds/month)

### Potentially FREE (if under limits):
- ⚠️ Consent gates - **FREE** if < 100k requests/day total across ALL domains
- ⚠️ Capability gates - **FREE** if < 100k requests/day total across ALL domains

### Example with 10 domains:

```
Domain 1: 5,000 requests/day (mostly static → Transform Rules = FREE)
Domain 2: 3,000 requests/day (mostly static → Transform Rules = FREE)
Domain 3: 2,000 requests/day (mostly static → Transform Rules = FREE)
... (7 more domains)
Total: 30,000 requests/day

Workers only needed for:
- Analytics endpoints: ~1,000 requests/day (consent gate)
- API endpoints: ~500 requests/day (capability gate)

Total worker requests: ~1,500/day = 45,000/month
FREE tier: 3,000,000/month

Cost: £0/month ✅
```

---

## What Gets Applied to Each Domain:

### Always (FREE via Transform Rules):
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- CAA records (Let's Encrypt + DigiCert, flags=128)
- SPF record
- DMARC record

### Standard DNS (FREE):
- `www` → CNAME to root (proxied)
- `static` → CNAME to root (proxied)
- `assets` → CNAME to root (proxied)
- `cdn` → CNAME to root (proxied)
- `api` → CNAME to root (proxied)
- `status` → CNAME to root (proxied)
- `ci` → CNAME to root (proxied)
- Plus 10+ more standard subdomains

### Optional (if enabled):
- GitHub Pages CNAME (if `enable_github_pages=true`)
- Cloudflare Pages custom domain (if `pages_project` set)
- MX/DKIM records (if `enable_mail=true`)
- SSH fingerprints (if `enable_ssh=true`)
- Cloudflare Tunnel (if `enable_tunnel=true`)
- Consent gate (if `enable_consent_gate=true`)
- Capability gate (if `enable_capability_gate=true`)

---

## Rollback Plan

If something goes wrong:

```bash
# See what Terraform created
terraform show

# Destroy specific domain
terraform destroy -target='cloudflare_record.www["problem-domain.com"]'

# Destroy everything (CAREFUL!)
terraform destroy
```

**Note:** Terraform tracks state in `terraform.tfstate` - don't delete this file!

---

## Monitoring

### Set up alerts to avoid surprise charges:

1. Go to: https://dash.cloudflare.com/[account]/notifications
2. Create alert: "Workers Requests Threshold"
3. Set threshold: 80,000 requests/day (80% of free tier)

### Check usage:

```bash
# Via dashboard
https://dash.cloudflare.com/[account]/workers/overview

# Via CLI
wrangler tail consent-aware-http --status
```

---

## Maintenance

### Adding a new domain:

1. Add row to `domains.csv`
2. Run `terraform apply`
3. Done!

### Removing a domain:

1. Delete row from `domains.csv`
2. Run `terraform apply`
3. Terraform will remove all DNS records

### Updating all domains:

1. Edit `domains.csv` (change columns for all domains)
2. Run `terraform apply`
3. Changes apply to all domains instantly

---

## Summary

**This will set up world-class security across ALL your websites:**

✅ Security headers (HSTS, CSP, etc.)
✅ CAA with critical flag (128)
✅ Standard DNS structure
✅ Cloudflare Pages support
✅ GitHub Pages support
✅ Optional consent gates
✅ Optional capability gates
✅ **All FREE** (unless you exceed 100k requests/day)

**Total cost: £0/month for typical usage** 🎉

Ready to deploy? Run:
```bash
terraform apply
```
