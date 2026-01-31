# Quick Start - Deploy to Your 26 Domains

## Step 1: List Your Domains

Go to https://dash.cloudflare.com and copy all 26 domain names.

## Step 2: Fill domains.csv

Open `domains.csv` in Excel and add one row per domain:

```csv
domain,github_user,github_repo,tunnel_id,mx_primary,mx_secondary,admin_email,ssh_fp_sha256,ssh_fp_sha256_backup,dkim_selector,tlsa_cert_hash,enable_mail,enable_tunnel,enable_ssh,enable_github_pages,enable_consent_gate,enable_capability_gate,pages_project
wokelang.org,hyperpolymath,wokelang,,,,,,,default,,false,false,false,false,false,false,wokelang
domain2.com,hyperpolymath,,,,,,,,default,,false,false,false,false,false,false,
domain3.com,hyperpolymath,,,,,,,,default,,false,false,false,false,false,false,
... (add all 26 domains)
```

**Quick fill:** Just change the domain name, leave everything else as defaults!

## Step 3: Deploy

```bash
cd /var/mnt/eclipse/repos/cloudflare-dns-terraform

# Set API token
export CLOUDFLARE_API_TOKEN='bEy8xJ8vDmHLh0wMcC52Z7Pyw42bQDasPiW7fQzc'

# Deploy
terraform init
terraform plan    # Preview
terraform apply   # Deploy!
```

## Cost: FREE

All 26 domains will use Transform Rules (FREE unlimited) for security headers.

No workers = No cost! 🎉
