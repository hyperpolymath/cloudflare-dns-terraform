#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Generate domains.csv from all Cloudflare zones in your account
# This will replace existing domains.csv with ALL your domains

set -e

if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
    echo "Error: Set CLOUDFLARE_API_TOKEN environment variable"
    echo "export CLOUDFLARE_API_TOKEN='your-api-token-here'"
    exit 1
fi

echo "🔍 Fetching all domains from Cloudflare..."

# Get all zones
ZONES=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?per_page=100" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json")

# Extract domain names
DOMAINS=$(echo "$ZONES" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if data['success']:
    for zone in data['result']:
        print(zone['name'])
else:
    print('Error:', data['errors'], file=sys.stderr)
    sys.exit(1)
")

if [ -z "$DOMAINS" ]; then
    echo "❌ No domains found in Cloudflare account"
    exit 1
fi

echo "✅ Found $(echo "$DOMAINS" | wc -l) domains"
echo ""

# Create CSV header
CSV_FILE="domains.csv"
echo "Writing to $CSV_FILE..."

cat > "$CSV_FILE" << 'EOF'
domain,github_user,github_repo,tunnel_id,mx_primary,mx_secondary,admin_email,ssh_fp_sha256,ssh_fp_sha256_backup,dkim_selector,tlsa_cert_hash,enable_mail,enable_tunnel,enable_ssh,enable_github_pages,enable_consent_gate,enable_capability_gate,enable_ipfs_gateway,ipfs_dnslink,pages_project
EOF

# Add each domain with defaults
while IFS= read -r domain; do
    echo "${domain},hyperpolymath,,,,,,,,default,,false,false,false,false,false,false,false,," >> "$CSV_FILE"
    echo "  ✓ Added: $domain"
done <<< "$DOMAINS"

echo ""
echo "✅ Generated $CSV_FILE with $(echo "$DOMAINS" | wc -l) domains"
echo ""
echo "Next steps:"
echo "1. Edit domains.csv to customize settings per domain"
echo "2. Run: terraform plan"
echo "3. Run: terraform apply"
echo ""
echo "COST: FREE (using Transform Rules for headers, workers optional)"
