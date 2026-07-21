#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Automatically detect and add new Cloudflare domains to domains.csv

set -e

if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
    echo "Error: Set CLOUDFLARE_API_TOKEN environment variable"
    exit 1
fi

echo "🔍 Checking for new domains in Cloudflare..."

# Get all zones from Cloudflare
CF_DOMAINS=$(curl -s -X GET 'https://api.cloudflare.com/client/v4/zones?per_page=100' \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H 'Content-Type: application/json' | \
  python3 -c "import sys,json; [print(z['name']) for z in json.load(sys.stdin)['result']]" 2>/dev/null || echo "")

if [ -z "$CF_DOMAINS" ]; then
    echo "❌ Failed to fetch domains from Cloudflare"
    exit 1
fi

# Get domains already in CSV
CSV_DOMAINS=$(tail -n +2 domains.csv | cut -d',' -f1 | sort)

# Find new domains
NEW_DOMAINS=""
while IFS= read -r domain; do
    if ! echo "$CSV_DOMAINS" | grep -q "^${domain}$"; then
        NEW_DOMAINS="${NEW_DOMAINS}${domain}\n"
    fi
done <<< "$CF_DOMAINS"

if [ -z "$NEW_DOMAINS" ]; then
    echo "✅ No new domains found. All domains already in domains.csv"
    exit 0
fi

echo "📝 Found new domains:"
echo -e "$NEW_DOMAINS"
echo ""
echo "Adding to domains.csv..."

# Add new domains to CSV
while IFS= read -r domain; do
    if [ -n "$domain" ]; then
        echo "${domain},hyperpolymath,,,,,,,,default,,false,false,false,false,false,false," >> domains.csv
        echo "  ✓ Added: $domain"
    fi
done <<< "$(echo -e "$NEW_DOMAINS")"

echo ""
echo "✅ domains.csv updated!"
echo ""
echo "Review the changes:"
echo "  git diff domains.csv"
echo ""
echo "Deploy to new domains:"
echo "  terraform plan    # Preview"
echo "  terraform apply   # Deploy"
