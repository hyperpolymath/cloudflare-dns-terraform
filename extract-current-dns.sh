#!/usr/bin/env bash
# SPDX-License-Identifier: PMPL-1.0-or-later
# Extract current Cloudflare DNS records to help populate domains.csv

set -e

if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
    echo "Error: Set CLOUDFLARE_API_TOKEN environment variable"
    echo "export CLOUDFLARE_API_TOKEN='your-token-here'"
    exit 1
fi

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain>"
    echo "Example: $0 wokelang.org"
    exit 1
fi

echo "Fetching DNS records for $DOMAIN..."

# Get zone ID
ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" | \
  python3 -c "import sys, json; data=json.load(sys.stdin); print(data['result'][0]['id'] if data['result'] else '')")

if [ -z "$ZONE_ID" ]; then
    echo "Error: Zone not found for $DOMAIN"
    exit 1
fi

echo "Zone ID: $ZONE_ID"
echo ""
echo "Current DNS Records:"
echo "===================="

# Get all records
curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for record in data['result']:
    print(f\"{record['type']:10} {record['name']:40} -> {record.get('content', '')} (Proxied: {record.get('proxied', False)})\")
"

echo ""
echo "Suggested CSV Entry Template:"
echo "=============================="
echo "$DOMAIN,hyperpolymath,,,,,,,,default,,false,false,false,false,"
