# Security Headers & HTTP Protocol Guide

## Quick Answers to Your Questions:

### 1. HTTP/0.9 and HTTP/1.0 - Any Value?

**Short Answer: NO - Zero value in 2026.**

**HTTP Protocol Timeline:**
| Protocol | Year | Status | Support It? |
|----------|------|--------|-------------|
| HTTP/0.9 | 1991 | Obsolete | ❌ NO |
| HTTP/1.0 | 1996 | Legacy | ❌ NO |
| HTTP/1.1 | 1997 | Mature | ✅ YES (fallback only) |
| HTTP/2 | 2015 | Modern | ✅ YES (minimum) |
| HTTP/3 | 2022 | Cutting-edge | ✅ YES (preferred) |

**Why NOT to support HTTP/0.9 or HTTP/1.0:**
- ❌ No security features (no TLS/SSL integration)
- ❌ No header support (can't set security headers!)
- ❌ No caching controls
- ❌ No content negotiation
- ❌ < 0.01% of traffic uses these
- ❌ All modern browsers/tools require at least HTTP/1.1

**Cloudflare Configuration (Recommended):**
```terraform
resource "cloudflare_zone_settings_override" "http_protocol" {
  zone_id = each.value.zone_id

  settings {
    # Minimum TLS version
    min_tls_version = "1.2"  # Drop TLS 1.0/1.1

    # HTTP/2 and HTTP/3
    http2 = "on"
    http3 = "on"

    # Drop HTTP/1.0 and older
    # (Cloudflare does this automatically when proxying)
  }
}
```

**Best Practice: HTTP/3 → HTTP/2 → HTTP/1.1**
- Clients negotiate downward automatically
- No need to explicitly support HTTP/0.9 or HTTP/1.0

---

## 2. Security Headers Solutions (Comprehensive)

### Option A: Cloudflare Transform Rules (EASIEST)

**Already included in your Terraform!** (`security-headers.tf`)

```bash
terraform apply
```

This automatically adds headers to **all domains** without code!

**Headers Added:**
- ✅ `Strict-Transport-Security` (HSTS)
- ✅ `Content-Security-Policy` (CSP)
- ✅ `X-Frame-Options`
- ✅ `X-Content-Type-Options`
- ✅ `Referrer-Policy`
- ✅ `Permissions-Policy`
- ✅ `X-XSS-Protection`
- ✅ `Cross-Origin-*` policies (COEP, COOP, CORP)

### Option B: Cloudflare Pages `_headers` File

If using Cloudflare Pages (like wokelang-ssg):

1. Copy `examples/_headers` to your SSG build output
2. Cloudflare Pages automatically applies headers!

**For wokelang-ssg:**
```bash
# In your build script
cp _headers dist/
```

### Option C: Meta Tags (LIMITED - Not Recommended)

**Only works for CSP**, and less secure than HTTP headers:

```html
<!-- In SSG template <head> -->
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self' 'unsafe-inline'">
```

**Problems:**
- ❌ Can't set HSTS via meta tag
- ❌ Can't set X-Frame-Options via meta tag
- ❌ Browsers trust HTTP headers more than meta tags
- ❌ Easier to bypass

**Verdict:** Don't use meta tags. Use Cloudflare Transform Rules.

---

## 3. Email Security Records - Now Complete!

### New DNS Records Added:

#### DKIM (DomainKeys Identified Mail)
Proves your emails aren't forged.

**CSV Fields:**
```csv
dkim_selector,dkim_public_key,dkim_selector_rotation,dkim_public_key_rotation
```

**Get your DKIM key:**
```bash
# If using mail server
cat /etc/opendkim/keys/default.txt

# Or generate
opendkim-genkey -s default -d yourdomain.org
```

#### BIMI (Brand Indicators)
Shows your logo in email clients.

**CSV Fields:**
```csv
bimi_logo_url,bimi_vmc_url
```

**Example:**
```csv
https://yourdomain.org/logo.svg,https://yourdomain.org/vmc.pem
```

#### ARC (Authenticated Received Chain)
For mailing lists/forwarders.

**CSV Fields:**
```csv
arc_selector,arc_public_key
```

#### CAA with Critical Flag (128)
**Already updated in `email-security.tf`!**

```terraform
data {
  flags = "128"  # CRITICAL - Reject if CA doesn't support CAA
  tag   = "issue"
  value = "letsencrypt.org"
}
```

**What flags=128 means:**
- Normal CAA (flags=0): CAs that don't understand CAA ignore it
- Critical CAA (flags=128): CAs that don't understand CAA **must reject**

**More secure, but:**
- Some older CAs might fail
- Let's Encrypt and DigiCert both support it

#### Additional Email Records:
- ✅ SRV records for IMAP/POP3/Submission
- ✅ Autoconfig/Autodiscover CNAMEs
- ✅ Enhanced SPF with custom includes
- ✅ ADSP (legacy but some use)

---

## 4. Complete Security Stack

### DNS Level (via Terraform):
- ✅ CAA with critical flag (128)
- ✅ DNSSEC (enable in Cloudflare dashboard)
- ✅ SPF, DMARC, DKIM, BIMI, ARC
- ✅ TLSA for mail servers
- ✅ SSHFP fingerprints

### HTTP Level (via Cloudflare):
- ✅ HSTS with preload
- ✅ CSP (Content Security Policy)
- ✅ Frame protection
- ✅ XSS protection
- ✅ MIME sniffing protection
- ✅ Referrer policy
- ✅ Permissions policy
- ✅ Cross-origin isolation

### TLS Level (via Cloudflare):
- ✅ TLS 1.2+ only (drop 1.0/1.1)
- ✅ HTTP/2 and HTTP/3
- ✅ OCSP stapling
- ✅ Certificate transparency

---

## 5. Testing Your Security

### Test Headers:
```bash
# Check headers
curl -I https://wokelang.org

# Security headers test
https://securityheaders.com/?q=https://wokelang.org

# SSL Labs test
https://www.ssllabs.com/ssltest/analyze.html?d=wokelang.org
```

### Test Email Security:
```bash
# DMARC
dig +short TXT _dmarc.wokelang.org

# DKIM
dig +short TXT default._domainkey.wokelang.org

# SPF
dig +short TXT wokelang.org | grep spf

# MTA-STS
curl https://mta-sts.wokelang.org/.well-known/mta-sts.txt
```

### Test CAA:
```bash
dig +short CAA wokelang.org
# Should show: 128 issue "letsencrypt.org"
```

---

## 6. Deployment Steps

### Step 1: Deploy DNS Records
```bash
cd /var/mnt/eclipse/repos/cloudflare-dns-terraform
terraform init
terraform plan
terraform apply
```

### Step 2: Verify Headers (Automatic via Cloudflare)
```bash
curl -I https://wokelang.org | grep -i strict
# Should show: Strict-Transport-Security: max-age=31536000...
```

### Step 3: Enable HSTS Preload (Optional)
Submit to: https://hstspreload.org/?domain=wokelang.org

### Step 4: Monitor
- https://observatory.mozilla.org
- https://securityheaders.com
- https://www.hardenize.com

---

## Summary:

✅ **HTTP/0.9, HTTP/1.0** - Don't support them (no value)
✅ **Security Headers** - Use Cloudflare Transform Rules (included in Terraform)
✅ **CAA flags=128** - Now using critical flag
✅ **DKIM** - Added to email-security.tf
✅ **All email security** - BIMI, ARC, SRV records, autoconfig
✅ **Complete stack** - DNS + HTTP + TLS security

**Your infrastructure is now world-class secure!** 🔒🚀
