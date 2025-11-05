# Certificate Revocation Setup Guide

This guide explains how to set up automatic certificate revocation checking for the RHEL IDM Certificate Plugin.

## Overview

With certificate revocation enabled:
- ✅ Certificates issued contain CRL Distribution Point URLs
- ✅ Certificates contain OCSP Responder URLs
- ✅ TAK Server can check if certificates have been revoked
- ✅ Revoked users automatically lose access

## Architecture

```
ATAK User → TAK Server → Checks CRL/OCSP → RHEL IDM
                ↓
         Revoked? → Deny connection
         Valid? → Allow connection
```

---

## Part 1: Configure RHEL IDM for CRL Publishing

### Step 1: Enable CRL Generation on RHEL IDM

On your RHEL IDM server:

```bash
# Check current CRL status
ipa-crlgen-manage status

# Enable CRL generation
ipa-crlgen-manage enable

# Start CRL generation
systemctl restart ipa-crlgen

# Verify CRL is being generated
ls -lh /var/lib/pki/pki-tomcat/ca/crl/MasterCRL.bin
```

### Step 2: Publish CRL via HTTP

The CRL needs to be accessible via HTTP for TAK Server to download it.

**Option A: Use IPA's Built-in HTTP Server (Recommended)**

```bash
# CRL is automatically published at:
# http://your-idm-server.example.com/ipa/crl/MasterCRL.bin

# Verify it's accessible
curl -I http://your-idm-server.example.com/ipa/crl/MasterCRL.bin

# Should return: HTTP/1.1 200 OK
```

**Option B: Manual HTTP Configuration**

If the built-in path isn't working, manually configure Apache:

```bash
# Create symlink in Apache document root
sudo mkdir -p /var/www/html/crl
sudo ln -s /var/lib/pki/pki-tomcat/ca/crl/MasterCRL.bin /var/www/html/crl/MasterCRL.bin

# Set permissions
sudo chmod 644 /var/lib/pki/pki-tomcat/ca/crl/MasterCRL.bin
sudo chown apache:apache /var/www/html/crl

# Restart Apache
sudo systemctl restart httpd

# Test
curl -I http://your-idm-server.example.com/crl/MasterCRL.bin
```

### Step 3: Enable OCSP Responder (Optional but Recommended)

OCSP provides real-time certificate status checking (faster than CRL).

```bash
# Enable OCSP on RHEL IDM
ipa-certmonger status

# OCSP is available at:
# http://your-idm-server.example.com/ca/ocsp

# Test OCSP responder
openssl ocsp -issuer /etc/ipa/ca.crt \
  -url http://your-idm-server.example.com/ca/ocsp \
  -resp_text
```

### Step 4: Configure Automatic CRL Updates

Set up periodic CRL updates to ensure it stays current:

```bash
# Add cron job for CRL update (every hour)
sudo crontab -e

# Add this line:
0 * * * * /usr/bin/ipa-crlgen-run

# Or use systemd timer
sudo systemctl enable ipa-crlgen.timer
sudo systemctl start ipa-crlgen.timer
```

---

## Part 2: Configure the Plugin

### Step 1: Update Plugin Configuration

Edit `/opt/tak/conf/plugins/tak.server.plugins.rhelidmcert.RhelIdmCertificatePlugin.yaml`:

```yaml
certificate:
  # CRL Configuration
  crl_distribution_point: "http://idm.example.com/ipa/crl/MasterCRL.bin"
  enable_crl: true

  # OCSP Configuration
  ocsp_responder_url: "http://idm.example.com/ca/ocsp"
  enable_ocsp: true

  # Other certificate settings
  key_size: 2048
  validity_days: 365
  default_organization: "Your Organization"
```

**Important URLs:**
- Replace `idm.example.com` with your actual RHEL IDM server hostname
- Use `http://` not `https://` for CRL/OCSP (required by certificate standards)
- Ensure these URLs are accessible from TAK Server

### Step 2: Restart TAK Server

```bash
# Restart to load new configuration
sudo systemctl restart takserver

# Verify plugin loaded with revocation support
sudo tail -f /opt/tak/logs/takserver.log | grep -i "revocation"

# You should see:
# "Certificate revocation extensions added to CSR (CRL: true, OCSP: true)"
```

---

## Part 3: Configure TAK Server for Revocation Checking

TAK Server needs to be configured to actually CHECK the revocation information.

### Step 1: Enable CRL Checking in TAK Server

Edit `/opt/tak/CoreConfig.xml`:

```xml
<Configuration>
    <security>
        <tls>
            <!-- Enable CRL checking -->
            <enableCRLCheck>true</enableCRLCheck>

            <!-- CRL cache update interval (seconds) -->
            <crlCacheInterval>3600</crlCacheInterval>

            <!-- Fail if CRL unavailable (strict mode) -->
            <requireCRLForValidation>true</requireCRLForValidation>
        </tls>
    </security>
</Configuration>
```

### Step 2: Configure Trust Store

TAK Server needs to trust the RHEL IDM CA:

```bash
# Import RHEL IDM CA certificate to TAK Server truststore
sudo keytool -import \
  -alias rhel-idm-ca \
  -file /path/to/rhel-idm-ca.crt \
  -keystore /opt/tak/certs/files/truststore-root.jks \
  -storepass atakatak

# Verify import
sudo keytool -list \
  -keystore /opt/tak/certs/files/truststore-root.jks \
  -storepass atakatak \
  | grep rhel-idm-ca
```

### Step 3: Configure Java Security for CRL

Edit `/opt/tak/java_config.sh` (or TAK Server's Java options):

```bash
# Add these Java options
JAVA_OPTS="$JAVA_OPTS -Dcom.sun.security.enableCRLDP=true"
JAVA_OPTS="$JAVA_OPTS -Dcom.sun.net.ssl.checkRevocation=true"
JAVA_OPTS="$JAVA_OPTS -Dcom.sun.security.enableAIAcaIssuers=true"

export JAVA_OPTS
```

### Step 4: Restart TAK Server

```bash
sudo systemctl restart takserver
```

---

## Part 4: Testing Certificate Revocation

### Test 1: Issue a Certificate

```bash
# Have an ATAK user enroll and get a certificate
# User should successfully connect to TAK Server
```

### Test 2: Revoke the Certificate

On RHEL IDM server:

```bash
# List certificates for the user
ipa cert-find --user=testuser

# Revoke the certificate (using serial number from above)
ipa cert-revoke 1234567 --revocation-reason=4

# Verify revocation
ipa cert-show 1234567

# Should show: Revoked: True
```

### Test 3: Generate New CRL

```bash
# Force CRL regeneration
sudo /usr/bin/ipa-crlgen-run

# Verify CRL contains the revoked certificate
openssl crl -in /var/lib/pki/pki-tomcat/ca/crl/MasterCRL.bin \
  -inform DER -text -noout | grep -A5 "Serial Number: 1234567"
```

### Test 4: Verify TAK Server Blocks Revoked User

```bash
# Wait for TAK Server to update its CRL cache (default: 1 hour)
# Or restart TAK Server to force immediate CRL download

# User should now be DENIED connection
# Check TAK Server logs:
sudo tail -f /opt/tak/logs/takserver.log | grep -i revoked

# Should see: "Certificate has been revoked"
```

---

## Part 5: Troubleshooting

### Issue: CRL Not Accessible

```bash
# Test CRL URL from TAK Server
curl -v http://idm.example.com/ipa/crl/MasterCRL.bin

# Should return HTTP 200 and binary data
# If 404: Check CRL publishing configuration
# If connection refused: Check firewall rules
```

### Issue: TAK Server Not Checking CRL

```bash
# Enable debug logging in TAK Server
# Edit /opt/tak/CoreConfig.xml
<log>
    <level>DEBUG</level>
</log>

# Restart and check logs
sudo systemctl restart takserver
sudo tail -f /opt/tak/logs/takserver.log | grep -i crl
```

### Issue: Certificates Don't Contain CRL Extension

```bash
# Check a generated certificate
openssl x509 -in user_cert.pem -text -noout | grep -A5 "CRL Distribution"

# If not present:
# 1. Verify plugin configuration (enable_crl: true)
# 2. Check plugin logs for errors
# 3. Verify RHEL IDM is honoring CSR extension requests
```

### Issue: OCSP Not Working

```bash
# Test OCSP directly
openssl ocsp \
  -issuer /etc/ipa/ca.crt \
  -cert user_cert.pem \
  -url http://idm.example.com/ca/ocsp \
  -resp_text

# Should return: Response verify OK
# If fails: Check OCSP responder is running on RHEL IDM
```

---

## Part 6: Operational Procedures

### Revoking a User's Certificate

1. **Identify the certificate serial number:**
   ```bash
   ipa cert-find --user=username
   ```

2. **Revoke the certificate:**
   ```bash
   ipa cert-revoke <serial> --revocation-reason=4
   ```

   Revocation reasons:
   - 0: Unspecified
   - 1: Key compromise
   - 2: CA compromise
   - 3: Affiliation changed
   - 4: Superseded (use this for normal revocations)
   - 5: Cessation of operation
   - 6: Certificate hold (temporary suspension)

3. **Update CRL:**
   ```bash
   sudo /usr/bin/ipa-crlgen-run
   ```

4. **Verify revocation:**
   - CRL update takes effect in ~1 hour (or restart TAK Server)
   - OCSP provides immediate status update

### Unrevoking a Certificate (Certificate Hold)

If you used reason 6 (Certificate Hold), you can unrevoke:

```bash
ipa cert-remove-hold <serial>
```

### Monitoring CRL Status

```bash
# Check CRL age
stat /var/lib/pki/pki-tomcat/ca/crl/MasterCRL.bin

# View CRL contents
openssl crl -in /var/lib/pki/pki-tomcat/ca/crl/MasterCRL.bin \
  -inform DER -text -noout | less

# Count revoked certificates
openssl crl -in /var/lib/pki/pki-tomcat/ca/crl/MasterCRL.bin \
  -inform DER -text -noout | grep "Serial Number" | wc -l
```

---

## Summary

✅ **What You've Configured:**
1. RHEL IDM publishes CRLs via HTTP
2. RHEL IDM provides OCSP responder
3. Plugin adds CRL/OCSP info to certificates
4. TAK Server checks revocation before allowing connections

✅ **How It Works:**
1. User gets certificate with CRL/OCSP URLs embedded
2. TAK Server downloads CRL periodically (or checks OCSP)
3. When user connects, TAK Server verifies certificate isn't revoked
4. Revoked users are automatically denied access

✅ **Revocation Timing:**
- **OCSP**: Real-time (immediate)
- **CRL**: Cached (default 1 hour, configurable)

✅ **Best Practices:**
- Use OCSP for real-time checking (faster)
- Keep CRL as backup (more reliable)
- Monitor CRL generation (alert if stale)
- Regular testing of revocation workflow
