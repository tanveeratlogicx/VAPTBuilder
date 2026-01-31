# WordPress VAPT Quick Reference Guide

A rapid implementation guide for all 21 WordPress security features.

## 🎯 Quick Navigation

- [Critical Features](#critical-features) (Implement First)
- [High Severity](#high-severity-features)
- [Medium Severity](#medium-severity-features)
- [Low Severity](#low-severity-features)
- [One-Command Tests](#one-command-tests)
- [Common Code Snippets](#common-code-snippets)

---

## Critical Features

### 1. SQL Injection Protection

**Quick Apache Rule:**
```apache
<IfModule mod_rewrite.c>
    RewriteCond %{QUERY_STRING} (union|select|insert|drop|update|delete) [NC]
    RewriteRule ^(.*)$ - [F,L]
</IfModule>
```

**Quick nginx Rule:**
```nginx
if ($args ~* "(union|select|insert|drop|update|delete)") {
    return 403;
}
```

**Quick Test:**
```bash
curl -I "https://example.com/?id=1' OR '1'='1"
# Expected: 403 Forbidden
```

---

### 2. Protect wp-config.php

**Apache:**
```apache
<Files wp-config.php>
    Require all denied
</Files>
```

**nginx:**
```nginx
location ~ /wp-config\.php {
    deny all;
}
```

**Test:**
```bash
curl -I https://example.com/wp-config.php
# Expected: 403 Forbidden
```

---

### 3. Disable File Editing

**wp-config.php:**
```php
define('DISALLOW_FILE_EDIT', true);
```

**Verify:** Login to wp-admin → Appearance → should see "File editing disabled"

---

## High Severity Features

### 4. XSS Protection

**Security Headers (Apache):**
```apache
Header always set X-XSS-Protection "1; mode=block"
Header always set Content-Security-Policy "default-src 'self';"
```

**Security Headers (nginx):**
```nginx
add_header X-XSS-Protection "1; mode=block" always;
add_header Content-Security-Policy "default-src 'self';" always;
```

**Test:**
```bash
curl -I "https://example.com/?search=<script>alert('XSS')</script>"
# Expected: Blocked or sanitized
```

---

### 5. Broken Authentication

**Rate Limit Login (nginx):**
```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=2r/m;

location = /wp-login.php {
    limit_req zone=login burst=2 nodelay;
}
```

**Test:**
```bash
# Try 5 rapid login attempts
for i in {1..5}; do
    curl -X POST https://example.com/wp-login.php
    sleep 1
done
# Expected: Some requests should be rate limited
```

---

## Medium Severity Features

### 6. Security Headers (Complete Set)

**Apache (.htaccess):**
```apache
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>
```

**Test All Headers:**
```bash
curl -I https://example.com | grep -i "x-frame\|x-content\|x-xss\|strict-transport"
```

---

### 7. Disable XML-RPC

**Apache:**
```apache
<Files xmlrpc.php>
    Require all denied
</Files>
```

**nginx:**
```nginx
location = /xmlrpc.php {
    deny all;
}
```

**Test:**
```bash
curl -X POST https://example.com/xmlrpc.php
# Expected: 403 Forbidden
```

---

### 8. Disable User Enumeration

**Apache:**
```apache
<IfModule mod_rewrite.c>
    RewriteCond %{QUERY_STRING} ^author=([0-9]*)
    RewriteRule .* - [F,L]
</IfModule>
```

**nginx:**
```nginx
if ($args ~* "author=\d+") {
    return 403;
}
```

**Test:**
```bash
curl -I "https://example.com/?author=1"
# Expected: 403 Forbidden
```

---

### 9. CSRF Protection

**functions.php:**
```php
// WordPress automatically includes nonces
// Verify they're used in forms:
wp_nonce_field('my_action', 'my_nonce');

// Verify in processing:
if (!wp_verify_nonce($_POST['my_nonce'], 'my_action')) {
    die('Security check failed');
}
```

---

### 10. Disable Directory Listing

**Apache:**
```apache
Options -Indexes
```

**nginx:**
```nginx
autoindex off;
```

**Test:**
```bash
curl https://example.com/wp-content/uploads/
# Expected: No directory listing shown
```

---

## Low Severity Features

### 11. Rate Limiting

**nginx (General):**
```nginx
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;

location / {
    limit_req zone=general burst=20 nodelay;
}
```

**Test:**
```bash
# Use Apache Bench to test
ab -n 100 -c 10 https://example.com/
# Check for rate limit responses
```

---

### 12. Cron Protection

**Apache (if using system cron):**
```apache
<Files wp-cron.php>
    Require all denied
</Files>
```

**wp-config.php (disable wp-cron):**
```php
define('DISABLE_WP_CRON', true);
```

**Add to system cron:**
```bash
*/15 * * * * wget -q -O - https://example.com/wp-cron.php?doing_wp_cron >/dev/null 2>&1
```

---

### 13. Disable REST API Users Endpoint

**nginx:**
```nginx
location ~ ^/wp-json/wp/v2/users {
    deny all;
}
```

**functions.php:**
```php
add_filter('rest_endpoints', function($endpoints) {
    if (isset($endpoints['/wp/v2/users'])) {
        unset($endpoints['/wp/v2/users']);
    }
    return $endpoints;
});
```

---

## One-Command Tests

### Security Headers Check
```bash
curl -I https://example.com | grep -i "x-frame-options\|x-content-type-options\|x-xss-protection\|strict-transport-security\|content-security-policy\|referrer-policy"
```

### SQL Injection Test
```bash
curl -I "https://example.com/?id=1' UNION SELECT NULL--"
```

### XSS Test
```bash
curl -I "https://example.com/?search=<script>alert('XSS')</script>"
```

### File Access Tests
```bash
# wp-config.php
curl -I https://example.com/wp-config.php

# readme.html
curl -I https://example.com/readme.html

# XML-RPC
curl -X POST https://example.com/xmlrpc.php

# .htaccess
curl -I https://example.com/.htaccess
```

### User Enumeration Tests
```bash
# Author archive
curl -I "https://example.com/?author=1"

# REST API users
curl https://example.com/wp-json/wp/v2/users
```

### WPScan (Comprehensive)
```bash
wpscan --url https://example.com \
    --enumerate vp,vt,u \
    --random-user-agent \
    --detection-mode aggressive
```

---

## Common Code Snippets

### Apache: Block by IP
```apache
<RequireAll>
    Require all denied
    Require ip 192.168.1.1
    Require ip 203.0.113.0/24
</RequireAll>
```

### nginx: Block by IP
```nginx
allow 192.168.1.1;
allow 203.0.113.0/24;
deny all;
```

### Force HTTPS (Apache)
```apache
<IfModule mod_rewrite.c>
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}/$1 [R=301,L]
</IfModule>
```

### Force HTTPS (nginx)
```nginx
server {
    listen 80;
    return 301 https://$server_name$request_uri;
}
```

### Disable PHP in Uploads (Apache)
```apache
<Directory "/var/www/html/wp-content/uploads/">
    <FilesMatch "\.php$">
        Require all denied
    </FilesMatch>
</Directory>
```

### Disable PHP in Uploads (nginx)
```nginx
location ~* ^/wp-content/uploads/.*\.php$ {
    deny all;
}
```

---

## Testing Checklist

Use this checklist after implementing security features:

### Basic Functionality
- [ ] Website loads correctly
- [ ] Login works properly
- [ ] Admin dashboard accessible
- [ ] Posts/pages display correctly
- [ ] Media uploads working
- [ ] Plugins functioning
- [ ] Theme features working

### Security Tests
- [ ] SQL injection blocked
- [ ] XSS attempts blocked
- [ ] Security headers present
- [ ] wp-config.php protected
- [ ] XML-RPC disabled/protected
- [ ] User enumeration blocked
- [ ] Directory listing disabled
- [ ] File editing disabled
- [ ] Rate limiting working
- [ ] HTTPS enforced

### Performance Tests
- [ ] Page load time acceptable
- [ ] No 500 errors
- [ ] No false positive blocks
- [ ] Rate limits not too aggressive
- [ ] Caching still working

---

## Emergency Rollback

If something breaks:

### Apache
```bash
# Rename .htaccess temporarily
mv .htaccess .htaccess.backup

# Test if site works
# If yes, the issue is in .htaccess

# Restore and debug
mv .htaccess.backup .htaccess
# Comment out sections one by one to find issue
```

### nginx
```bash
# Restore backup configuration
sudo cp /etc/nginx/sites-available/site.conf.backup /etc/nginx/sites-available/site.conf

# Test configuration
sudo nginx -t

# Reload
sudo systemctl reload nginx
```

### wp-config.php
```bash
# Use SFTP/FTP to download current file
# Edit locally and remove problem lines
# Upload corrected version
```

---

## Severity-Based Implementation Order

### Week 1 (Critical)
1. SQL Injection Protection
2. Protect wp-config.php
3. Disable File Editing
4. Disable PHP in Uploads
5. Force HTTPS

### Week 2 (High)
6. XSS Protection
7. Security Headers
8. Broken Authentication Protection
9. Access Control
10. Rate Limiting

### Week 3 (Medium)
11. Disable XML-RPC
12. Disable User Enumeration
13. CSRF Protection
14. Logging & Monitoring
15. Directory Listing

### Week 4 (Low/Hardening)
16. Disable REST API Users
17. Cron Protection
18. Input Validation
19. Remove Version Info
20. Block Bad Bots
21. Advanced CSP

---

## Online Testing Tools

- **Security Headers**: https://securityheaders.com/
- **Mozilla Observatory**: https://observatory.mozilla.org/
- **SSL Labs**: https://www.ssllabs.com/ssltest/
- **WPScan**: https://wpscan.com/
- **OWASP ZAP**: https://www.zaproxy.org/

---

## Log File Locations

### Apache
- Access: `/var/log/apache2/access.log`
- Error: `/var/log/apache2/error.log`

### nginx
- Access: `/var/log/nginx/access.log`
- Error: `/var/log/nginx/error.log`

### PHP
- Error: `/var/log/php8.1-fpm.log`

### WordPress
- Debug: `wp-content/debug.log` (if WP_DEBUG_LOG enabled)

---

## Quick Verification Commands

### Check Apache Modules
```bash
apache2ctl -M | grep -E "rewrite|headers"
```

### Check nginx Modules
```bash
nginx -V 2>&1 | grep -o with-http_[a-z_]*module
```

### Check PHP Version
```bash
php -v
```

### Check WordPress Version
```bash
wp core version
```

### Check File Permissions
```bash
# Should be 644 for files
find . -type f -exec stat -c "%a %n" {} \; | grep -v "^644"

# Should be 755 for directories
find . -type d -exec stat -c "%a %n" {} \; | grep -v "^755"
```

---

## Environment-Specific Notes

### Shared Hosting
- Limited .htaccess capabilities
- Cannot modify nginx config
- Use functions.php for most features
- Cannot use some Apache modules

### VPS/Dedicated
- Full control over server config
- Can optimize nginx/Apache fully
- Install security tools (fail2ban, ModSecurity)
- Implement advanced rate limiting

### Managed WordPress
- Hosting provider handles most security
- Limited configuration access
- Focus on application-level security
- Use approved plugins only

---

**Last Updated**: 2024-01-18  
**Quick Reference Version**: 1.0

---

For detailed implementations, see:
- [SKILL.md](../SKILL.md)
- [SQL Injection Example](../examples/sql-injection-protection.md)
- [Security Headers Example](../examples/security-headers.md)
- [Complete Templates](../resources/)
