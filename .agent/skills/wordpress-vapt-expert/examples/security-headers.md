# Security Headers - Complete Implementation Example

**Feature:** HTTP Security Headers  
**Severity:** Medium  
**OWASP:** A05:2021 - Security Misconfiguration

---

## Overview

This example demonstrates a comprehensive implementation of HTTP security headers for WordPress sites. Security headers are HTTP response headers that instruct browsers to implement additional security protections.

## Headers Implemented

1. **X-Frame-Options** - Prevents clickjacking attacks
2. **X-Content-Type-Options** - Prevents MIME sniffing
3. **X-XSS-Protection** - Enables browser XSS filters
4. **Strict-Transport-Security (HSTS)** - Enforces HTTPS
5. **Content-Security-Policy (CSP)** - Prevents XSS and code injection
6. **Referrer-Policy** - Controls referrer information
7. **Permissions-Policy** - Controls browser features

---

## Apache Implementation (.htaccess)

**File Path:** `/public_html/.htaccess`

```apache
# ============================================================================
# HTTP Security Headers - Apache Configuration
# Severity: Medium | OWASP: A05:2021
# ============================================================================

<IfModule mod_headers.c>

    # ----------------------------------------------------------------------
    # X-Frame-Options: Prevents clickjacking attacks
    # ----------------------------------------------------------------------
    # SAMEORIGIN: Allows framing from same origin only
    # DENY: Completely disables framing
    # ALLOW-FROM https://example.com: Allows specific domain
    
    Header always set X-Frame-Options "SAMEORIGIN" env=!skip_headers
    
    # Alternative for complete protection:
    # Header always set X-Frame-Options "DENY" env=!skip_headers
    
    
    # ----------------------------------------------------------------------
    # X-Content-Type-Options: Prevents MIME type sniffing
    # ----------------------------------------------------------------------
    # nosniff: Browser must respect declared Content-Type
    
    Header always set X-Content-Type-Options "nosniff" env=!skip_headers
    
    
    # ----------------------------------------------------------------------
    # X-XSS-Protection: Enables browser XSS filtering
    # ----------------------------------------------------------------------
    # 1; mode=block: Enable XSS filter and block page if attack detected
    # Note: This header is legacy; CSP is preferred for modern browsers
    
    Header always set X-XSS-Protection "1; mode=block" env=!skip_headers
    
    
    # ----------------------------------------------------------------------
    # Strict-Transport-Security (HSTS): Forces HTTPS
    # ----------------------------------------------------------------------
    # max-age=31536000: Remember for 1 year
    # includeSubDomains: Apply to all subdomains
    # preload: Allow submission to HSTS preload list
    
    # Only set HSTS header if HTTPS is enabled
    <If "%{HTTPS} == 'on'">
        Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" env=!skip_headers
    </If>
    
    
    # ----------------------------------------------------------------------
    # Content-Security-Policy (CSP): Prevents XSS and code injection
    # ----------------------------------------------------------------------
    # This is a balanced policy that works with most WordPress sites
    # Adjust based on your specific needs
    
    Header always set Content-Security-Policy "\
        default-src 'self'; \
        script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.google.com https://www.gstatic.com https://ajax.googleapis.com; \
        style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
        font-src 'self' data: https://fonts.gstatic.com; \
        img-src 'self' data: https: http:; \
        connect-src 'self'; \
        frame-src 'self' https://www.google.com https://www.youtube.com; \
        object-src 'none'; \
        base-uri 'self'; \
        form-action 'self'; \
        frame-ancestors 'self'; \
        upgrade-insecure-requests;\
    " env=!skip_headers
    
    # For stricter security (may break some functionality):
    # Header always set Content-Security-Policy "\
    #     default-src 'self'; \
    #     script-src 'self'; \
    #     style-src 'self'; \
    #     img-src 'self' data:; \
    #     font-src 'self'; \
    #     connect-src 'self'; \
    #     frame-src 'none'; \
    #     object-src 'none'; \
    # "
    
    
    # ----------------------------------------------------------------------
    # Referrer-Policy: Controls referrer information
    # ----------------------------------------------------------------------
    # Options:
    # - no-referrer: Never send referrer
    # - no-referrer-when-downgrade: Send only on HTTPS->HTTPS
    # - same-origin: Send only to same origin
    # - origin: Send only origin (not full URL)
    # - strict-origin-when-cross-origin: Recommended balance
    
    Header always set Referrer-Policy "strict-origin-when-cross-origin" env=!skip_headers
    
    
    # ----------------------------------------------------------------------
    # Permissions-Policy (formerly Feature-Policy)
    # ----------------------------------------------------------------------
    # Controls access to browser features and APIs
    
    Header always set Permissions-Policy "\
        geolocation=(), \
        microphone=(), \
        camera=(), \
        payment=(), \
        usb=(), \
        magnetometer=(), \
        gyroscope=(), \
        accelerometer=(), \
        fullscreen=(self)\
    " env=!skip_headers
    
    
    # ----------------------------------------------------------------------
    # Additional Security Headers
    # ----------------------------------------------------------------------
    
    # Remove server signature
    Header unset Server
    Header always unset X-Powered-By
    Header unset X-Powered-By
    
    # Expect-CT: Certificate Transparency (for HTTPS only)
    <If "%{HTTPS} == 'on'">
        Header always set Expect-CT "max-age=86400, enforce" env=!skip_headers
    </If>
    
    # Cross-Origin-Embedder-Policy
    Header always set Cross-Origin-Embedder-Policy "require-corp" env=!skip_headers
    
    # Cross-Origin-Opener-Policy
    Header always set Cross-Origin-Opener-Policy "same-origin" env=!skip_headers
    
    # Cross-Origin-Resource-Policy
    Header always set Cross-Origin-Resource-Policy "same-origin" env=!skip_headers

</IfModule>

# ============================================================================
# ServerTokens Configuration (requires server-level access)
# ============================================================================
# Add to Apache configuration file if you have access:
# ServerTokens Prod
# ServerSignature Off

# ============================================================================
# Testing Commands
# ============================================================================
#
# 1. Test all headers at once:
#    curl -I https://example.com
#
# 2. Test specific header:
#    curl -I https://example.com | grep -i "x-frame-options"
#
# 3. Online testing:
#    https://securityheaders.com/?q=https://example.com
#    https://observatory.mozilla.org/analyze/example.com
#
# 4. Verify .htaccess syntax:
#    apache2ctl configtest
#    (or: apachectl configtest)
#
# 5. Check if mod_headers is enabled:
#    apache2ctl -M | grep headers
#    (Should show: headers_module (shared))
```

---

## nginx Implementation

**File Path:** `/etc/nginx/sites-available/your-site.conf` or include file

```nginx
# ============================================================================
# HTTP Security Headers - nginx Configuration
# Severity: Medium | OWASP: A05:2021
# ============================================================================

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com www.example.com;
    
    # SSL Configuration (required for HSTS)
    ssl_certificate /path/to/ssl/certificate.crt;
    ssl_certificate_key /path/to/ssl/private.key;
    
    # ----------------------------------------------------------------------
    # Security Headers
    # ----------------------------------------------------------------------
    
    # X-Frame-Options: Prevents clickjacking
    add_header X-Frame-Options "SAMEORIGIN" always;
    
    # X-Content-Type-Options: Prevents MIME sniffing
    add_header X-Content-Type-Options "nosniff" always;
    
    # X-XSS-Protection: Legacy XSS protection
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Strict-Transport-Security: Force HTTPS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    
    # Content-Security-Policy: XSS and injection protection
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.google.com https://www.gstatic.com https://ajax.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: https: http:; connect-src 'self'; frame-src 'self' https://www.google.com https://www.youtube.com; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'; upgrade-insecure-requests;" always;
    
    # Referrer-Policy: Control referrer information
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Permissions-Policy: Control browser features
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=(), fullscreen=(self)" always;
    
    # Expect-CT: Certificate Transparency
    add_header Expect-CT "max-age=86400, enforce" always;
    
    # Cross-Origin Policies
    add_header Cross-Origin-Embedder-Policy "require-corp" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    
    # Remove server signature
    server_tokens off;
    more_clear_headers Server;
    
    # WordPress root directory
    root /var/www/html;
    index index.php index.html;
    
    # WordPress permalinks
    location / {
        try_files $uri $uri/ /index.php?$args;
    }
    
    # PHP processing
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # Deny access to sensitive files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;
    return 301 https://$server_name$request_uri;
}

# ============================================================================
# Testing Commands
# ============================================================================
#
# 1. Test nginx configuration:
#    sudo nginx -t
#
# 2. Reload nginx:
#    sudo systemctl reload nginx
#    (or: sudo service nginx reload)
#
# 3. Test headers:
#    curl -I https://example.com
#
# 4. Test specific header:
#    curl -I https://example.com | grep -i "content-security-policy"
#
# 5. Check nginx error log:
#    sudo tail -f /var/log/nginx/error.log
```

---

## PHP Implementation (Alternative/Fallback)

**File Path:** `/wp-content/themes/your-theme/functions.php`

```php
<?php
/**
 * HTTP Security Headers - PHP Implementation
 * Severity: Medium | OWASP: A05:2021
 * 
 * This is a fallback method if you cannot modify server configuration
 * Server-level implementation (.htaccess/nginx) is preferred for better performance
 */

/**
 * Add security headers via PHP
 * 
 * Note: This runs after WordPress loads, so it's less efficient than
 * server-level implementation, but works in restricted hosting environments
 */
function add_security_headers() {
    // Only add headers if not already set by server
    if (!headers_sent()) {
        
        // X-Frame-Options: Prevent clickjacking
        if (!header_sent('X-Frame-Options')) {
            header('X-Frame-Options: SAMEORIGIN');
        }
        
        // X-Content-Type-Options: Prevent MIME sniffing
        if (!header_sent('X-Content-Type-Options')) {
            header('X-Content-Type-Options: nosniff');
        }
        
        // X-XSS-Protection: Legacy XSS filter
        if (!header_sent('X-XSS-Protection')) {
            header('X-XSS-Protection: 1; mode=block');
        }
        
        // Strict-Transport-Security: Force HTTPS (only if HTTPS is active)
        if (is_ssl() && !header_sent('Strict-Transport-Security')) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        }
        
        // Content-Security-Policy
        if (!header_sent('Content-Security-Policy')) {
            $csp = "default-src 'self'; ";
            $csp .= "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.google.com https://www.gstatic.com; ";
            $csp .= "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; ";
            $csp .= "font-src 'self' data: https://fonts.gstatic.com; ";
            $csp .= "img-src 'self' data: https: http:; ";
            $csp .= "connect-src 'self'; ";
            $csp .= "frame-src 'self' https://www.google.com; ";
            $csp .= "object-src 'none'; ";
            $csp .= "base-uri 'self'; ";
            $csp .= "form-action 'self'; ";
            $csp .= "frame-ancestors 'self'; ";
            $csp .= "upgrade-insecure-requests;";
            
            header("Content-Security-Policy: $csp");
        }
        
        // Referrer-Policy
        if (!header_sent('Referrer-Policy')) {
            header('Referrer-Policy: strict-origin-when-cross-origin');
        }
        
        // Permissions-Policy
        if (!header_sent('Permissions-Policy')) {
            $permissions = 'geolocation=(), microphone=(), camera=(), payment=(), ';
            $permissions .= 'usb=(), magnetometer=(), gyroscope=(), accelerometer=(), ';
            $permissions .= 'fullscreen=(self)';
            header("Permissions-Policy: $permissions");
        }
        
        // Remove powered by header
        header_remove('X-Powered-By');
    }
}
add_action('send_headers', 'add_security_headers', 1);

/**
 * Helper function to check if a header was already sent
 */
function header_sent($header_name) {
    $headers = headers_list();
    foreach ($headers as $header) {
        if (stripos($header, $header_name . ':') === 0) {
            return true;
        }
    }
    return false;
}

/**
 * Remove WordPress version from generator meta tag
 * Prevents version disclosure
 */
remove_action('wp_head', 'wp_generator');

/**
 * Remove WordPress version from RSS feeds
 */
add_filter('the_generator', '__return_empty_string');

/**
 * Remove version from scripts and styles
 */
function remove_version_from_assets($src) {
    if (strpos($src, 'ver=')) {
        $src = remove_query_arg('ver', $src);
    }
    return $src;
}
add_filter('style_loader_src', 'remove_version_from_assets', 9999);
add_filter('script_loader_src', 'remove_version_from_assets', 9999);

// Testing Instructions:
// 1. Clear all caches (browser, WordPress, server)
// 2. Visit your site and check headers:
//    - Open browser DevTools (F12)
//    - Go to Network tab
//    - Reload page
//    - Click on main document
//    - Check Response Headers
// 3. Verify each security header is present
// 4. Use online tools for comprehensive testing
```

---

## Content Security Policy (CSP) Customization Guide

### Understanding CSP Directives

```
default-src 'self';               # Default policy for all resources
script-src 'self' 'unsafe-inline'; # JavaScript sources
style-src 'self' 'unsafe-inline';  # CSS sources
img-src 'self' data: https:;       # Image sources
font-src 'self' data:;             # Font sources
connect-src 'self';                # AJAX, WebSocket sources
frame-src 'self';                  # iframe sources
object-src 'none';                 # Flash, Java, etc. (disable)
base-uri 'self';                   # <base> tag URLs
form-action 'self';                # Form submission URLs
frame-ancestors 'self';            # Who can frame this page
upgrade-insecure-requests;         # Upgrade HTTP to HTTPS
```

### Common WordPress CSP Configurations

#### Strict CSP (Maximum Security)
```apache
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self';
```

#### Balanced CSP (Recommended for most sites)
```apache
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.google.com https://ajax.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self'; frame-src 'self' https://www.youtube.com https://www.google.com; object-src 'none';
```

#### Permissive CSP (For sites with many third-party integrations)
```apache
Content-Security-Policy: default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https: http:; font-src 'self' data: https:; connect-src 'self' https:; frame-src https:; object-src 'none';
```

### CSP for Common WordPress Plugins

#### Google Analytics
```
script-src 'self' https://www.google-analytics.com https://ssl.google-analytics.com;
connect-src 'self' https://www.google-analytics.com;
img-src 'self' https://www.google-analytics.com;
```

#### Facebook Pixel
```
script-src 'self' https://connect.facebook.net;
connect-src 'self' https://www.facebook.com;
img-src 'self' https://www.facebook.com;
```

#### Google Fonts
```
font-src 'self' https://fonts.gstatic.com;
style-src 'self' https://fonts.googleapis.com;
```

#### YouTube Embeds
```
frame-src 'self' https://www.youtube.com https://www.youtube-nocookie.com;
img-src 'self' https://i.ytimg.com;
```

---

## Testing & Verification

### Manual Testing with curl

```bash
# Test all headers
curl -I https://example.com

# Test specific header
curl -I https://example.com | grep -i "x-frame-options"

# Test with verbose output
curl -v https://example.com 2>&1 | grep -i "< "

# Save headers to file
curl -I https://example.com > headers.txt
```

### Browser DevTools Testing

1. Open your website in a browser
2. Press F12 to open Developer Tools
3. Go to Network tab
4. Refresh the page (F5)
5. Click on the main document (first item)
6. Check Response Headers section

### Online Testing Tools

1. **Security Headers**: https://securityheaders.com/
   - Enter your URL
   - Get detailed grade and recommendations

2. **Mozilla Observatory**: https://observatory.mozilla.org/
   - Comprehensive security analysis
   - Provides actionable recommendations

3. **SSL Labs**: https://www.ssllabs.com/ssltest/
   - Tests HSTS and SSL configuration
   - Provides detailed security report

### Expected Test Results

```http
HTTP/2 200
date: Mon, 18 Jan 2024 10:00:00 GMT
content-type: text/html; charset=UTF-8
x-frame-options: SAMEORIGIN
x-content-type-options: nosniff
x-xss-protection: 1; mode=block
strict-transport-security: max-age=31536000; includeSubDomains; preload
content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline'...
referrer-policy: strict-origin-when-cross-origin
permissions-policy: geolocation=(), microphone=(), camera=()...
```

### Security Headers Grade Goals

- **SecurityHeaders.com**: A or A+
- **Mozilla Observatory**: 90+ score
- **SSL Labs**: A or A+

---

## Troubleshooting

### Issue: CSP Breaking Site Functionality

**Symptom**: Scripts, styles, or features not loading

**Solution**:
1. Open browser console (F12)
2. Look for CSP violation errors
3. Add blocked resources to CSP policy
4. Test incrementally

**Example CSP Error**:
```
Refused to load the script 'https://example.com/script.js' 
because it violates the following Content Security Policy directive: 
"script-src 'self'"
```

**Fix**: Add the domain to script-src:
```apache
script-src 'self' https://example.com;
```

### Issue: HSTS Causing Redirects on Local Development

**Symptom**: Can't access local site after implementing HSTS

**Solution**:
```
1. Clear browser HSTS cache:
   Chrome: chrome://net-internals/#hsts
   Firefox: Clear browsing history with "Active Logins" checked

2. Use conditional HSTS (only on HTTPS):
   <If "%{HTTPS} == 'on'">
       Header always set Strict-Transport-Security...
   </If>
```

### Issue: Headers Not Appearing

**Checklist**:
- [ ] mod_headers enabled (Apache): `a2enmod headers`
- [ ] .htaccess allowed: `AllowOverride All` in Apache config
- [ ] nginx reloaded: `sudo systemctl reload nginx`
- [ ] No caching interfering (test in incognito mode)
- [ ] No CDN/proxy overriding headers

---

## Monitoring & Maintenance

### Monthly Checks

1. Run security header scan
2. Check for CSP violations in logs
3. Verify HSTS is working
4. Update policies for new third-party services

### When to Update Headers

- Adding new third-party integrations
- Installing new plugins
- Changing themes
- After WordPress core updates
- When security standards change

---

## Compliance Checklist

- [x] OWASP Secure Headers Project
- [x] Mozilla Web Security Guidelines
- [x] PCI DSS Requirements (if applicable)
- [x] GDPR Technical Measures
- [x] NIST Cybersecurity Framework

---

## Additional Resources

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [Content Security Policy Reference](https://content-security-policy.com/)
- [Can I Use CSP](https://caniuse.com/contentsecuritypolicy)

---

**Document Version:** 1.0  
**Last Updated:** 2024-01-18  
**Next Review:** 2024-04-18
