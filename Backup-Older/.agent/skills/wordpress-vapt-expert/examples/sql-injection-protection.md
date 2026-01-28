# SQL Injection Protection - Complete Implementation Example

**Feature:** SQL Injection Protection  
**Severity:** Critical  
**OWASP:** A03:2021 - Injection

---

## Overview

This example demonstrates a complete, production-ready implementation of SQL Injection protection for WordPress sites. The implementation uses multiple layers of defense to prevent SQL injection attacks.

## Implementation Strategy

SQL Injection protection is implemented at three levels:
1. **Server Level** (.htaccess/nginx) - First line of defense
2. **WordPress Configuration** (wp-config.php) - Database security
3. **Application Level** (functions.php) - Input sanitization and query preparation

---

## 1. Server-Level Protection

### Apache (.htaccess)

**File Path:** `/public_html/.htaccess` (WordPress root directory)

```apache
# ============================================================================
# SQL Injection Protection - Apache Configuration
# Severity: Critical | OWASP: A03:2021
# ============================================================================

<IfModule mod_rewrite.c>
    RewriteEngine On
    
    # Block SQL injection attempts in query strings
    # Matches common SQL injection patterns
    RewriteCond %{QUERY_STRING} (\<|%3C).*script.*(\>|%3E) [NC,OR]
    RewriteCond %{QUERY_STRING} GLOBALS(=|\[|\%[0-9A-Z]{0,2}) [OR]
    RewriteCond %{QUERY_STRING} _REQUEST(=|\[|\%[0-9A-Z]{0,2}) [OR]
    RewriteCond %{QUERY_STRING} (union|select|insert|drop|update|delete|replace) [NC,OR]
    RewriteCond %{QUERY_STRING} (cast|create|char|convert|alter|declare) [NC,OR]
    RewriteCond %{QUERY_STRING} (information_schema|sysdatabases|sysusers) [NC,OR]
    RewriteCond %{QUERY_STRING} (concat|group_concat|having|benchmark) [NC,OR]
    RewriteCond %{QUERY_STRING} (--|;|\'|\"|\=|\*|\(|\)|\[|\]|\{|\}) [NC,OR]
    RewriteCond %{QUERY_STRING} (0x[0-9a-f]{2,}) [NC,OR]
    RewriteCond %{QUERY_STRING} (waitfor|sleep|benchmark|MD5|SHA) [NC]
    RewriteRule ^(.*)$ - [F,L]
    
    # Block SQL injection attempts in request URI
    RewriteCond %{REQUEST_URI} (union|select|insert|cast|set|declare|drop|update|delete|replace) [NC]
    RewriteRule ^(.*)$ - [F,L]
    
    # Block requests with suspicious file operations
    RewriteCond %{QUERY_STRING} (\.\.\/|\.\.\\|\/\.\.) [NC,OR]
    RewriteCond %{QUERY_STRING} (\.php|\.phtml|\.asp|\.aspx|\.jsp) [NC]
    RewriteRule ^(.*)$ - [F,L]
</IfModule>

# Additional protection through headers
<IfModule mod_headers.c>
    # Add security header to indicate protection is active
    Header set X-SQL-Protection "Active"
</IfModule>

# Testing Commands:
# 1. Test basic SQL injection:
#    curl -I "https://example.com/?id=1' OR '1'='1"
#    Expected: HTTP 403 Forbidden
#
# 2. Test UNION attack:
#    curl -I "https://example.com/?search=1' UNION SELECT NULL--"
#    Expected: HTTP 403 Forbidden
#
# 3. Verify protection header:
#    curl -I https://example.com | grep X-SQL-Protection
#    Expected: X-SQL-Protection: Active
```

---

### nginx Configuration

**File Path:** `/etc/nginx/sites-available/your-site.conf` or `/etc/nginx/conf.d/wordpress-security.conf`

```nginx
# ============================================================================
# SQL Injection Protection - nginx Configuration
# Severity: Critical | OWASP: A03:2021
# ============================================================================

# Map to detect SQL injection patterns
map $request_uri $is_sqli {
    default 0;
    "~*union.*select" 1;
    "~*insert.*into" 1;
    "~*drop.*table" 1;
    "~*update.*set" 1;
    "~*delete.*from" 1;
    "~*concat.*\(" 1;
    "~*information_schema" 1;
    "~*benchmark.*\(" 1;
    "~*sleep.*\(" 1;
    "~*0x[0-9a-f]" 1;
}

map $args $is_sqli_args {
    default 0;
    "~*union.*select" 1;
    "~*insert.*into" 1;
    "~*(\'|\"|\-\-|\#)" 1;
    "~*concat.*\(" 1;
    "~*information_schema" 1;
    "~*0x[0-9a-f]{2,}" 1;
    "~*waitfor.*delay" 1;
    "~*benchmark.*\(" 1;
}

server {
    listen 443 ssl http2;
    server_name example.com www.example.com;
    
    # Block SQL injection attempts
    if ($is_sqli) {
        return 403;
    }
    
    if ($is_sqli_args) {
        return 403;
    }
    
    # Additional query string filtering
    location / {
        # Block common SQL keywords in query strings
        if ($args ~* "(union|select|insert|drop|update|delete|cast|create|char|information_schema)") {
            return 403;
        }
        
        # Block encoded SQL attempts
        if ($args ~* "(%27|%22|%2d%2d|%23)") {
            return 403;
        }
        
        try_files $uri $uri/ /index.php?$args;
    }
    
    # Add security header
    add_header X-SQL-Protection "Active" always;
    
    # Rest of your WordPress configuration...
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
}

# Testing Commands:
# 1. Test configuration syntax:
#    sudo nginx -t
#
# 2. Reload nginx:
#    sudo systemctl reload nginx
#
# 3. Test SQL injection blocking:
#    curl -I "https://example.com/?id=1' OR '1'='1"
#    Expected: HTTP 403 Forbidden
#
# 4. Check nginx error log:
#    sudo tail -f /var/log/nginx/error.log
```

---

## 2. WordPress Configuration

### wp-config.php Security Enhancements

**File Path:** `/public_html/wp-config.php`

**⚠️ IMPORTANT:** Add these lines BEFORE `require_once(ABSPATH . 'wp-settings.php');`

```php
<?php
/**
 * SQL Injection Protection - Database Security Configuration
 * Severity: Critical | OWASP: A03:2021
 * 
 * This configuration enhances database security and prevents SQL injection
 * by enforcing strict database connection parameters and error handling.
 */

// ============================================================================
// Database Security Settings
// ============================================================================

/**
 * Force database character set to UTF-8
 * Prevents SQL injection through character encoding vulnerabilities
 */
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', 'utf8mb4_unicode_ci');

/**
 * Disable database error display
 * Prevents information disclosure through database error messages
 */
define('WP_DEBUG', false);
define('WP_DEBUG_DISPLAY', false);
@ini_set('display_errors', 0);

/**
 * Enable database error logging (instead of displaying)
 * Logs errors to debug.log file instead of showing to users
 */
define('WP_DEBUG_LOG', true);

/**
 * Custom database table prefix
 * Makes table guessing more difficult for attackers
 * NOTE: Only set this during initial installation or with proper migration
 */
// $table_prefix = 'wp_secure_'; // Uncomment if changing from default 'wp_'

// ============================================================================
// Additional Security Constants
// ============================================================================

/**
 * Disable file editing from WordPress admin
 * Prevents attackers from modifying code even if they gain admin access
 */
define('DISALLOW_FILE_EDIT', true);
define('DISALLOW_FILE_MODS', false); // Set to true to disable plugin/theme installation

/**
 * Force SSL for admin and login pages
 * Prevents session hijacking and credential theft
 */
define('FORCE_SSL_ADMIN', true);
define('FORCE_SSL_LOGIN', true);

/**
 * Increase memory limit for complex operations
 * Helps prevent denial of service during heavy database operations
 */
define('WP_MEMORY_LIMIT', '256M');
define('WP_MAX_MEMORY_LIMIT', '512M');

// ============================================================================
// Database Connection Settings (MySQL 5.7+)
// ============================================================================

/**
 * Note: These settings require MySQL 5.7+ or MariaDB 10.2+
 * Uncomment and adjust based on your server capabilities
 */

// Force strict SQL mode for better data integrity
// mysqli_query($wpdb->dbh, "SET SESSION sql_mode = 'STRICT_ALL_TABLES'");

/**
 * That's all, stop editing! Happy blogging.
 */

/** Absolute path to the WordPress directory. */
if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';

// Testing Instructions:
// 1. Verify configuration loads without errors:
//    - Visit your website
//    - Check for white screen or errors
//
// 2. Verify debug mode is disabled:
//    - Trigger an error (access non-existent page)
//    - Ensure no PHP/MySQL errors are displayed
//
// 3. Check debug log:
//    - Look for wp-content/debug.log
//    - Verify errors are logged but not displayed
//
// 4. Test file editing disabled:
//    - Login to wp-admin
//    - Go to Appearance > Theme Editor
//    - Should see "File editing disabled" message
```

---

## 3. Application-Level Protection

### functions.php Security Functions

**File Path:** `/wp-content/themes/your-theme/functions.php`

```php
<?php
/**
 * SQL Injection Protection - Application Level
 * Severity: Critical | OWASP: A03:2021
 * 
 * This code provides comprehensive SQL injection protection at the application level
 * through input sanitization, validation, and secure database query practices.
 */

// ============================================================================
// Input Sanitization Functions
// ============================================================================

/**
 * Sanitize all GET and POST inputs globally
 * Applies sanitization to user inputs before they reach WordPress core
 */
function secure_sanitize_inputs() {
    // Sanitize GET parameters
    if (!empty($_GET)) {
        foreach ($_GET as $key => $value) {
            if (is_array($value)) {
                $_GET[$key] = array_map('sanitize_text_field', $value);
            } else {
                $_GET[$key] = sanitize_text_field($value);
            }
        }
    }
    
    // Sanitize POST parameters
    if (!empty($_POST)) {
        foreach ($_POST as $key => $value) {
            if (is_array($value)) {
                $_POST[$key] = array_map('sanitize_text_field', $value);
            } else {
                $_POST[$key] = sanitize_text_field($value);
            }
        }
    }
}
add_action('init', 'secure_sanitize_inputs', 1);

/**
 * Additional SQL keyword filtering for extra protection
 * Blocks requests containing dangerous SQL keywords
 */
function block_sql_keywords() {
    $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
    $query_string = isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '';
    
    // SQL keywords to block
    $sql_keywords = array(
        'union', 'select', 'insert', 'update', 'delete', 'drop',
        'create', 'alter', 'exec', 'execute', 'script', 'javascript',
        'concat', 'information_schema', 'benchmark', 'sleep', 'waitfor'
    );
    
    // Check query string
    foreach ($sql_keywords as $keyword) {
        if (stripos($query_string, $keyword) !== false) {
            status_header(403);
            die('403 Forbidden - SQL Injection Detected');
        }
    }
    
    // Check request URI
    foreach ($sql_keywords as $keyword) {
        if (stripos($request_uri, $keyword) !== false) {
            status_header(403);
            die('403 Forbidden - SQL Injection Detected');
        }
    }
}
add_action('init', 'block_sql_keywords', 1);

// ============================================================================
// Secure Database Query Examples
// ============================================================================

/**
 * Example: Secure custom database query using $wpdb->prepare()
 * Always use prepared statements for database queries
 */
function get_user_by_id_secure($user_id) {
    global $wpdb;
    
    // CORRECT: Using prepared statement
    $user_id = absint($user_id); // Ensure integer
    $user = $wpdb->get_row(
        $wpdb->prepare(
            "SELECT * FROM {$wpdb->users} WHERE ID = %d",
            $user_id
        )
    );
    
    // INCORRECT (commented out): Never do this
    // $user = $wpdb->get_row("SELECT * FROM {$wpdb->users} WHERE ID = {$user_id}");
    
    return $user;
}

/**
 * Example: Secure search query with LIKE statement
 */
function search_posts_secure($search_term) {
    global $wpdb;
    
    // Sanitize search term
    $search_term = sanitize_text_field($search_term);
    
    // CORRECT: Using prepared statement with LIKE
    $posts = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT * FROM {$wpdb->posts} 
            WHERE post_title LIKE %s 
            AND post_status = 'publish'",
            '%' . $wpdb->esc_like($search_term) . '%'
        )
    );
    
    return $posts;
}

/**
 * Example: Secure custom meta query
 */
function get_posts_by_meta_secure($meta_key, $meta_value) {
    global $wpdb;
    
    // Sanitize inputs
    $meta_key = sanitize_key($meta_key);
    $meta_value = sanitize_text_field($meta_value);
    
    // CORRECT: Using prepared statement
    $results = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT p.* FROM {$wpdb->posts} p
            INNER JOIN {$wpdb->postmeta} pm ON p.ID = pm.post_id
            WHERE pm.meta_key = %s
            AND pm.meta_value = %s
            AND p.post_status = 'publish'",
            $meta_key,
            $meta_value
        )
    );
    
    return $results;
}

// ============================================================================
// Input Validation Functions
// ============================================================================

/**
 * Validate and sanitize numeric input
 */
function validate_numeric_input($input, $min = null, $max = null) {
    $value = absint($input);
    
    if ($min !== null && $value < $min) {
        return $min;
    }
    
    if ($max !== null && $value > $max) {
        return $max;
    }
    
    return $value;
}

/**
 * Validate and sanitize email input
 */
function validate_email_input($email) {
    $email = sanitize_email($email);
    
    if (!is_email($email)) {
        return false;
    }
    
    return $email;
}

/**
 * Validate and sanitize URL input
 */
function validate_url_input($url) {
    $url = esc_url_raw($url);
    
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        return false;
    }
    
    return $url;
}

// ============================================================================
// Security Logging
// ============================================================================

/**
 * Log potential SQL injection attempts
 */
function log_sql_injection_attempt($type, $details) {
    $log_file = WP_CONTENT_DIR . '/sql-injection-attempts.log';
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    
    $log_entry = sprintf(
        "[%s] Type: %s | IP: %s | Details: %s | User-Agent: %s\n",
        $timestamp,
        $type,
        $ip,
        $details,
        $user_agent
    );
    
    error_log($log_entry, 3, $log_file);
}

// ============================================================================
// Admin Notices
// ============================================================================

/**
 * Display admin notice if SQL injection protection is active
 */
function sql_injection_protection_notice() {
    if (current_user_can('manage_options')) {
        echo '<div class="notice notice-success is-dismissible">';
        echo '<p><strong>Security:</strong> SQL Injection protection is active.</p>';
        echo '</div>';
    }
}
add_action('admin_notices', 'sql_injection_protection_notice');

// Testing Instructions:
// 1. Test input sanitization:
//    - Submit form with SQL keywords
//    - Verify input is sanitized or blocked
//
// 2. Test custom queries:
//    - Use functions above in your code
//    - Verify they use prepared statements
//
// 3. Check error logs:
//    - Look for wp-content/sql-injection-attempts.log
//    - Verify attempts are logged
//
// 4. Verify admin notice:
//    - Login to wp-admin
//    - Check for success notice at top of dashboard
```

---

## Testing & Verification

### Manual Testing Procedures

#### Test 1: Basic SQL Injection Attempt
```bash
# Test with single quote
curl -I "https://example.com/?id=1' OR '1'='1"

# Expected Result: HTTP/1.1 403 Forbidden
```

#### Test 2: Union-Based SQL Injection
```bash
# Test UNION SELECT
curl -I "https://example.com/?search=1' UNION SELECT username,password FROM users--"

# Expected Result: HTTP/1.1 403 Forbidden
```

#### Test 3: Blind SQL Injection
```bash
# Test with sleep/delay
curl -I "https://example.com/?id=1' AND SLEEP(5)--"

# Expected Result: HTTP/1.1 403 Forbidden
```

#### Test 4: Comment-Based Injection
```bash
# Test with SQL comments
curl -I "https://example.com/?user=admin'--"

# Expected Result: HTTP/1.1 403 Forbidden
```

### Automated Testing with SQLMap

```bash
# Install SQLMap (if not already installed)
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev

# Run comprehensive SQL injection test
python sqlmap-dev/sqlmap.py -u "https://example.com/page?id=1" \
    --batch \
    --level=5 \
    --risk=3 \
    --random-agent \
    --tamper=space2comment \
    --threads=5

# Expected Result: No injection points found
```

### WPScan Testing

```bash
# Scan for vulnerabilities including SQL injection
wpscan --url https://example.com \
    --enumerate vp,vt,u \
    --plugins-detection aggressive \
    --random-user-agent

# Expected Result: No SQL injection vulnerabilities detected
```

---

## Evidence Collection

### 1. Server Logs

Check Apache error log:
```bash
tail -f /var/log/apache2/error.log
```

Check nginx error log:
```bash
tail -f /var/log/nginx/error.log
```

### 2. WordPress Debug Log

```bash
tail -f wp-content/debug.log
```

### 3. Custom SQL Injection Log

```bash
tail -f wp-content/sql-injection-attempts.log
```

### 4. Screenshot Evidence

Take screenshots of:
- 403 Forbidden responses to SQL injection attempts
- SQLMap results showing "no vulnerabilities"
- WPScan results confirming security
- Browser console showing blocked requests

---

## Maintenance & Monitoring

### Daily Checks
- Review SQL injection attempt logs
- Monitor for unusual database query patterns
- Check error logs for database errors

### Weekly Tasks
- Review and analyze blocked SQL injection attempts
- Update security rules if new patterns detected
- Test critical functionality to ensure no false positives

### Monthly Tasks
- Run full SQLMap scan
- Review and update sanitization functions
- Update WordPress core and all plugins
- Conduct manual penetration testing

### Quarterly Tasks
- Comprehensive security audit
- Review and update all security configurations
- Professional penetration testing (recommended)

---

## Troubleshooting

### Issue: Legitimate queries being blocked

**Solution:**
```apache
# In .htaccess, add exception for specific pages
RewriteCond %{REQUEST_URI} !^/admin/reports [NC]
```

### Issue: Custom plugins not working

**Solution:**
- Review plugin code for direct SQL queries
- Update plugin to use $wpdb->prepare()
- Contact plugin developer for security update

### Issue: Performance degradation

**Solution:**
- Optimize .htaccess rules
- Use caching plugins
- Move complex filtering to nginx if possible

---

## Compliance Checklist

- [x] OWASP Top 10 2021 - A03:2021 Injection
- [x] PCI DSS Requirement 6.5.1
- [x] CWE-89: SQL Injection
- [x] SANS Top 25 - CWE-89
- [x] WordPress Security Best Practices

---

## Additional Resources

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [WordPress Codex - Data Validation](https://developer.wordpress.org/apis/security/data-validation/)
- [WordPress $wpdb Documentation](https://developer.wordpress.org/reference/classes/wpdb/)
- [SQLMap Documentation](https://github.com/sqlmapproject/sqlmap/wiki)

---

**Document Version:** 1.0  
**Last Updated:** 2024-01-18  
**Next Review:** 2024-04-18
