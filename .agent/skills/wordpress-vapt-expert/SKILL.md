---
name: wordpress-vapt-expert
description: WordPress Vulnerability Assessment and Penetration Testing (VAPT) expert. Use when implementing security protections, generating evidence for VAPT features, or hardening WordPress websites against OWASP Top 10 vulnerabilities. Handles SQL injection, XSS, authentication issues, access control, and 87+ security features with both .htaccess and nginx configurations.
---

# WordPress VAPT Expert Skill

This skill helps implement comprehensive security protections for WordPress websites and generate concrete evidence for vulnerability assessments. It covers 87 security features across OWASP Top 10 2021, CWE Top 25, and PCI DSS standards.

## When to use this skill

- **Implementing VAPT protections**: When you need to secure a WordPress site against specific vulnerabilities
- **Generating security evidence**: When you need proof that protections are working (logs, test results, configuration files)
- **Security hardening**: When performing comprehensive WordPress security audits
- **Compliance requirements**: When meeting OWASP, CWE, or PCI DSS standards
- **Multiple VAPT features**: When handling several security features simultaneously

**Keywords that trigger this skill**: WordPress security, VAPT, vulnerability assessment, penetration testing, SQL injection, XSS, authentication, access control, security headers, OWASP, hardening, evidence generation, .htaccess security, nginx security

## Feature Categories Covered

**📊 Quick Reference:** See `/resources/features-database.json` for the complete database of all 87 features with detailed implementation methods, testing procedures, and evidence requirements.

1. **Injection Attacks** (Critical Priority)
   - SQL Injection Protection
   - XSS Protection (Reflected, Stored, DOM-based)
   - Command Injection
   - XXE Protection
   - SSRF Protection
   - LFI/RFI Protection
   - Template Injection
   - Email Header Injection

2. **Authentication & Session Management** (Critical/High Priority)
   - Broken Authentication Protection
   - Weak Password Policy Enforcement
   - Brute Force Protection
   - Session Management Security
   - Session Fixation Protection
   - Session Timeout
   - Password Reset Vulnerabilities
   - Account Takeover Prevention

3. **Access Control** (Critical/High Priority)
   - Broken Access Control
   - IDOR Protection
   - Privilege Escalation Prevention
   - Admin Interface Protection
   - CSRF Protection
   - Admin Functionality Exposure

4. **Configuration Security** (High/Medium Priority)
   - Sensitive Data Exposure Prevention
   - Security Headers (CSP, HSTS, X-Frame-Options, etc.)
   - wp-config.php Protection
   - File Permissions
   - .htaccess Security Rules
   - Debug Mode Configuration
   - File Editor Disabling

5. **API Security** (Medium Priority)
   - XML-RPC Security
   - REST API Endpoint Security
   - Rate Limiting
   - CORS Configuration

6. **Information Disclosure** (Medium/Low Priority)
   - Version Disclosure Prevention
   - User Enumeration Blocking
   - Directory Listing Prevention
   - Backup File Exposure
   - Log File Protection
   - Database Error Disclosure

7. **Cryptography** (High Priority)
   - SSL/TLS Configuration
   - Data Encryption at Rest
   - Data Encryption in Transit
   - Weak Cryptographic Algorithms
   - Insecure Random Number Generation

8. **Input Validation** (High Priority)
   - Input Validation & Sanitization
   - File Upload Security
   - Directory Traversal Protection
   - Mass Assignment Prevention
   - Validation Bypass Prevention

9. **Availability & DoS** (Medium/High Priority)
   - Rate Limiting
   - DoS Protection
   - Cron Protection
   - Resource Limits

10. **Third-Party & Dependencies** (High Priority)
    - Known Vulnerabilities Monitoring
    - Insecure Third-Party Integrations
    - Component Version Management

## How to approach VAPT implementation

### Step 1: Understand the Feature Request

When given a VAPT feature title or ID, **first consult the features database** at `/resources/features-database.json`:

```javascript
// Example: Look up a feature by ID or name
const featuresDB = JSON.parse(readFile('resources/features-database.json'));
const feature = featuresDB.features.find(f => f.id === 'sql-injection' || f.name.includes('SQL Injection'));
```

From the database entry, identify:
- **Feature ID** and **name** (for consistent reference)
- **Category** (Injection, Authentication, Access Control, etc.)
- **Severity level** (Critical, High, Medium, Low)
- **Priority** (1-87, lower is higher priority)
- **OWASP reference** (e.g., A03:2021-Injection)
- **CWE reference** (e.g., CWE-89)
- **Implementation methods** available (.htaccess, nginx, functions.php, wp-config.php)
- **Test method** (automated scanning, manual testing, etc.)
- **Verification steps** (specific test procedures)
- **Remediation** approach
- **Evidence requirements** (what to collect to prove protection works)

### Step 2: Choose Implementation Method

**Decision tree for implementation:**

```
Is the feature fixable via web server configuration?
├─ YES → Prefer .htaccess (Apache) or nginx config
│   └─ Reasons: Fewer security risks, no PHP execution, server-level protection
└─ NO → Use WordPress-specific methods
    ├─ wp-config.php for configuration constants
    ├─ functions.php for filters/hooks
    └─ Custom validation/sanitization functions
```

**Priority order:**
1. **.htaccess / nginx** - For blocking, redirects, headers, file access
2. **wp-config.php** - For WordPress constants and configuration
3. **functions.php** - For WordPress hooks, filters, and custom logic
4. **Custom plugins** - Only when absolutely necessary (avoid creating actual plugins in this skill)

### Step 3: Create Implementation Artifacts

For each feature, create **self-contained** artifacts that include:

#### A. Protection Implementation
- Complete code in a single file
- All necessary components included
- No external dependencies
- Comments explaining each section

#### B. Evidence Generation Script
- Automated testing script
- Log file analysis
- Configuration verification
- Proof of protection working

#### C. Deployment Instructions
- Exact file paths
- Backup procedures
- Testing steps
- Rollback procedures

### Step 4: Handle Multiple Features Simultaneously

When implementing multiple VAPT features:

1. **Group by implementation method**
   - Combine all .htaccess rules into one artifact
   - Combine all nginx rules into one artifact
   - Separate functions.php additions into logical groups

2. **Avoid conflicts**
   - Check for overlapping rules
   - Ensure proper directive order
   - Test combined configurations

3. **Prioritize by severity**
   - Implement Critical features first
   - Then High, Medium, Low
   - Document dependencies between features

## Implementation Patterns

### Pattern 1: .htaccess Implementation

```apache
# ============================================
# WordPress VAPT Protection: [FEATURE_NAME]
# Category: [CATEGORY]
# Severity: [SEVERITY]
# Deployment Path: .htaccess in WordPress root
# ============================================

# [Brief description of protection]

# Protection rules
<IfModule mod_rewrite.c>
    RewriteEngine On
    # Specific rules here
</IfModule>

# Alternative approach (if applicable)
<FilesMatch "pattern">
    # Access control
</FilesMatch>

# Evidence generation: Check logs at /var/log/apache2/error.log
```

### Pattern 2: nginx Configuration

```nginx
# ============================================
# WordPress VAPT Protection: [FEATURE_NAME]
# Category: [CATEGORY]
# Severity: [SEVERITY]
# Deployment Path: /etc/nginx/sites-available/your-site.conf
# ============================================

# [Brief description of protection]

# Protection rules
location ~ pattern {
    # Specific rules here
}

# Alternative approach (if applicable)
location = /specific-file {
    # Access control
}

# Evidence generation: Check logs at /var/log/nginx/error.log
```

### Pattern 3: wp-config.php Constants

```php
<?php
/**
 * ============================================
 * WordPress VAPT Protection: [FEATURE_NAME]
 * Category: [CATEGORY]
 * Severity: [SEVERITY]
 * Deployment Path: wp-config.php (before "That's all, stop editing!")
 * ============================================
 * 
 * [Brief description of protection]
 * 
 * BACKUP INSTRUCTIONS:
 * 1. Create backup: cp wp-config.php wp-config.php.backup
 * 2. Add the code below BEFORE the line: require_once ABSPATH . 'wp-settings.php';
 * 3. Test the site after implementation
 * 4. If issues occur, restore: cp wp-config.php.backup wp-config.php
 */

// Protection constants
define('CONSTANT_NAME', value);

// Additional configuration
// [Explanation of each setting]
```

### Pattern 4: functions.php Implementation

```php
<?php
/**
 * ============================================
 * WordPress VAPT Protection: [FEATURE_NAME]
 * Category: [CATEGORY]
 * Severity: [SEVERITY]
 * Deployment Path: wp-content/themes/your-theme/functions.php
 * ============================================
 * 
 * [Brief description of protection]
 * 
 * BACKUP INSTRUCTIONS:
 * 1. Create backup: cp functions.php functions.php.backup
 * 2. Add this code at the END of functions.php
 * 3. Test the site thoroughly
 * 4. If issues occur, restore: cp functions.php.backup functions.php
 */

// Protection function
add_action('hook_name', 'vapt_protection_function_name');
function vapt_protection_function_name() {
    // Protection logic
    // Include all necessary validation, sanitization, etc.
}

// Additional hooks/filters as needed
```

### Pattern 5: Evidence Generation Script

```php
<?php
/**
 * ============================================
 * Evidence Generator: [FEATURE_NAME]
 * Purpose: Generate concrete evidence of protection
 * Deployment Path: /vapt-evidence/[feature-id]-evidence.php
 * ============================================
 * 
 * USAGE:
 * 1. Upload this file to /vapt-evidence/ directory (create if needed)
 * 2. Access via: https://your-site.com/vapt-evidence/[feature-id]-evidence.php
 * 3. Review the output and save for documentation
 * 4. DELETE this file after evidence collection
 * 
 * SECURITY WARNING:
 * This file should ONLY be used temporarily for evidence collection.
 * DELETE immediately after use to prevent information disclosure.
 */

// Authentication check (basic - improve for production)
$auth_key = 'YOUR_RANDOM_KEY_HERE'; // Change this!
if (!isset($_GET['key']) || $_GET['key'] !== $auth_key) {
    die('Unauthorized access');
}

echo "<h1>VAPT Evidence: [FEATURE_NAME]</h1>";
echo "<h2>Feature ID: [FEATURE_ID]</h2>";
echo "<h3>Generated: " . date('Y-m-d H:i:s') . "</h3>";

// Evidence collection logic
echo "<h3>1. Configuration Status</h3>";
// Check if protections are active

echo "<h3>2. Test Results</h3>";
// Run automated tests

echo "<h3>3. Log Analysis</h3>";
// Check relevant logs

echo "<h3>4. Recommendations</h3>";
// Provide actionable recommendations

echo "<hr><p style='color:red;'><strong>SECURITY REMINDER: DELETE THIS FILE AFTER USE!</strong></p>";
```

## Server Configuration Guidelines

### Apache (.htaccess) Best Practices

1. **Always backup** before modifying .htaccess
2. **Test after each change** - syntax errors can break the site
3. **Order matters** - RewriteRule directives are processed sequentially
4. **Use IfModule** - Ensures compatibility if modules aren't loaded
5. **Comment extensively** - Future administrators need context

**Common .htaccess modules:**
- `mod_rewrite` - URL rewriting and redirects
- `mod_headers` - HTTP header manipulation
- `mod_deflate` - Compression
- `mod_expires` - Cache control
- `mod_security` - Web application firewall

### nginx Best Practices

1. **Always backup** before modifying nginx configuration
2. **Test configuration** - `nginx -t` before reloading
3. **Reload, don't restart** - `nginx -s reload` for zero downtime
4. **Location block order** - More specific locations first
5. **Separate files** - Use includes for organization

**Common nginx directives:**
- `location` - URL matching and handling
- `add_header` - HTTP header manipulation
- `deny` / `allow` - Access control
- `limit_req` - Rate limiting
- `return` - Redirects and responses

### Choosing Between Apache and nginx

**Use .htaccess when:**
- WordPress is on shared hosting (Apache)
- No access to main server config
- Need per-directory configuration
- Quick prototyping and testing

**Use nginx when:**
- Full server control available
- Performance is critical
- Hosting modern WordPress stack
- Managing multiple sites

**Provide both when:**
- Implementation method varies by server
- Maximum compatibility needed
- Documentation for different environments

## Evidence Generation Guidelines

### Types of Evidence Required

1. **Configuration Evidence**
   - Screenshots of wp-config.php settings
   - .htaccess / nginx config snippets
   - WordPress admin panel settings
   - File permissions output

2. **Testing Evidence**
   - Successful block of attack attempts (403 errors)
   - Tool scan results (WPScan, SQLMap, etc.)
   - Manual test results with payloads
   - Before/after comparisons

3. **Log Evidence**
   - Apache/nginx access logs showing blocked attempts
   - WordPress debug logs (if enabled for testing)
   - Security plugin logs
   - Error logs showing proper handling

4. **Verification Evidence**
   - HTTP header analysis (curl -I output)
   - Security header testing results (securityheaders.com)
   - SSL test results (SSL Labs)
   - Third-party scanner results

### Evidence Collection Scripts

Create PHP scripts that:
- Run automated tests
- Parse log files for relevant entries
- Check configuration settings
- Generate formatted reports
- Include timestamps and system info

**Important:** All evidence scripts must:
- Include authentication mechanism
- Warn about deletion after use
- Not expose sensitive data unnecessarily
- Be thoroughly commented
- Include usage instructions

## Testing Methodology

### Verification Steps for Each Feature

1. **Pre-Implementation Baseline**
   - Document current state
   - Run vulnerability scans
   - Record existing protections

2. **Implementation**
   - Apply protection code
   - Verify syntax/configuration
   - Clear caches (WordPress, server, CDN)

3. **Functional Testing**
   - Verify site still works normally
   - Test affected functionality
   - Check for broken features

4. **Security Testing**
   - Attempt attack payloads
   - Verify blocks are working
   - Check for bypass techniques
   - Use automated tools

5. **Evidence Collection**
   - Run evidence generation scripts
   - Capture screenshots
   - Export logs
   - Document results

6. **Documentation**
   - Record what was implemented
   - Note any customizations
   - Document test results
   - Create rollback plan

### Common Testing Tools

Reference the scripts in `/scripts/testing-tools.sh` for:
- **WPScan** - WordPress vulnerability scanner
- **SQLMap** - SQL injection testing
- **OWASP ZAP** - Web application scanner
- **Burp Suite** - Manual testing platform
- **Nikto** - Web server scanner
- **curl** - HTTP header testing
- **SecurityHeaders.com** - Header analysis
- **SSL Labs** - SSL/TLS testing

## Priority Implementation Guide

### Critical Priority (Implement First)

1. SQL Injection Protection
2. Sensitive Data Exposure Prevention
3. Broken Authentication Protection
4. Insecure Deserialization Protection
5. Disable File Editing
6. Admin Interface Protection
7. RFI Protection
8. Command Injection Protection
9. Authentication Bypass Prevention
10. Admin Functionality Exposure Prevention

### High Priority (Implement Second)

1. XSS Protection
2. Broken Access Control
3. IDOR Protection
4. Session Management Security
5. Known Vulnerabilities Monitoring
6. Weak Password Policy Enforcement
7. XXE Protection
8. SSRF Protection
9. File Upload Security
10. Directory Traversal Protection

### Medium Priority (Implement Third)

1. Security Headers
2. CSRF Protection
3. Logging & Monitoring
4. Rate Limiting
5. Disable XML-RPC
6. Disable REST API (if not needed)
7. Content Security Policy
8. File Permissions
9. Database Security Configuration

### Low Priority (Implement Last)

1. User Enumeration Prevention
2. Cron Protection
3. WordPress Version Disclosure
4. Directory Listing Prevention
5. Concurrent Session Control

## Common Patterns and Solutions

### Pattern: Blocking Malicious Patterns

**.htaccess approach:**
```apache
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{QUERY_STRING} [malicious_pattern] [NC,OR]
    RewriteCond %{REQUEST_URI} [malicious_pattern] [NC]
    RewriteRule .* - [F,L]
</IfModule>
```

**nginx approach:**
```nginx
location ~ [malicious_pattern] {
    return 403;
}
```

### Pattern: Adding Security Headers

**.htaccess approach:**
```apache
<IfModule mod_headers.c>
    Header set X-Header-Name "value"
</IfModule>
```

**nginx approach:**
```nginx
add_header X-Header-Name "value" always;
```

**functions.php approach:**
```php
add_action('send_headers', 'vapt_security_headers');
function vapt_security_headers() {
    header('X-Header-Name: value');
}
```

### Pattern: Protecting Sensitive Files

**.htaccess approach:**
```apache
<FilesMatch "^(wp-config\.php|readme\.html|license\.txt)">
    Order allow,deny
    Deny from all
</FilesMatch>
```

**nginx approach:**
```nginx
location ~ ^/(wp-config\.php|readme\.html|license\.txt) {
    deny all;
}
```

### Pattern: Input Validation & Sanitization

**functions.php approach:**
```php
add_filter('pre_user_query', 'vapt_sanitize_user_input');
function vapt_sanitize_user_input($query) {
    // Validation logic
    // Use WordPress sanitization functions
    // sanitize_text_field(), esc_sql(), etc.
}
```

## Artifact Organization

When creating artifacts for a VAPT feature, organize as follows:

```
Artifact 1: Protection Implementation (.htaccess)
- Complete .htaccess rules
- Comments explaining each section
- Deployment path and instructions

Artifact 2: Protection Implementation (nginx)
- Complete nginx configuration
- Comments explaining each section
- Deployment path and instructions

Artifact 3: Protection Implementation (WordPress)
- wp-config.php additions (if needed)
- functions.php additions (if needed)
- Complete, self-contained code

Artifact 4: Evidence Generation Script
- PHP script for automated testing
- Evidence collection logic
- Report generation
- Security warnings

Artifact 5: Testing & Verification Guide
- Manual testing steps
- Expected results
- Tool commands
- Evidence checklist
```

## Critical Reminders

1. **Never create actual WordPress plugin files** - Only provide code snippets for existing files
2. **Always provide both Apache and nginx** configurations when applicable
3. **Make artifacts self-contained** - No external dependencies
4. **Include deployment paths** in every artifact header
5. **Provide backup instructions** before any file modification
6. **Generate concrete evidence** - Not just "this should work"
7. **Test before deploying** - Syntax errors can break sites
8. **Delete evidence scripts** after use - Security risk if left
9. **Comment extensively** - Future administrators need context
10. **Follow WordPress coding standards** when writing PHP

## Example Workflow

**User Request:** "Implement SQL Injection Protection and XSS Protection"

**Agent Response:**

1. **Identify features** from the JSON database
   - sql-injection (Critical, Priority 1)
   - xss-protection (High, Priority 2)

2. **Determine implementation methods**
   - SQL Injection: .htaccess + nginx + functions.php
   - XSS Protection: .htaccess + nginx + functions.php + CSP headers

3. **Create artifacts** (5 total):
   - Artifact 1: Combined .htaccess rules for both features
   - Artifact 2: Combined nginx configuration for both features
   - Artifact 3: functions.php additions for both features
   - Artifact 4: Evidence generation script for SQL Injection
   - Artifact 5: Evidence generation script for XSS Protection

4. **Provide deployment guide**:
   - Order of implementation
   - Testing procedures
   - Evidence collection steps
   - Rollback procedures

## Scripts and Resources

This skill includes the following resources in the skill folder:

### Scripts (`/scripts/`)
- `testing-tools.sh` - Reference commands for common VAPT testing tools (WPScan, SQLMap, OWASP ZAP, Burp Suite, Nikto, curl, nmap, etc.)
- `evidence-collector.php` - Template for creating feature-specific evidence collection scripts with automated testing and reporting

### Examples (`/examples/`)
- `htaccess-complete.conf` - Complete Apache .htaccess security configuration with 30+ protection rules
- `nginx-complete.conf` - Complete nginx security configuration with 35+ security directives
- `functions-security.php` - Complete WordPress functions.php security additions with 20+ protection functions

### Resources (`/resources/`)
- `features-database.json` - **Complete database of all 87 VAPT features** with implementation methods, testing procedures, and evidence requirements
- `vapt-checklist.md` - Comprehensive implementation checklist organized by priority
- `evidence-template.md` - Professional evidence documentation template for compliance reporting

### How to Use These Resources

**When implementing a VAPT feature:**
1. **Check `features-database.json`** first to understand the feature's category, severity, implementation methods, and evidence requirements
2. **Reference example files** in `/examples/` for implementation patterns
3. **Use `testing-tools.sh`** for the correct testing commands
4. **Generate evidence** using the template from `evidence-collector.php`
5. **Document** using `evidence-template.md`
6. **Track progress** with `vapt-checklist.md`

**Important:** The agent should read these files as needed to provide accurate implementations, but should not include entire file contents in responses unless specifically requested. Instead, extract relevant sections and customize for the specific feature being implemented.

## Response Format

When responding to a VAPT feature request:

1. **Feature Summary** (Brief)
   - Feature name and ID
   - Category and severity
   - Implementation methods chosen

2. **Artifacts** (Main content)
   - Each artifact as separate code block
   - Clear headers with deployment paths
   - Self-contained and complete

3. **Deployment Instructions** (Clear steps)
   - Order of implementation
   - File locations
   - Testing procedures

4. **Evidence Requirements** (Specific)
   - What evidence to collect
   - How to collect it
   - What to look for

5. **Verification Steps** (Actionable)
   - Manual tests to perform
   - Expected results
   - Tool commands to run

## Conclusion

This skill enables comprehensive WordPress VAPT implementation with:
- 87 security features from OWASP Top 10 2021
- Both .htaccess and nginx configurations
- Evidence generation for compliance
- Self-contained, production-ready artifacts
- Clear deployment and testing procedures

Always prioritize Critical and High severity features first, and ensure every implementation includes concrete evidence generation capabilities.
