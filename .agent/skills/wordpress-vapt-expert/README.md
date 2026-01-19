# WordPress VAPT Expert Skill - Quick Start Guide

**Deployment Path:** `.agent/skills/wordpress-vapt-expert/README.md`

Welcome to the WordPress VAPT (Vulnerability Assessment and Penetration Testing) Expert Skill for Google's Antigravity IDE! This skill helps you implement comprehensive security protections for WordPress websites and generate concrete evidence for compliance.

---

## 🚀 What This Skill Does

This skill enables you to:

✅ **Implement 87 WordPress security features** covering OWASP Top 10 2021, CWE Top 25, and PCI DSS standards  
✅ **Generate both protection AND evidence** for each security feature  
✅ **Support multiple servers** - provides both Apache (.htaccess) and nginx configurations  
✅ **Handle multiple features simultaneously** with conflict detection  
✅ **Create self-contained artifacts** ready for production deployment  
✅ **Follow best practices** with comprehensive testing and rollback procedures

---

## 📁 Skill Structure

```
wordpress-vapt-expert/
├── SKILL.md                          # Main skill definition
├── README.md                         # This file
├── scripts/
│   ├── testing-tools.sh             # Testing tool commands reference
│   └── evidence-collector.php       # Evidence generation template
├── examples/
│   ├── htaccess-complete.conf       # Complete Apache security config
│   ├── nginx-complete.conf          # Complete nginx security config
│   └── functions-security.php       # Complete WordPress security functions
└── resources/
    ├── features-database.json       # 87 VAPT features database ⭐
    ├── vapt-checklist.md           # Implementation checklist
    └── evidence-template.md         # Evidence documentation template
```

---

## 🎯 Quick Start Examples

### Example 1: Implement a Single Feature

**User Request:**
```
Implement SQL Injection Protection for my WordPress site
```

**Agent Response:**
The agent will:
1. Look up `sql-injection` in `features-database.json`
2. See it's Critical severity, Priority 1
3. Note implementation methods: .htaccess, nginx, wp-config.php, functions.php
4. Generate 4 artifacts:
   - `.htaccess` rules for SQL injection protection
   - `nginx` configuration for SQL injection protection
   - `functions.php` additions for prepared statements
   - Evidence generation script to prove protection works
5. Provide deployment instructions with backup procedures
6. Include testing steps and expected results

### Example 2: Implement Multiple Features

**User Request:**
```
Implement XSS Protection and CSRF Protection
```

**Agent Response:**
The agent will:
1. Look up both features in the database
2. Identify XSS (High, Priority 2) and CSRF (Medium, Priority 8)
3. Combine related .htaccess rules into one artifact
4. Combine related nginx rules into one artifact
5. Provide separate evidence scripts for each feature
6. Include comprehensive testing procedures

### Example 3: Implement by Category

**User Request:**
```
Implement all Critical priority Injection protections
```

**Agent Response:**
The agent will:
1. Filter `features-database.json` for:
   - Category: "Injection"
   - Severity: "critical"
2. Find: SQL Injection, RFI Protection, Command Injection, etc.
3. Generate combined artifacts organized by server type
4. Prioritize by the "priority" field (1, 5, 53, 54...)
5. Provide implementation order and dependencies

### Example 4: Server-Specific Implementation

**User Request:**
```
Give me nginx configuration for all authentication features
```

**Agent Response:**
The agent will:
1. Filter database for Category: "Authentication"
2. Extract only nginx-compatible implementations
3. Generate single comprehensive nginx config file
4. Include rate limiting zones
5. Provide nginx-specific testing commands

---

## 📊 Features Database Overview

The **`resources/features-database.json`** file is the heart of this skill. It contains:

- **87 complete VAPT features** organized by category
- **Implementation methods** for each feature
- **Testing procedures** with specific commands
- **Evidence requirements** for compliance
- **OWASP and CWE mappings** for standards compliance
- **Priority rankings** from 1 (most critical) to 87 (least critical)

### Feature Categories:

1. **Injection Attacks** - SQL Injection, XSS, XXE, SSRF, LFI, RFI, etc.
2. **Authentication & Session** - Password policies, brute force, session management
3. **Access Control** - IDOR, privilege escalation, admin protection
4. **Configuration** - wp-config.php, file permissions, debug mode
5. **API Security** - XML-RPC, REST API, rate limiting
6. **Information Disclosure** - Version info, user enumeration, logs
7. **Cryptography** - SSL/TLS, encryption, hashing
8. **Input Validation** - File uploads, sanitization, validation bypass
9. **Availability** - DoS protection, rate limiting, resource limits
10. **Dependencies** - Known vulnerabilities, third-party integrations

---

## 🛠️ Using the Resources

### Testing Tools Reference (`scripts/testing-tools.sh`)

Contains ready-to-use commands for:
- **WPScan** - WordPress vulnerability scanner
- **SQLMap** - SQL injection testing
- **OWASP ZAP** - Web application scanner
- **Burp Suite** - Manual testing platform
- **Nikto** - Web server scanner
- **curl** - HTTP header testing
- And 10+ more tools with examples

**Usage:** Reference this file when you need specific testing commands.

### Evidence Collector Template (`scripts/evidence-collector.php`)

A complete PHP template for generating evidence reports with:
- Automated configuration checking
- HTTP header analysis
- Log file parsing
- Test result generation
- Professional HTML output

**Usage:** Copy and customize for each feature you implement.

### Complete Configuration Examples (`examples/`)

Three comprehensive reference implementations:

1. **`htaccess-complete.conf`** (30+ security rules)
   - SQL injection protection
   - XSS protection
   - File access controls
   - Security headers
   - Rate limiting

2. **`nginx-complete.conf`** (35+ security directives)
   - All major VAPT protections
   - SSL/TLS configuration
   - Rate limiting zones
   - Performance optimization

3. **`functions-security.php`** (20+ security functions)
   - Input validation & sanitization
   - Session management
   - File upload security
   - Logging & monitoring

**Usage:** Reference these when implementing features to see complete patterns.

### Implementation Checklist (`resources/vapt-checklist.md`)

A comprehensive checklist organized by priority:
- ✅ Pre-implementation requirements
- ✅ Critical features (implement first)
- ✅ High priority features (implement second)
- ✅ Medium priority features (implement third)
- ✅ Low priority features (implement last)
- ✅ Post-implementation verification
- ✅ Ongoing maintenance

**Usage:** Track your progress through all 87 features systematically.

### Evidence Template (`resources/evidence-template.md`)

Professional documentation template for each feature including:
- Executive summary
- Implementation details
- Testing evidence
- Security headers
- Log file evidence
- Vulnerability scan results
- Before/after comparison
- Compliance verification (OWASP, CWE, PCI DSS)
- Sign-off section

**Usage:** Fill out for each implemented feature to maintain compliance documentation.

---

## ⚡ Common Usage Patterns

### Pattern 1: Quick Security Audit

```
"Scan my WordPress site and identify all Critical vulnerabilities"
```

Agent will use `features-database.json` to list all Critical severity features and provide a prioritized implementation plan.

### Pattern 2: Compliance Requirements

```
"I need to meet OWASP Top 10 2021 A03:2021-Injection requirements"
```

Agent will filter the database for all features tagged with `"owasp": "A03:2021-Injection"` and implement them.

### Pattern 3: Server Migration

```
"Convert my Apache .htaccess security rules to nginx"
```

Agent will read your current .htaccess, identify the protections, and generate equivalent nginx configuration using the examples as reference.

### Pattern 4: Evidence Collection

```
"Generate evidence for all implemented SQL injection protections"
```

Agent will create a custom evidence collection script based on the template and the specific requirements from `features-database.json`.

---

## 🎓 Best Practices

1. **Always backup first** - Every artifact includes backup commands
2. **Test in staging** - Never implement directly in production
3. **Implement by priority** - Critical → High → Medium → Low
4. **One feature at a time** - Test after each implementation
5. **Collect evidence** - Document everything for compliance
6. **Monitor logs** - Watch for false positives or issues
7. **Regular updates** - Security is ongoing, not one-time

---

## 📖 How the Agent Uses This Skill

When you request WordPress VAPT implementation, the agent:

1. **Reads SKILL.md** to understand the implementation methodology
2. **Queries features-database.json** to get feature details
3. **References examples/** for implementation patterns
4. **Uses scripts/** for testing commands
5. **Applies resources/** for templates and checklists
6. **Generates artifacts** customized for your specific needs
7. **Provides evidence** generation capabilities

All artifacts are:
- ✅ Self-contained (no external dependencies)
- ✅ Production-ready (with comprehensive comments)
- ✅ Tested (with verification procedures)
- ✅ Documented (with deployment instructions)
- ✅ Reversible (with rollback procedures)

---

## 🔍 Finding Features

### By Feature ID
```
"Implement sql-injection protection"
```

### By Feature Name
```
"Implement Cross-Site Scripting Protection"
```

### By Category
```
"Implement all Injection protections"
```

### By Severity
```
"Implement all Critical features"
```

### By Priority
```
"Implement the top 10 priority features"
```

### By OWASP Reference
```
"Implement all A03:2021-Injection features"
```

### By CWE Reference
```
"Implement protection for CWE-89"
```

---

## 🆘 Troubleshooting

### "Implementation broke my site"
1. Check the error logs (paths provided in artifacts)
2. Use the rollback procedure (included in every artifact)
3. Restore from backup (backup commands provided)
4. Test in staging environment first next time

### "False positives blocking legitimate traffic"
1. Review the server logs to identify the specific rule
2. Adjust the rule or add exceptions
3. Consider using less aggressive patterns
4. Monitor and refine over time

### "Evidence script not working"
1. Verify PHP version compatibility
2. Check file permissions
3. Ensure WordPress is loaded properly
4. Review the authentication key

### "Can't find a specific feature"
1. Check `features-database.json` directly
2. Search by ID, name, category, or OWASP reference
3. All 87 features are documented
4. Ask the agent to list features in a category

---

## 📚 Additional Resources

- **OWASP Top 10 2021:** https://owasp.org/Top10/
- **CWE Top 25:** https://cwe.mitre.org/top25/
- **WordPress Security:** https://wordpress.org/support/article/hardening-wordpress/
- **SecurityHeaders.com:** https://securityheaders.com/
- **Mozilla Observatory:** https://observatory.mozilla.org/

---

## 🤝 Contributing

This skill is designed to be comprehensive but can always be improved:

1. **New features** - Add to `features-database.json`
2. **Better implementations** - Update example files
3. **Additional tools** - Add to `testing-tools.sh`
4. **Improved templates** - Enhance evidence and documentation templates

---

## 📝 Version History

- **v1.1.0** (2024-01-19) - Added features database, enhanced documentation
- **v1.0.0** (2024-01-19) - Initial release with 87 VAPT features

---

## ⚠️ Important Disclaimers

1. **Test in staging first** - Never implement directly in production
2. **Backup everything** - Always backup before making changes
3. **Monitor continuously** - Security is ongoing, not one-time
4. **Legal compliance** - Only test sites you own or have permission to test
5. **Professional review** - Consider professional security audit for critical systems

---

## 🎯 Quick Command Reference

```bash
# Backup WordPress
tar -czf wordpress-backup-$(date +%Y%m%d).tar.gz /var/www/html/

# Backup database
mysqldump -u user -p database > db-backup-$(date +%Y%m%d).sql

# Test Apache config
apachectl configtest

# Test nginx config
nginx -t

# Reload Apache
sudo systemctl reload apache2

# Reload nginx
sudo nginx -s reload

# Check file permissions
find /var/www/html -type f -ls | grep -v 644
find /var/www/html -type d -ls | grep -v 755

# View recent logs
tail -f /var/log/apache2/error.log
tail -f /var/log/nginx/error.log
```

---

**Ready to secure your WordPress site? Just ask the agent to implement any VAPT feature!** 🚀🔒

For detailed implementation guidance, see `SKILL.md`.  
For the complete features list, see `resources/features-database.json`.  
For progress tracking, use `resources/vapt-checklist.md`.
