# WordPress VAPT Evidence Report Template

**Deployment Path:** `.agent/skills/wordpress-vapt-expert/resources/evidence-template.md`

Use this template to document evidence for each implemented VAPT feature.

---

## Report Information

**Feature Name:** [Feature Name]  
**Feature ID:** [feature-id]  
**Category:** [Category]  
**Severity:** [Critical/High/Medium/Low]  
**OWASP Reference:** [A0X:2021]  
**CWE Reference:** [CWE-XXX]  
**Implementation Date:** [YYYY-MM-DD]  
**Tester Name:** [Name]  
**Environment:** [Production/Staging/Development]

---

## 1. Executive Summary

**Status:** ✅ Implemented / ⚠️ Partially Implemented / ❌ Not Implemented

**Brief Description:**
[Provide a 2-3 sentence summary of what this feature protects against and how it was implemented]

**Key Findings:**
- [Finding 1]
- [Finding 2]
- [Finding 3]

---

## 2. Implementation Details

### 2.1 Implementation Method(s)

- [ ] .htaccess
- [ ] nginx configuration
- [ ] wp-config.php
- [ ] functions.php
- [ ] Custom plugin
- [ ] Third-party plugin: [Plugin Name]

### 2.2 Files Modified

| File Path | Backup Location | Modification Date |
|-----------|-----------------|-------------------|
| `/path/to/file` | `/path/to/backup` | YYYY-MM-DD HH:MM |
| | | |

### 2.3 Configuration Changes

**Before Implementation:**
```
[Paste relevant configuration before changes]
```

**After Implementation:**
```
[Paste relevant configuration after changes]
```

### 2.4 Code Implementation

**File:** [filename]  
**Lines:** [line numbers]

```php
// Paste implemented code here
```

---

## 3. Testing Evidence

### 3.1 Test Methodology

**Tools Used:**
- [Tool 1]: [Version]
- [Tool 2]: [Version]
- [Tool 3]: [Version]

**Test Scenarios:**
1. [Test scenario 1]
2. [Test scenario 2]
3. [Test scenario 3]

### 3.2 Automated Testing Results

**Test Command:**
```bash
[Command used for testing]
```

**Test Output:**
```
[Paste test output here]
```

**Result:** ✅ Pass / ❌ Fail

### 3.3 Manual Testing Results

**Test Date:** [YYYY-MM-DD]

| Test Case | Test Payload/Method | Expected Result | Actual Result | Status |
|-----------|---------------------|-----------------|---------------|---------|
| Test 1 | [Payload] | [Expected] | [Actual] | ✅/❌ |
| Test 2 | [Payload] | [Expected] | [Actual] | ✅/❌ |
| Test 3 | [Payload] | [Expected] | [Actual] | ✅/❌ |

### 3.4 Screenshot Evidence

**Screenshot 1: [Description]**
- File: `evidence-screenshots/[feature-id]-test1.png`
- Shows: [What the screenshot demonstrates]

**Screenshot 2: [Description]**
- File: `evidence-screenshots/[feature-id]-test2.png`
- Shows: [What the screenshot demonstrates]

**Screenshot 3: [Description]**
- File: `evidence-screenshots/[feature-id]-test3.png`
- Shows: [What the screenshot demonstrates]

---

## 4. Security Header Evidence

**Test URL:** [https://example.com]  
**Test Date:** [YYYY-MM-DD]  
**Test Tool:** curl / SecurityHeaders.com / Observatory

**HTTP Response Headers:**
```http
HTTP/1.1 200 OK
Date: [Date]
Server: [Server]
X-Frame-Options: [Value]
X-Content-Type-Options: [Value]
X-XSS-Protection: [Value]
Strict-Transport-Security: [Value]
Content-Security-Policy: [Value]
Referrer-Policy: [Value]
Permissions-Policy: [Value]
```

**SecurityHeaders.com Grade:** [A+/A/B/C/D/F]  
**Mozilla Observatory Score:** [0-100]

**Evidence File:** `evidence-logs/[feature-id]-headers.txt`

---

## 5. Log File Evidence

### 5.1 Access Logs

**Log File:** `/var/log/[apache2|nginx]/access.log`  
**Date Range:** [YYYY-MM-DD] to [YYYY-MM-DD]

**Blocked Attempts:**
```
[IP] - - [Date] "GET /malicious-request HTTP/1.1" 403 [Size] "-" "[User-Agent]"
[IP] - - [Date] "POST /attack-vector HTTP/1.1" 403 [Size] "-" "[User-Agent]"
```

**Evidence File:** `evidence-logs/[feature-id]-access-log.txt`

### 5.2 Error Logs

**Log File:** `/var/log/[apache2|nginx]/error.log`  
**Date Range:** [YYYY-MM-DD] to [YYYY-MM-DD]

**Relevant Entries:**
```
[Date] [error] [client IP] [Error message related to blocked request]
```

**Evidence File:** `evidence-logs/[feature-id]-error-log.txt`

### 5.3 WordPress Debug Logs

**Log File:** `wp-content/debug.log`  
**Date Range:** [YYYY-MM-DD] to [YYYY-MM-DD]

**Relevant Entries:**
```
[Date] [VAPT] [Event description]
```

**Evidence File:** `evidence-logs/[feature-id]-debug-log.txt`

---

## 6. Vulnerability Scan Results

### 6.1 WPScan Results

**Scan Date:** [YYYY-MM-DD]  
**WPScan Version:** [Version]

**Command:**
```bash
wpscan --url https://example.com --enumerate vp,vt,u
```

**Results Summary:**
- Vulnerabilities Found: [Number]
- Related to this feature: [Number]
- Status: ✅ All mitigated / ⚠️ Partially mitigated / ❌ Not mitigated

**Detailed Output:**
```
[Paste relevant WPScan output]
```

**Evidence File:** `evidence-scans/[feature-id]-wpscan.txt`

### 6.2 SQLMap Results (if applicable)

**Scan Date:** [YYYY-MM-DD]  
**SQLMap Version:** [Version]

**Command:**
```bash
sqlmap -u "https://example.com/page?id=1" --batch --level=3
```

**Results:**
- Injection Points Found: [Number]
- Exploitable: Yes/No
- Status: ✅ Protected / ❌ Vulnerable

**Evidence File:** `evidence-scans/[feature-id]-sqlmap.txt`

### 6.3 Other Scanner Results

**Scanner:** [OWASP ZAP / Burp Suite / Nikto / Other]  
**Scan Date:** [YYYY-MM-DD]

**Results Summary:**
[Summarize findings]

**Evidence File:** `evidence-scans/[feature-id]-[scanner].txt`

---

## 7. Configuration Verification

### 7.1 Server Configuration

**Web Server:** Apache [Version] / nginx [Version]  
**PHP Version:** [Version]  
**WordPress Version:** [Version]

**Configuration Check:**
```bash
# Command to verify configuration
[Command]
```

**Output:**
```
[Configuration output]
```

### 7.2 WordPress Configuration

**wp-config.php Constants:**
```php
define('CONSTANT_NAME', value); // ✅ Correctly set / ❌ Not set
```

**Plugin Status:**
- Security Plugin: [Name] v[Version] - ✅ Active / ❌ Inactive
- Related Plugins: [List]

### 7.3 File Permissions

**Critical Files:**
```bash
-rw------- 1 user group  [size] [date] wp-config.php          # 600 ✅
-rw-r--r-- 1 user group  [size] [date] .htaccess              # 644 ✅
drwxr-xr-x 5 user group  [size] [date] wp-content/            # 755 ✅
```

---

## 8. Before/After Comparison

### 8.1 Vulnerability Status

**Before Implementation:**
- Status: ❌ Vulnerable
- Test Result: [Description of vulnerability]
- Risk Level: Critical/High/Medium/Low

**After Implementation:**
- Status: ✅ Protected
- Test Result: [Description of protection]
- Risk Level: None/Minimal

### 8.2 Performance Impact

**Response Time:**
- Before: [XXX ms]
- After: [XXX ms]
- Impact: [+/- XX%]

**Server Load:**
- Before: [Load average]
- After: [Load average]
- Impact: [Description]

---

## 9. Compliance Verification

### 9.1 OWASP Top 10 Compliance

**Relevant OWASP Category:** [A0X:2021 - Category Name]  
**Compliance Status:** ✅ Compliant / ⚠️ Partially Compliant / ❌ Non-Compliant

**Evidence:**
- [Evidence point 1]
- [Evidence point 2]

### 9.2 CWE Compliance

**Relevant CWE:** [CWE-XXX: Description]  
**Mitigation Status:** ✅ Mitigated / ⚠️ Partially Mitigated / ❌ Not Mitigated

**Evidence:**
- [Evidence point 1]
- [Evidence point 2]

### 9.3 PCI DSS Compliance (if applicable)

**Relevant Requirement:** [Requirement X.X]  
**Compliance Status:** ✅ Compliant / ⚠️ Partially Compliant / ❌ Non-Compliant

---

## 10. Recommendations

### 10.1 Current Status
- ✅ **Strengths:** [What's working well]
- ⚠️ **Weaknesses:** [What needs improvement]
- 🔄 **Ongoing Requirements:** [What needs regular attention]

### 10.2 Action Items

| Priority | Action | Responsible | Due Date | Status |
|----------|--------|-------------|----------|---------|
| High | [Action 1] | [Person] | [Date] | ⏳/✅/❌ |
| Medium | [Action 2] | [Person] | [Date] | ⏳/✅/❌ |
| Low | [Action 3] | [Person] | [Date] | ⏳/✅/❌ |

### 10.3 Future Enhancements
1. [Enhancement 1]
2. [Enhancement 2]
3. [Enhancement 3]

---

## 11. Rollback Procedure

**If Issues Arise:**

1. **Stop the web server:**
   ```bash
   sudo systemctl stop [apache2|nginx]
   ```

2. **Restore backup files:**
   ```bash
   cp /path/to/backup/file /path/to/original/file
   ```

3. **Restart web server:**
   ```bash
   sudo systemctl start [apache2|nginx]
   ```

4. **Verify restoration:**
   ```bash
   [Verification command]
   ```

**Backup Locations:**
- [File 1]: [Backup location]
- [File 2]: [Backup location]

---

## 12. Sign-Off

**Implemented By:**  
Name: [Name]  
Date: [YYYY-MM-DD]  
Signature: ___________________

**Tested By:**  
Name: [Name]  
Date: [YYYY-MM-DD]  
Signature: ___________________

**Approved By:**  
Name: [Name]  
Date: [YYYY-MM-DD]  
Signature: ___________________

---

## 13. Appendix

### 13.1 Referenced Documentation
- [Document 1]: [URL or location]
- [Document 2]: [URL or location]

### 13.2 Related Evidence Files
- `evidence-screenshots/` - Screenshot evidence
- `evidence-logs/` - Log file excerpts
- `evidence-scans/` - Scanner reports
- `evidence-configs/` - Configuration backups

### 13.3 Change History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | [Date] | [Name] | Initial implementation |
| | | | |

---

## Notes

- Keep all evidence files organized in a dedicated evidence directory
- Update this document whenever changes are made to the implementation
- Store evidence securely and maintain for compliance requirements
- Review and update evidence periodically (e.g., quarterly)
- Include this documentation in security audit packages

**Template Version:** 1.0.0  
**Last Updated:** 2024-01-19
