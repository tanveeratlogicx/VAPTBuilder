# VAPT Feature Troubleshooting

Common issues and solutions when implementing VAPT configurations.

## 🔗 Feature: XML-RPC Blocking
**Symptom**: Jetpack plugin disconnects, or mobile app stops working.
**Cause**: `xmlrpc.php` is used for remote API communication.
**Fix**: Whitelist the specific IP addresses or User-Agents required.
```apache
<Files "xmlrpc.php">
    Order Deny,Allow
    Deny from all
    Allow from 192.0.64.0/18
    Allow from 111.111.111.111
</Files>
```

## 🔒 Feature: Broken Authentication / Login Limits
**Symptom**: Legitimate administrators blocked from login.
**Cause**: "Spam Requests" logic or overly aggressive rate limiting (RPM).
**Fix**: Reset rate limits using the CLI or via the "Force Fix" PHP method to clear transients.
*   CLI: `wp cache flush`
*   PHP: `VAPT_Hook_Driver::reset_limit();`

## 📄 Feature: Directory Browsing (`Options -Indexes`)
**Symptom**: 403 Forbidden on pages that rely on auto-indexing (rare in WP).
**Cause**: The server is configured to prevent listing files.
**Fix**: This is usually desired behavior. If a specific folder *needs* listing, add `.htaccess` inside that specific subfolder with `Options +Indexes`.

## 🛡️ Feature: Security Headers (HSTS)
**Symptom**: Site fails to load resources over HTTP; browser warnings.
**Cause**: HSTS `max-age` is too long during testing, and SSL is invalid.
**Fix**: Reduce `max-age` during testing (e.g., `max-age=300`) before committing to a year (`31536000`).

## 🧱 Feature: WAF / SQLi Rules
**Symptom**: "403 Forbidden" when saving complex post content (e.g., code snippets).
**Cause**: `mod_security` or `.htaccess` rules flagging typical SQL keywords (`SELECT`, `UNION`) in the POST body.
**Fix**: Tune the specific rule causing false positives.
*   **Debug**: Check `error.log` to see WHICH rule ID triggered.
*   **Exclusion**: `<IfModule mod_security2.c> SecRuleRemoveById [ID] </IfModule>`
## 🏁 Feature: Verification Failures
**Symptom**: "Verification Failed" but the protection seems to be working manually.
**Cause**: The probe is looking for the `X-VAPTC-Enforced` header, but it's missing from the enforcement code.
**Fix**: Ensure your enforcement mapping includes the evidence header.
*   Apache: `Header set X-VAPTC-Enforced "feature-key"`
*   Nginx: `add_header X-VAPTC-Enforced "feature-key" always;`
*   IIS: `<add name="X-VAPTC-Enforced" value="feature-key" />`

## 🚗 Feature: Driver Mismatch
**Symptom**: "Invalid Driver" or "Driver not supported" error during schema validation.
**Cause**: Using a driver name that isn't whitelist in the validator.
**Fix**: Use one of the supported drivers: `htaccess`, `nginx`, `iis`, `wp-config`, `hook`, or `manual`.
