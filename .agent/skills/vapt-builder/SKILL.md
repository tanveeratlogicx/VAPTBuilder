---
name: vapt-builder
description: Specialized VAPT Builder skill trained on the 99-item Risk Catalog and SixT Risk Catalog. Focuses on generating JSON configuration schemas for the VAPTBuilder plugin, specifically prioritizing .htaccess (Apache) rules for server-side security enforcement.
---

# VAPT Builder Expert Skill

This skill is a specialized extension of the generic WordPress VAPT expert, specifically tailored for the **VAPTBuilder Plugin**. It uses the `VAPT-Complete-Risk-Catalog-99.json` as its primary source of truth.

## 🎯 Primary Goal

To implement security features by **generating configuration schemas** for various server architectures. The VAPTBuilder plugin uses a "Driver" system where you map features to existing drivers (Apache, Nginx, IIS) or provide manual configuration steps (Cloudflare, Caddy, Node.js).

## 🧠 Intelligent Trigger (When to use this skill)

**You MUST use this skill whenever:**
1.  The user mentions "VAPTBuilder".
2.  **The user references "VAPTBuilder", "99-item catalog", or "SixT catalog".**
3.  The task involves implementing security controls from a risk list found in the resources.

## 📚 Source of Truth

*   **Primary Risk Catalog**: `.agent/skills/vapt-builder/resources/VAPT-Complete-Risk-Catalog-99.json`
*   **Supplementary Risk Catalog**: `.agent/skills/vapt-builder/resources/VAPT-SixT-Risk-Catalog-12.json`
*   **Driver System**:
    *   `vapt_htaccess_driver`: For Apache/Litespeed (native support).
    *   `vapt_nginx_driver`: For Nginx/OpenResty (native support).
    *   `vapt_iis_driver`: For IIS (native support).
    *   `vapt_hook_driver`: For WordPress-specific logic.
    *   `manual`: For Cloudflare, Caddy, Node.js, etc.

## 🛠️ Implementation Strategy

### 1. Server-Side Rules (Apache/Nginx/IIS) - **PRIORITY**

For any feature that can be implemented at the server level, check the target architecture and use the appropriate driver.

**Driver Selection:**
*   **Apache / Litespeed** -> `driver: "htaccess"`
*   **Nginx / OpenResty** -> `driver: "nginx"`
*   **IIS** -> `driver: "iis"`

**Schema Pattern (Native Drivers):**
```json
{
  "enforcement": {
    "driver": "nginx", // or "htaccess", "iis"
    "mappings": {
      "enable_feature": "add_header X-Frame-Options SAMEORIGIN always;" // Nginx syntax
    }
  }
}
```

### 2. Manual Configuration (Cloudflare/Caddy/Node.js)

For architectures without native plugin drivers, use `driver: "manual"` and provide the exact configuration code in `manual_steps`.

**Schema Pattern (Manual):**
```json
{
  "enforcement": {
    "driver": "manual",
    "manual_steps": [
      {
        "platform": "cloudflare",
        "description": "Create a WAF Custom Rule.",
        "code": "(http.request.uri.path eq \"/xmlrpc.php\") action: block"
      },
      {
        "platform": "caddy",
        "description": "Add to Caddyfile",
        "code": "@xmlrpc { path /xmlrpc.php } respond @xmlrpc 403"
      }
    ]
  }
}
```

### 3. Application Logic (WordPress Hooks)

Use the `VAPT_Hook_Driver` only when PHP/WP logic is required.

## 📋 JSON Schema Reference

When generating the `generated_schema` for a feature, use this exact structure:

```json
{
  "controls": [
    // 1. Functional Controls (Left Column)
    {
      "type": "toggle",
      "label": "Enable [Feature Name]",
      "key": "enable_[feature_key]",
      "help": "Description of what this does."
    },
    // 2. Verification Controls (Right Column)
    {
      "type": "test_action",
      "label": "Verify: [Test Name]",
      "key": "verify_[test_key]",
      "test_logic": "universal_probe",
      "test_config": {
        "method": "GET", // or POST, HEAD
        "path": "/target/path",
        "expected_status": 403, // or 200, 404
        "expected_headers": { "X-VAPTC-Enforced": "[feature_key]" } // Evidence header
      }
    }
  ],
  "enforcement": {
    "driver": "htaccess", // CHANGE TO 'hook' if necessary
    "mappings": {
      "enable_[feature_key]": "[Raw .htaccess rules or Hook Method Name]"
    }
  }
}
```

## 🎨 UI Guidelines

1.  **Layout**: The dashboard expects controls in specific order.
    *   **Functional Inputs**: Defined first.
    *   **Test Actions**: Defined second (types: `test_action`).
    *   **Operational Notes**: Defined last (key: `operational_notes`).
2.  **Context**: Use the `help` property to provide tooltips.

## 🧪 Verification Engine

Always include `test_action` controls. The preferred logic is `universal_probe`.

*   **Positive Test**: Does the page load normally when it should? (Status 200)
*   **Negative Test**: Is the malicious request blocked? (Status 403)
*   **Evidence**: Does the response contain the `X-VAPTC-Enforced` header?

## 🚀 Workflow

1.  **Analyze**: Read the feature details.
2.  **Determine Target**: Ask or infer the user's server stack (Apache, Nginx, IIS, etc.).
3.  **Strategy**:
    *   **Native Supported**: Use `htaccess`, `nginx`, or `iis` drivers.
    *   **Manual Required**: Use `manual` driver for Cloudflare, Caddy, Node.
    *   **WordPress Logic**: Use `hook` driver.
4.  **Generate**: Create the JSON schema with Controls + Enforcement.
5.  **Verify**: Ensure `test_action` is configured to prove the protection works.

## ⚠️ Critical Constraints

*   **No Custom PHP Files**: Do not suggest creating new PHP files. Use the existing plugin infrastructure.
*   **Valid JSON**: The output must be valid JSON, parsable by `json_decode()`.
*   **Escape Characters**: When putting code (like Regex) into JSON strings, strictly escape backslashes (e.g., `\\` becomes `\\\\`).

## 📂 Included Resources

This skill comes with specialized resources to speed up implementation:

### `/resources/driver-reference.json`

A complete lookup table for:
*   **Htaccess Directives**: Allowed/Forbidden directives for the htaccess driver.
*   **Hook Driver Methods**: All available PHP enforcement methods in `VAPT_Hook_Driver`.
*   **Probe Schemas**: Configuration reference for `universal_probe` and others.

### `/examples/apache-templates.conf`

Pre-written, VAPT-ready `.htaccess` templates for:
*   Security Headers (HSTS, X-Frame-Options, etc.)
*   Blocking Sensitive Files (`wp-config.php`, `.log`)
*   Blocking XML-RPC
*   Disabling Directory Browsing


### `/examples/complete-schema-example.json`

A full JSON Schema example demonstrating:
1.  **Functional Controls**: Toggles with descriptions.
2.  **Verification**: Dual `test_action` probes (Positive & Negative tests).
3.  **Enforcement**: Use of `htaccess` driver with proper escaping.
4.  **Documentation**: `operational_notes` for context.

### `/scripts/validate-schema.js`

A Node.js utility to validate generated JSON files.
*   **Usage**: `node .agent/skills/vapt-builder/scripts/validate-schema.js <path-to-json>`
*   **Checks**: Verifies JSON syntax, required fields (`controls`, `enforcement`), driver validity, and maps keys between controls and enforcement.
