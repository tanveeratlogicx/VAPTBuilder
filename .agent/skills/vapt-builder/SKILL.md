---
name: vapt-builder
description: Specialized VAPT Builder skill trained on the 99-item Risk Catalog. Focuses on generating JSON configuration schemas for the VAPTBuilder plugin, specifically prioritizing .htaccess (Apache) rules for server-side security enforcement.
---

# VAPT Builder Expert Skill

This skill is a specialized extension of the generic WordPress VAPT expert, specifically tailored for the **VAPTBuilder Plugin**. It uses the `VAPT-Complete-Risk-Catalog-99.json` as its primary source of truth.

## 🎯 Primary Goal

To implement security features by **generating configuration schemas** rather than writing custom PHP code. The VAPTBuilder plugin uses a "Driver" system where you map features to existing drivers.

## 🧠 Intelligent Trigger (When to use this skill)

**You MUST use this skill whenever:**
1.  The user mentions "VAPTBuilder".
2.  **The active workspace contains a file matching `*Risk-Catalogue*.json` (e.g., `VAPT-Complete-Risk-Catalog-99.json`).**
3.  The task involves implementing security controls from a risk list.

## 📚 Source of Truth

*   **Risk Catalog**: `VAPTBuilder/data/VAPT-Complete-Risk-Catalog-99.json`
*   **Driver System**:
    *   `VAPT_Htaccess_Driver`: For all server-level blocking, headers, and access control.
    *   `VAPT_Hook_Driver`: For WordPress-specific logic (auth, XML-RPC, user enumeration).

## 🛠️ Implementation Strategy

### 1. Server-Side Rules (Apache/.htaccess) - **PRIORITY**

For any feature that *can* be implemented at the server level (e.g., blocking files, adding headers, stopping injection patterns), you **MUST** use the `htaccess` driver.

**Schema Pattern:**
```json
{
  "controls": [
    { "type": "toggle", "label": "Enable Feature", "key": "enable_feature" }
  ],
  "enforcement": {
    "driver": "htaccess",
    "mappings": {
      "enable_feature": "RewriteEngine On\nRewriteRule ^confidential/ - [F]"
    }
  }
}
```

**Common .htaccess Implementations:**
*   **Security Headers**: `Header set X-Content-Type-Options "nosniff"`
*   **Access Control**: `<FilesMatch ...> Deny from all </FilesMatch>`
*   **Blocking Parameters**: `RewriteCond %{QUERY_STRING} ...`

### 2. Application Logic (WordPress Hooks)

Use the `VAPT_Hook_Driver` only when PHP logic is required (e.g., user authentication, specific WP filters).

**Schema Pattern:**
```json
{
  "enforcement": {
    "driver": "hook",
    "mappings": {
      "enable_protection": "block_xmlrpc" // Must match a method in VAPT_Hook_Driver
    }
  }
}
```

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

1.  **Analyze**: Read the feature details from `VAPT-Complete-Risk-Catalog-99.json`.
2.  **Strategy**: Can this be done in `.htaccess`?
    *   **Yes**: Construct the Apache rules. Use `driver: "htaccess"`.
    *   **No**: Identify the `VAPT_Hook_Driver` method. Use `driver: "hook"`.
3.  **Generate**: Create the JSON schema with Controls + Enforcement.
4.  **Verify**: Ensure `test_action` is configured to prove the protection works.

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
