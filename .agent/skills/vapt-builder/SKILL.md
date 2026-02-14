---
name: vapt-builder
description: Specialized VAPT Builder skill trained on the 99-item Risk Catalog. Focuses on generating JSON configuration schemas for the VAPTBuilder plugin, serving as a single point of contact for implementing security features across various server drivers.
---

# VAPT Builder Expert Skill

This skill is the **Single Point of Contact** for implementing security features in the **VAPTBuilder Plugin**. It leverages a suite of structured JSON risk catalogs to provide precise implementation logic and UI configurations.

## 🎯 Primary Goal

To implement security features by **generating configuration schemas** (`generated_schema`) for various server architectures and WordPress environments.

## 🧠 Intelligent Trigger

**You MUST use this skill whenever:**
1.  The user mentions "VAPTBuilder" or "Workbench".
2.  The task involves implementing, modifying, or auditing security controls from the 99-item risk catalog.
3.  Generating JSON schemas for the VAPTBuilder Functional Workbench.

## 📚 Source of Truth (Risk Catalogs)

*   **Primary (Enhanced)**: `.agent/skills/vapt-builder/resources/VAPT-Complete-Risk-Catalog-99-ENHANCED.json`
*   **Split (Driver-Specific)**:
    *   `.agent/skills/vapt-builder/resources/VAPT-wp-config-Risk-Catalogue-87.json`
    *   `.agent/skills/vapt-builder/resources/VAPT-htaccess-Risk-Catalogue-3.json`
    *   `.agent/skills/vapt-builder/resources/VAPT-nginx-config-Risk-Catalogue-4.json`
    *   `.agent/skills/vapt-builder/resources/VAPT-file-system-Risk-Catalogue-5.json`
*   **Implementation Specs**: `.agent/skills/vapt-builder/resources/driver-reference.json`

## 🛠️ Feature Implementation Protocol

Follow this strict protocol when asked to implement or update a feature:

1.  **Locate Feature**: Search the risk catalogs (Enhanced first, then Split) for the corresponding `risk_id` or title.
2.  **Extract Implementation Logic**:
    *   Look at `protection.automated_protection.code` or `protection.configuration_changes`.
    *   Identify the target **Driver**: `htaccess`, `nginx`, `iis`, `wp-config`, or `hook`.
3.  **Map UI Configuration**:
    *   Translate the catalog's `ui_configuration.components` into the plugin's `controls` array.
    *   Standardize on `type: "toggle"` for most enforcements.
4.  **Configure Enforcement**:
    *   Use the `enforcement` object in the schema.
    *   Map the control keys (e.g., `enable_feature`) to the actual code/directive extracted in step 2.
5.  **Define Verification**:
    *   Convert `testing.verification_steps` into one or more `test_action` controls using `universal_probe`.

## 📋 JSON Schema Reference

When generating the `generated_schema` for a feature, use this structure:

```json
{
  "controls": [
    {
      "type": "toggle",
      "label": "Enable [Feature Name]",
      "key": "enable_[feature_key]",
      "help": "[Summary from Catalog]"
    },
    {
      "type": "test_action",
      "label": "Verify Coverage",
      "key": "verify_[feature_key]",
      "test_logic": "universal_probe",
      "test_config": {
        "method": "GET",
        "path": "/",
        "expected_status": 200,
        "expected_headers": { "X-VAPTC-Enforced": "[feature_key]" }
      }
    },
    {
      "type": "textarea",
      "label": "Operational Notes",
      "key": "operational_notes",
      "help": "Deployment specific context."
    }
  ],
  "enforcement": {
    "driver": "htaccess", // Use htaccess, nginx, iis, wp-config, or hook
    "mappings": {
      "enable_[feature_key]": "Header set X-Frame-Options \"SAMEORIGIN\"" 
    }
  }
}
```

## 🔌 Driver Specifics

*   **`htaccess`**: Standard Apache directives. Must be escaped for JSON.
*   **`nginx`**: Standard Nginx directives (always ends with `;`).
*   **`wp-config` / `hook`**: PHP constants or method names registered in `VAPT_Hook_Driver`.
*   **`manual`**: For manual steps where no driver exists.

## ⚠️ Critical Constraints

*   **No custom PHP files**: Use the `hook` driver for application-level logic.
*   **Strict JSON**: Must be valid for `json_decode()`.
*   **Escaping**: Escape backslashes (`\\\\`) and quotes properly.
*   **One Source**: Always cross-reference the `ENHANCED.json` catalog for the latest AI-compatible descriptions.
