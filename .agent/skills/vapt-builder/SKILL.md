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

## ⚒️ Feature Implementation Protocol

Follow this strict protocol when asked to implement or update a feature:

1.  **Locate Feature**: Search the risk catalogs (Enhanced first, then Split) for the corresponding `risk_id` or title.
2.  **Verify Active Driver**: Identify the **Single Driver** suggested by the active datasource file (e.g., `htaccess`, `wp-config`, etc.).
3.  **Single Enforcer Strategy (CRITICAL)**: Use ONLY the driver associated with the active datasource. Do NOT provide multi-driver or "Hybrid" deployments.
4.  **Production-Ready Mappings**:
    *   Ensure mappings are **Toggle-Aware**. If a control is a toggle, the mapping value must be the literal string/code to be injected.
    *   Mappings must be precise. Avoid placeholders like `[your_value_here]`.
    *   For `htaccess`, wrap directives in `<IfModule>` if applicable for robustness.
5.  **Simplify UI**: Transmit only essential controls. Avoid presentational "clutter".
6.  **Define Verification**: Convert `testing.verification_steps` into one or more `test_action` controls using `universal_probe`.

## 📋 JSON Schema Reference

When generating the `generated_schema` for a feature, use this structure:

```json
{
  "controls": [
    {
      "type": "toggle",
      "label": "Enable [Feature Name]",
      "key": "feat_enabled",
      "default": false
    },
    {
      "type": "test_action",
      "label": "Verify Coverage",
      "key": "verify_feat",
      "test_logic": "universal_probe",
      "test_config": {
        "method": "GET",
        "path": "/",
        "expected_status": 200
      }
    }
  ],
  "enforcement": {
    "driver": "htaccess", 
    "mappings": {
      "feat_enabled": "Header set X-Frame-Options \"SAMEORIGIN\"" 
    }
  }
}
```

## 🔌 Driver Specifics

*   **`htaccess`**: Standard Apache directives. Must be escaped for JSON.
*   **`nginx`**: Standard Nginx directives (always ends with `;`).
*   **`wp-config` / `hook`**: PHP constants or method names. **IMPORTANT**: If the active datasource is `wp-config/hook`, prioritize these over `htaccess`.
*   **`manual`**: For manual steps where no driver exists.

## ⚠️ Critical Constraints

*   **No Hybrid Chains**: Never combine `htaccess` and `hook` in the same `enforcement` block.
*   **Single Enforcer**: Target exactly ONE enforcer as suggested by the Active Datasource File.
*   **Production Ready**: Output must be a complete, drop-in replacement for the interface.
*   **Escaping**: Escape backslashes (`\\\\`) and quotes properly.
