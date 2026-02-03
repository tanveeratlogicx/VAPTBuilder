# Skill Summary: VAPT Builder

## Capabilities
*   **Schema Generation**: Creates strict JSON schemas for the VAPTBuilder UI.
*   **Apache/Htaccess**: Generates validated `.htaccess` rules for security headers, access control, and blocking.
*   **Verification**: Automatically configures `universal_probe` tests to verify security controls.
*   **Validation**: Includes tooling to syntax-check generated configurations.

## Source of Truth
*   **Risk Catalog**: `data/VAPT-Complete-Risk-Catalog-99.json`
*   **Plugin Version**: 3.3.20+
*   **Drivers**: `VAPT_Htaccess_Driver`, `VAPT_Hook_Driver`

## Quick Manifest

| Component | Path | Purpose |
| :--- | :--- | :--- |
| **Instructions** | `SKILL.md` | Main agent prompt and guidelines. |
| **Reference** | `resources/driver-reference.json` | Valid method/directive lookup. |
| **Template** | `examples/apache-templates.conf` | Copy-paste .htaccess rules. |
| **Example** | `examples/complete-schema-example.json` | Reference JSON schema. |
| **Tool** | `scripts/validate-schema.js` | Schema validation script. |

## Key Philosophy
> "Do not write code when a configuration will suffice."

1.  **Prefer .htaccess** for all blocking/header logic.
2.  **Use existing methods** in `VAPT_Hook_Driver` for logic.
3.  **Always verify** with `test_action`.
