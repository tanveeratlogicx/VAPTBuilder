# Skill Summary: VAPT Builder

## Capabilities
*   **Schema Generation**: Creates strict JSON schemas for the VAPTBuilder UI.
*   **Multi-Server Support**: Validated schemas for **Apache**, **Nginx**, **IIS**, and **Manual** configs (Cloudflare/Caddy).
*   **Native Drivers**: Generates native `nginx.conf` and `web.config` rules alongside `.htaccess`.
*   **Verification**: Automatically configures `universal_probe` tests to verify security controls.
*   **Validation**: Includes tooling to syntax-check generated configurations.

## Source of Truth
*   **Primary Catalog**: `resources/VAPT-Complete-Risk-Catalog-99-ENHANCED.json`
*   **Split Catalogs**: Driver-specific JSON files in `resources/`
*   **Plugin Version**: 3.12.2+
*   **Drivers**: `htaccess`, `nginx`, `iis`, `wp-config`, `hook`, `manual`

## Quick Manifest

| Component | Path | Purpose |
| :--- | :--- | :--- |
| **Instructions** | `SKILL.md` | Main agent prompt and guidelines. |
| **Reference** | `resources/driver-reference.json` | Valid method/directive lookup. |
| **Template** | `examples/apache-templates.conf` | Copy-paste .htaccess rules. |
| **Template** | `examples/nginx-custom-rules.conf` | Nginx security rules. |
| **Template** | `examples/iis-web-config-snippet.xml` | IIS configuration snippets. |
| **Guide** | `examples/manual-implementation-patterns.md` | Cloudflare/Caddy/Node patterns. |
| **Example** | `examples/complete-schema-example.json` | Reference JSON schema. |
| **Tool** | `scripts/validate-schema.js` | Schema validation script. |

## Key Philosophy
> "Do not write code when a configuration will suffice."

1.  **Prefer Server-Level Rules** (Native Drivers) where possible.
2.  **Use Manual Driver** for platforms like Cloudflare or Caddy.
2.  **Use existing methods** in `VAPT_Hook_Driver` for logic.
3.  **Always verify** with `test_action`.
