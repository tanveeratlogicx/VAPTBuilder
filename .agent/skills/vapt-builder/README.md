# VAPT Builder Skill

**Specially trained agent skill for the VAPTBuilder WordPress Plugin.**

This skill equips the AI agent with the specific knowledge required to configure, enforce, and verify security features within the VAPTBuilder ecosystem. It adheres to the "Configuration over Implementation" philosophy, generating standardized configurations for **Apache, Nginx, IIS, Litespeed**, and providing manual guidance for **Cloudflare, Caddy,** and **Node.js**.

## 📂 Structure

*   **`SKILL.md`**: The primary instruction file for the AI agent. Defines the rules, strategies, and constraints.
*   **`resources/`**: Reference data used by the agent to ensure accuracy.
    *   `VAPT-Complete-Risk-Catalog-99-ENHANCED.json`: Unified enhanced risk catalog.
    *   `VAPT-*-Risk-Catalogue-*.json`: Driver-specific risk catalogs.
    *   `driver-reference.json`: Lookup table for valid drivers (`htaccess`, `hook`), directives, and probe types.
*   **`examples/`**: "Gold Standard" implementation patterns.
    *   `apache-templates.conf`: Verified `.htaccess` snippets.
    *   `nginx-custom-rules.conf`: Nginx security rules.
    *   `iis-web-config-snippet.xml`: IIS `web.config` patterns.
    *   `manual-implementation-patterns.md`: Guide for Cloudflare/Caddy/Node.js.
    *   `complete-schema-example.json`: A perfect example of a feature schema.
*   **`scripts/`**: Utility scripts for validation.
    *   `validate-schema.js`: Updated to support `nginx`, `iis`, and `manual` drivers.
    *   `detect-server.php`: Helper to identify target environment.

## 🎯 Usage

When the user asks for help with VAPTBuilder features (e.g., "Implement XML-RPC blocking"), the agent loads this skill to:
1.  Consult the Risk Catalog (external data).
2.  **Determine Server Type**: Identify if the target is Apache, Nginx, IIS, or other.
3.  **Select Driver**: Choose `htaccess`, `nginx`, `iis`, or `manual`.
4.  **Generate JSON**: Construct a valid schema with appropriate rules or manual steps.
5.  **Validation**: Verify the output against the `driver-reference.json` logic.

## 🛠 Maintenance

*   **Updating Drivers**: If the VAPTBuilder plugin adds a new driver or method, update `resources/driver-reference.json`.
*   **New Patterns**: If a new security best practice is adopted, add it to `examples/`.
*   **Agent Instructions**: Modify `SKILL.md` if the agent needs to change its behavior or priority.
