# VAPT Builder Skill

**Specially trained agent skill for the VAPTBuilder WordPress Plugin.**

This skill equips the AI agent with the specific knowledge required to configure, enforce, and verify security features within the VAPTBuilder ecosystem. It strictly adheres to the "Configuration over Implementation" philosophy, prioritizing `.htaccess` rules and JSON configuration schemas over custom PHP code.

## 📂 Structure

*   **`SKILL.md`**: The primary instruction file for the AI agent. Defines the rules, strategies, and constraints.
*   **`resources/`**: Reference data used by the agent to ensure accuracy.
    *   `driver-reference.json`: Lookup table for valid drivers (`htaccess`, `hook`), directives, and probe types.
*   **`examples/`**: "Gold Standard" implementation patterns.
    *   `apache-templates.conf`: Verified `.htaccess` snippets.
    *   `complete-schema-example.json`: A perfect example of a feature schema.
*   **`scripts/`**: Utility scripts for validation.
    *   `validate-schema.js`: A Node.js tool to verify generated JSON schemas against plugin requirements.

## 🎯 Usage

When the user asks for help with VAPTBuilder features (e.g., "Implement XML-RPC blocking"), the agent loads this skill to:
1.  Consult the Risk Catalog (external data).
2.  Determine the best driver (Apache vs PHP).
3.  Generate a valid JSON schema.
4.  Construct necessary `.htaccess` rules or select the correct Hook method.
5.  Validate the output.

## 🛠 Maintenance

*   **Updating Drivers**: If the VAPTBuilder plugin adds a new driver or method, update `resources/driver-reference.json`.
*   **New Patterns**: If a new security best practice is adopted, add it to `examples/`.
*   **Agent Instructions**: Modify `SKILL.md` if the agent needs to change its behavior or priority.
