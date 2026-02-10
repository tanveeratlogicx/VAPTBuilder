---
description: Promotes a VAPT feature from Draft to Develop using the specialized vapt-builder skill.
---

1.  **Trigger**: User requests to transition a feature from "Draft" status to "Develop".
2.  **Information Gathering**:
    - Ask the user to click "Copy Design Prompt" for the feature in the VAPT Builder UI.
    - Alternatively, gather Risk ID, Title, and Remediation steps from the catalog (`VAPT-Complete-Risk-Catalog-99.json` or `VAPT-SixT-Risk-Catalog-12.json`).
3.  **Skill Activation**:
    - Explicitly activate the `vapt-builder` skill using `view_file` on its `SKILL.md`.
4.  **Draft Initial Build**:
    - Use the `vapt-builder` skill to generate a `generated_schema` JSON.
    - Ensure it includes `controls` (toggles, inputs), `enforcement` (driver and mappings), and `test_action` (universal_probe).
5.  **Schema Validation**:
    // turbo
    - Run `node .agent/skills/vapt-builder/scripts/validate-schema.js <path_to_temporary_json>` to verify the schema.
6.  **Workbench Handoff**:
    - Present the final JSON to the user.
    - Instruct the user to paste this into the "Workbench Design Hub" -> "JSON Schema Box" for the feature and click "Save & Deploy".
7.  **Status Promotion**:
    - Use the VAPT UI (or `update_feature` API) to set the feature status to "Develop".
8.  **Verification**:
    - Run the "Verify Protection" action (via `universal_probe`) to confirm the `X-VAPT-Enforced` header is present and the protection is active.
