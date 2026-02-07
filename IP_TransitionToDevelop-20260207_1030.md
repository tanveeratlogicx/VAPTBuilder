# Implementation Plan - Intelligence to "Transition to Develop" Modal

## Changelog
- **2026-02-07 10:30**: Added intelligence to "Transition to Develop" modal by auto-populating "Development Instructions" from active datafile.

The goal is to automatically populate the "Development Instructions (AI Guidance)" field in the "Transition to Develop" modal with meaningful context derived from the active risk catalog. This will assist the "Workbench Designer" (AI) in generating the interface.

## User Review Required

> [!NOTE]
> This change modifies `assets/js/admin.js`. Please ensure that the browser cache is cleared after deployment to see the changes.

## Proposed Changes

### [VAPTBuilder](file:///t:/~/Local925%20Sites/hermasnet/app/public/wp-content/plugins/VAPTBuilder)

#### [MODIFY] [assets/js/admin.js](file:///t:/~/Local925%20Sites/hermasnet/app/public/wp-content/plugins/VAPTBuilder/assets/js/admin.js)

-   Create a comprehensive `generateDevInstructions(feature)` function.
-   **Data Extraction & Formatting:**
    -   **Identity**: Title, ID, Category, Severity (with CVSS score/vector if available).
    -   **Context**: Summary, Detailed Description, Attack Scenario, Affected Components.
    -   **Compliance**: OWASP Mapping, PCI DSS, GDPR, NIST, CWE references.
    -   **Technical Protection**:
        -   Remediation Effort, Estimated Time, Priority.
        -   **Automated Protection**: Method, Implementation Steps (file, code snippets).
        -   **Manual Steps**: Description, reason, verification.
        -   **Configuration**: `wp-config` constants, `htaccess` rules, `php.ini` settings.
    -   **Verification Engine**:
        -   **Automated Checks**: Check ID, Name, Method, Script, Success Criteria, Failure Message.
        -   **Continuous Monitoring**: Enabled, Frequency, Alerting.
    -   **Testing Protocol**:
        -   Test Method, Difficulty, Tools Required.
        -   **Verification Steps**: Step-by-step actions (automated & manual), commands, expected results.
        -   **Test Payloads**: Type, Payload, Expected Behavior.
    -   **UI Configuration**:
        -   **Components**: ID, Type (toggle, dropdown, etc.), Label, Description, Default Value, Options.
        -   layout & Actions.
    -   **Reporting**: Status Indicators, Export Formats.
    -   **Code Examples**: Language, Description, Code Snippets.
    -   **References**: URLs and Titles.
-   **Integration**:
    -   Update `LifecycleIndicator` to call this function when `newStatus === 'Develop'`.
    -   Populate `devInstruct` with this rich, structured text.

#### [NEW] [scripts/version-bump.js](file:///t:/~/Local925%20Sites/hermasnet/app/public/wp-content/plugins/VAPTBuilder/scripts/version-bump.js)

-   Create a Node.js script to automate version bumping.
-   **Functionality**:
    -   Read `package.json` to get/increment version.
    -   Update `package.json` with new version.
    -   Update `vapt-builder.php`:
        -   Regex replace `Version: x.x.x` in header.
        -   Regex replace `define('VAPT_VERSION', 'x.x.x');`.
    -   (Optional) Update `VAPT_AUDITOR_VERSION` if it tracks main version.
    -   Log the changes.

#### [MODIFY] [package.json](file:///t:/~/Local925%20Sites/hermasnet/app/public/wp-content/plugins/VAPTBuilder/package.json)

-   Add scripts:
    -   `"bump:patch": "node scripts/version-bump.js patch"`
    -   `"bump:minor": "node scripts/version-bump.js minor"`
    -   `"bump:major": "node scripts/version-bump.js major"`

## Verification Plan

### Manual Verification
-   **Step 1**: Open the VAPT Builder Dashboard.
-   **Step 2**: Locate a feature in "Draft" status.
-   **Step 3**: Click the status indicator to transition it to "Develop".
-   **Step 4**: Verify that the "Development Instructions (AI Guidance)" textarea is pre-filled with detailed, structured information derived from the feature's data.
-   **Step 5**: Check that the generated text includes the Risk Title, Description, Testing Steps, and recommended actions.
-   **Step 6**: Confirm that the text is editable.
