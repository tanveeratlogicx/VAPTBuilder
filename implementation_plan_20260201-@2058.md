# Implement Strict Superadmin Separation & Monitoring

## Goal Description
Fix the broken separation between "Superadmin" and "WordPress Admin [Client]" access. Currently, sensitive features like the "VAPT Auditor" and "Domain Admin" are exposed to regular administrators. We will implement a centralized, strict `is_vapt_superadmin()` helper and enforce it across Menus, Page Callbacks, AJAX endpoints, and Feature Visibility.

Additionally, to enhance security and "obfuscation", we will:
1.  **Remove** plain-text `VAPT_SUPERADMIN_USER` and `VAPT_SUPERADMIN_EMAIL` constants.
2.  **Obfuscate** these credentials using Base64 encoding hidden within the core logic, ensuring they are not easily readable by glancing at the code or `wp-config.php`.
3.  Add an **Activation Notification** system to alert the Superadmin when the plugin is activated.

## User Review Required
> [!IMPORTANT]
> This change will RESTRICT access to the "VAPT Auditor" tab and "Domain Admin" page. Regular administrators (clients) will no longer be able to see or access these pages.
>
> **Feature Visibility**: Regular Administrators (Clients) will **ONLY** see features that are in **'Release'** status AND explicitly enabled for their domain. Features in **'Draft'**, **'Develop'**, or **'Test'** will be strictly hidden from them.

## Proposed Changes

### Core Plugin File (`vapt-builder.php`)

#### [MODIFY] [vapt-builder.php](file:///t:/~/Local925%20Sites/hermasnet/app/public/wp-content/plugins/VAPTBuilder/vapt-builder.php)
-   **Remove Constants**: Delete `define('VAPT_SUPERADMIN_EMAIL', ...)` and `define('VAPT_SUPERADMIN_USER', ...)`.
-   **New Helper**: Implement `vapt_get_superadmin_identity()`:
    -   Returns array `['user' => 'decoded_user', 'email' => 'decoded_email']`.
    -   Stores credentials as Base64 strings:
        -   User: `dGFudmVlcg==` (tanveer)
        -   Email: `dGFudmVlckBsb2dpY3guaW8=` (tanveer@logicx.io)
-   **Refactor Checker**: Implement `is_vapt_superadmin()` using `vapt_get_superadmin_identity()`.
    -   Checks current user's login and email against the decoded values.
    -   Allows `localhost` overrides if still desired (or restricts strictly to these creds).
-   **Update**: Update `vapt_check_permissions()`, `vapt_add_admin_menu`, and asset enqueues to use `is_vapt_superadmin()`.
-   **Activation Hook**: Update `vapt_activate_plugin()` to send an email.
    -   Recipient: Decoded Superadmin Email.
    -   Subject: `[VAPT Alert] Plugin Activated on {Site_Name}`
    -   Body: `VAPT Builder activated. Admin URL: {link}`.

### Admin Class (`includes/class-vapt-admin.php`)

#### [MODIFY] [class-vapt-admin.php](file:///t:/~/Local925%20Sites/hermasnet/app/public/wp-content/plugins/VAPTBuilder/includes/class-vapt-admin.php)
-   **Menu & Access**: Replace all checks with `is_vapt_superadmin()`.
-   **Legacy Constants**: Ensure no code relies on the deleted `VAPT_SUPERADMIN_*` constants.

### REST Class (`includes/class-vapt-rest.php`)

#### [MODIFY] [class-vapt-rest.php](file:///t:/~/Local925%20Sites/hermasnet/app/public/wp-content/plugins/VAPTBuilder/includes/class-vapt-rest.php)
-   **Permissions**: Update `check_permission` to use `is_vapt_superadmin()`.
-   **Feature Visibility (`get_features`)**:
    -   Pass `is_vapt_superadmin()` result to filtering logic.
    -   IF `!is_superadmin`: Filter out ALL features NOT in 'Release' or 'Implemented' status.
    -   IF `!is_superadmin`: Ensure 'Release' features are only shown if enabled for the current domain.

## Verification Plan

### Manual Verification
1.  **Obfuscation Check**:
    -   Search code for "tanveer". Should NOT find the definition (only perhaps in comments if missed, but should be gone).
    -   Search for "logicx.io". Should NOT find it.
2.  **Access Control**:
    -   Log in as Superadmin. Verify Access.
    -   Log in as Normal Admin. Verify Denial.
3.  **Activation**:
    -   Deactivate/Reactivate. Verify Email sent (check local mail logs).
