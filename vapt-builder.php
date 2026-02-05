<?php

/**
 * Plugin Name: VAPT Builder
 * Description: Ultimate VAPT and OWASP Security Plugin Builder.
 * Version:           3.3.46
 * Author:            Hermas International FZ LLE
 * Author URI:        #
 * License:           GPL-2.0+
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: vapt-builder
 */

if (! defined('ABSPATH')) {
  exit;
}

// Plugin Constants (Builder-specific)
define('VAPT_VERSION', '3.3.46');
define('VAPT_PATH', plugin_dir_path(__FILE__));
define('VAPT_URL', plugin_dir_url(__FILE__));

// Backward Compatibility Aliases
define('VAPTC_VERSION', VAPT_VERSION);
define('VAPTC_PATH', VAPT_PATH);
define('VAPTC_URL', VAPT_URL);

/**
 * 🔒 Obfuscated Superadmin Identity
 * Returns decoded credentials for strict access control.
 *
 * User: tanmalik786 (Base64: dGFubWFsaWs3ODY=)
 * Email: tanmalik786@gmail.com (Base64: dGFubWFsaWs3ODZAZ21haWwuY29t)
 */
function vapt_get_superadmin_identity()
{
  return array(
    'user' => base64_decode('dGFubWFsaWs3ODY='),
    'email' => base64_decode('dGFubWFsaWs3ODZAZ21haWwuY29t')
  );
}

/**
 * 🔒 Strict Superadmin Check
 * Verifies if current user matches the hidden identity.
 */
function is_vapt_superadmin()
{
  $current_user = wp_get_current_user();
  if (!$current_user->exists()) return false;

  $identity = vapt_get_superadmin_identity();
  $login = strtolower($current_user->user_login);
  $email = strtolower($current_user->user_email);

  // Strict Match
  if ($login === strtolower($identity['user']) || $email === strtolower($identity['email'])) {
    return true;
  }

  // Allow Localhost for development/testing (optional, keep enabled for now)
  /*
  if (is_vapt_localhost()) {
    return true;
  }
  */

  return false;
}

// Include core classes (new Builder includes)
require_once VAPT_PATH . 'includes/class-vapt-auth.php';
require_once VAPT_PATH . 'includes/class-vapt-rest.php';
require_once VAPT_PATH . 'includes/class-vapt-db.php';
require_once VAPT_PATH . 'includes/class-vapt-workflow.php';
require_once VAPT_PATH . 'includes/class-vapt-build.php';
require_once VAPT_PATH . 'includes/class-vapt-enforcer.php';
require_once VAPT_PATH . 'includes/class-vapt-scanner.php';
require_once VAPT_PATH . 'includes/class-vapt-admin.php';

// Initialize Global Services (deferred to plugins_loaded to avoid DB access during activation)
add_action('plugins_loaded', array('VAPT_Enforcer', 'init'));

// Instantiate other service objects on plugins_loaded so their constructors can hook into WP
add_action('plugins_loaded', 'vapt_initialize_services');
function vapt_initialize_services()
{
  if (class_exists('VAPT_REST')) {
    new VAPT_REST();
  }
  if (class_exists('VAPT_Auth')) {
    // Auth may provide static helpers but instantiate to register hooks if needed
    new VAPT_Auth();
  }
  if (class_exists('VAPT_Admin')) {
    new VAPT_Admin();
  }
  if (class_exists('VAPT_Scanner')) {
    new VAPT_Scanner();
  }
}

// Add cron hook for scans
add_action('vapt_run_scan', 'vapt_execute_scan', 10, 2);
function vapt_execute_scan($scan_id, $target_url)
{
  $scanner = new VAPT_Scanner();
  $scanner->run_scan($scan_id, $target_url);
}

/**
 * Activation Hook: Initialize Database Tables
 */
register_activation_hook(__FILE__, 'vapt_activate_plugin');
function vapt_activate_plugin()
{
  global $wpdb;
  $charset_collate = $wpdb->get_charset_collate();
  require_once ABSPATH . 'wp-admin/includes/upgrade.php';
  // Domains Table
  $table_domains = "CREATE TABLE {$wpdb->prefix}vapt_domains (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        domain VARCHAR(255) NOT NULL,
        is_wildcard TINYINT(1) DEFAULT 0,
        license_id VARCHAR(100),
        license_type VARCHAR(50) DEFAULT 'standard',
        first_activated_at DATETIME DEFAULT NULL,
        manual_expiry_date DATETIME DEFAULT NULL,
        auto_renew TINYINT(1) DEFAULT 0,
        renewals_count INT DEFAULT 0,
        renewal_history TEXT DEFAULT NULL,
        is_enabled TINYINT(1) DEFAULT 1,
        PRIMARY KEY  (id),
        UNIQUE KEY domain (domain)
    ) $charset_collate;";
  // Domain Features Table
  $table_features = "CREATE TABLE {$wpdb->prefix}vapt_domain_features (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        domain_id BIGINT(20) UNSIGNED NOT NULL,
        feature_key VARCHAR(100) NOT NULL,
        enabled TINYINT(1) DEFAULT 0,
        PRIMARY KEY  (id),
        KEY domain_id (domain_id)
    ) $charset_collate;";
  // Feature Status Table
  $table_status = "CREATE TABLE {$wpdb->prefix}vapt_feature_status (
        feature_key VARCHAR(100) NOT NULL,
        status ENUM('Draft', 'Develop', 'Test', 'Release') DEFAULT 'Draft',
        implemented_at DATETIME DEFAULT NULL,
        assigned_to BIGINT(20) UNSIGNED DEFAULT NULL,
        PRIMARY KEY  (feature_key)
    ) $charset_collate;";
  // Feature Meta Table
  $table_meta = "CREATE TABLE {$wpdb->prefix}vapt_feature_meta (
        feature_key VARCHAR(100) NOT NULL,
        category VARCHAR(100),
        test_method TEXT,
        verification_steps TEXT,
        include_test_method TINYINT(1) DEFAULT 0,
        include_verification TINYINT(1) DEFAULT 0,
        include_verification_engine TINYINT(1) DEFAULT 0,
        include_verification_guidance TINYINT(1) DEFAULT 1,
        include_manual_protocol TINYINT(1) DEFAULT 1,
        include_operational_notes TINYINT(1) DEFAULT 1,
        is_enforced TINYINT(1) DEFAULT 0,
        wireframe_url TEXT DEFAULT NULL,
        generated_schema LONGTEXT DEFAULT NULL,
        implementation_data LONGTEXT DEFAULT NULL,
        PRIMARY KEY  (feature_key)
    ) $charset_collate;";
  // Feature History/Audit Table
  $table_history = "CREATE TABLE {$wpdb->prefix}vapt_feature_history (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        feature_key VARCHAR(100) NOT NULL,
        old_status VARCHAR(50),
        new_status VARCHAR(50),
        user_id BIGINT(20) UNSIGNED,
        note TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY  (id),
        KEY feature_key (feature_key)
    ) $charset_collate;";
  // Build History Table
  $table_builds = "CREATE TABLE {$wpdb->prefix}vapt_domain_builds (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        domain VARCHAR(255) NOT NULL,
        version VARCHAR(50) NOT NULL,
        features TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY  (id),
        KEY domain (domain)
    ) $charset_collate;";
  // Scans Table
  $table_scans = "CREATE TABLE {$wpdb->prefix}vapt_scans (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        target_url VARCHAR(500) NOT NULL,
        status ENUM('pending', 'running', 'completed', 'failed') DEFAULT 'pending',
        started_at DATETIME DEFAULT NULL,
        completed_at DATETIME DEFAULT NULL,
        user_id BIGINT(20) UNSIGNED DEFAULT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY  (id),
        KEY target_url (target_url),
        KEY status (status)
    ) $charset_collate;";
  // Scan Results Table
  $table_scan_results = "CREATE TABLE {$wpdb->prefix}vapt_scan_results (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        scan_id BIGINT(20) UNSIGNED NOT NULL,
        vulnerability_id VARCHAR(100) NOT NULL,
        severity ENUM('critical', 'high', 'medium', 'low') NOT NULL,
        affected_url VARCHAR(500),
        description TEXT,
        impact TEXT,
        recommendation TEXT,
        steps_to_reproduce TEXT,
        evidence_url VARCHAR(500),
        screenshot_path VARCHAR(500),
        found_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY  (id),
        KEY scan_id (scan_id),
        KEY severity (severity)
    ) $charset_collate;";
  dbDelta($table_domains);
  dbDelta($table_features);
  dbDelta($table_status);
  dbDelta($table_meta);
  dbDelta($table_history);
  dbDelta($table_builds);
  dbDelta($table_scans);
  dbDelta($table_scan_results);
  // Ensure data directory exists
  if (! file_exists(VAPT_PATH . 'data')) {
    wp_mkdir_p(VAPT_PATH . 'data');
  }

  // 🔔 Send Activation Email to Superadmin (Only on fresh activation)
  $existing_version = get_option('vapt_version');
  if (empty($existing_version)) {
    vapt_send_activation_email();
  }
}

/**
 * Send Activation Email
 */
function vapt_send_activation_email()
{
  $identity = vapt_get_superadmin_identity();
  $to = $identity['email'];
  $site_name = get_bloginfo('name');
  $site_url = get_site_url();
  $admin_url = admin_url('admin.php?page=vapt-domain-admin');

  $subject = "[VAPT Alert] Plugin Activated on $site_name";
  $message = "VAPT Builder has been activated on a new site.\n\n";
  $message .= "Site Name: $site_name\n";
  $message .= "Site URL: $site_url\n";
  $message .= "Activation Date: " . current_time('mysql') . "\n";
  $message .= "Access Dashboard: $admin_url\n\n";
  $message .= "This is an automated security notification.";

  $headers = array('Content-Type: text/plain; charset=UTF-8');

  wp_mail($to, $subject, $message, $headers);
}

/**
 * Manual DB Fix Trigger (Force Run)
 */
add_action('init', 'vapt_manual_db_fix');
add_action('init', 'vapt_auto_update_db');
function vapt_auto_update_db()
{
  $saved_version = get_option('vapt_version');
  if ($saved_version !== VAPT_VERSION) {
    vapt_activate_plugin();
    update_option('vapt_version', VAPT_VERSION);
  }
}
if (! function_exists('vapt_manual_db_fix')) {
  function vapt_manual_db_fix()
  {
    if (isset($_GET['vapt_fix_db']) && current_user_can('manage_options')) {
      require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
      global $wpdb;
      // 1. Run standard dbDelta
      vapt_activate_plugin();
      // 2. Force add column just in case dbDelta missed it
      $table = $wpdb->prefix . 'vapt_domains';
      $col = $wpdb->get_results("SHOW COLUMNS FROM $table LIKE 'manual_expiry_date'");
      if (empty($col)) {
        $wpdb->query("ALTER TABLE $table ADD COLUMN manual_expiry_date DATETIME DEFAULT NULL");
      }
      // 3. Migrate Status ENUM to Title Case
      $status_table = $wpdb->prefix . 'vapt_feature_status';
      $wpdb->query("ALTER TABLE $status_table MODIFY COLUMN status ENUM('Draft', 'Develop', 'Test', 'Release') DEFAULT 'Draft'");
      // 4. Update existing lowercase statuses to Title Case
      $wpdb->query("UPDATE $status_table SET status = 'Draft' WHERE status IN ('draft', 'available')");
      $wpdb->query("UPDATE $status_table SET status = 'Develop' WHERE status IN ('develop', 'in_progress')");
      $wpdb->query("UPDATE $status_table SET status = 'Test' WHERE status = 'test'");
      $wpdb->query("UPDATE $status_table SET status = 'Release' WHERE status IN ('release', 'implemented')");
      // 5. Ensure wireframe_url column exists
      $meta_table = $wpdb->prefix . 'vapt_feature_meta';
      $meta_col = $wpdb->get_results("SHOW COLUMNS FROM $meta_table LIKE 'wireframe_url'");
      if (empty($meta_col)) {
        $wpdb->query("ALTER TABLE $meta_table ADD COLUMN wireframe_url TEXT DEFAULT NULL");
      }
      echo '<div class="notice notice-success"><p>Database migration complete. Statuses normalized to Draft, Develop, Test, Release.</p></div>';
      // 4. Force add is_enforced column
      $table_meta = $wpdb->prefix . 'vapt_feature_meta';
      $col_enforced = $wpdb->get_results("SHOW COLUMNS FROM $table_meta LIKE 'is_enforced'");
      if (empty($col_enforced)) {
        $wpdb->query("ALTER TABLE $table_meta ADD COLUMN is_enforced TINYINT(1) DEFAULT 0");
      }
      // 5. Force add assigned_to column
      $col_assigned = $wpdb->get_results("SHOW COLUMNS FROM $status_table LIKE 'assigned_to'");
      if (empty($col_assigned)) {
        $wpdb->query("ALTER TABLE $status_table ADD COLUMN assigned_to BIGINT(20) UNSIGNED DEFAULT NULL");
      }
      // 3. Force add generated_schema column
      $col_schema = $wpdb->get_results("SHOW COLUMNS FROM $meta_table LIKE 'generated_schema'");
      if (empty($col_schema)) {
        $wpdb->query("ALTER TABLE $meta_table ADD COLUMN generated_schema LONGTEXT DEFAULT NULL");
      }
      $col_data = $wpdb->get_results("SHOW COLUMNS FROM $meta_table LIKE 'implementation_data'");
      if (empty($col_data)) {
        $wpdb->query("ALTER TABLE $meta_table ADD COLUMN implementation_data LONGTEXT DEFAULT NULL");
      }
      $col_verif = $wpdb->get_results("SHOW COLUMNS FROM $meta_table LIKE 'include_verification_engine'");
      if (empty($col_verif)) {
        $wpdb->query("ALTER TABLE $meta_table ADD COLUMN include_verification_engine TINYINT(1) DEFAULT 0");
      }
      $col_guidance = $wpdb->get_results("SHOW COLUMNS FROM $meta_table LIKE 'include_verification_guidance'");
      if (empty($col_guidance)) {
        $wpdb->query("ALTER TABLE $meta_table ADD COLUMN include_verification_guidance TINYINT(1) DEFAULT 1");
      }
      $col_proto = $wpdb->get_results("SHOW COLUMNS FROM $meta_table LIKE 'include_manual_protocol'");
      if (empty($col_proto)) {
        $wpdb->query("ALTER TABLE $meta_table ADD COLUMN include_manual_protocol TINYINT(1) DEFAULT 1");
      }
      $col_notes = $wpdb->get_results("SHOW COLUMNS FROM $meta_table LIKE 'include_operational_notes'");
      if (empty($col_notes)) {
        $wpdb->query("ALTER TABLE $meta_table ADD COLUMN include_operational_notes TINYINT(1) DEFAULT 1");
      }
      $col_enabled = $wpdb->get_results("SHOW COLUMNS FROM $table LIKE 'is_enabled'");
      if (empty($col_enabled)) {
        $wpdb->query("ALTER TABLE $table ADD COLUMN is_enabled TINYINT(1) DEFAULT 1");
      }
      $col_id = $wpdb->get_results("SHOW COLUMNS FROM $table LIKE 'id'");
      if (empty($col_id)) {
        $wpdb->query("ALTER TABLE $table DROP PRIMARY KEY");
        $wpdb->query("ALTER TABLE $table ADD COLUMN id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT FIRST, ADD PRIMARY KEY (id)");
      } else {
        $pk_check = $wpdb->get_row("SHOW KEYS FROM $table WHERE Key_name = 'PRIMARY'");
        if (!$pk_check || $pk_check->Column_name !== 'id') {
          $wpdb->query("ALTER TABLE $table DROP PRIMARY KEY");
          $wpdb->query("ALTER TABLE $table MODIFY COLUMN id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT, ADD PRIMARY KEY (id)");
        }
      }
      $msg = "Database schema updated (History Table + assigned_to + is_enforced + Status Enum + Manual Expiry + Generated Schema + Implementation Data + Domain Enabled + Robust ID column).";
      wp_die("<h1>VAPT Builder Database Updated</h1><p>Schema refresh run. $msg</p><p>Please go back to the dashboard.</p>");
    }
  }
}

/**
 * Workbench Action Handler (Ajax-Alternative via GET)
 */
add_action('init', function () {
  if (isset($_GET['vapt_action']) && current_user_can('manage_options')) {
    $action = sanitize_text_field($_GET['vapt_action']);
    if ($action === 'reset_rate_limits') {
      require_once VAPT_PATH . 'includes/enforcers/class-vapt-hook-driver.php';
      VAPT_Hook_Driver::reset_limit();
      wp_die("Rate limits reset successfully.", "VAPT Builder Reset", array('response' => 200, 'back_link' => true));
    }
  }
});

/**
 * Detect Localhost Environment
 */
/**
 * 🚨 FORCE FIX: API Rate Limiting
 * Trigger via URL: ?vapt_force_fix_ratelimit=1
 */
add_action('init', 'vapt_force_fix_ratelimit');
if (! function_exists('vapt_force_fix_ratelimit')) {
  function vapt_force_fix_ratelimit()
  {
    if (isset($_GET['vapt_force_fix_ratelimit']) && current_user_can('manage_options')) {
      global $wpdb;
      $key = 'api-rate-limiting';
      // 1. Force Schema with Enforcer Mapping
      $schema = array(
        'controls' => array(
          array('type' => 'toggle', 'label' => 'Enable API Rate Limiting', 'key' => 'enable_api_rate_limiting', 'help' => 'Activates the global rate limiting middleware.'),
          array('type' => 'test_action', 'label' => 'Test: Burst Resilience (13 req/min)', 'key' => 'verif_rate_limit', 'test_logic' => 'spam_requests', 'help' => 'Sends a sharp burst of traffic to test server stability.'),
          array('type' => 'test_action', 'label' => 'Test: Limit Enforcement', 'key' => 'verif_limit_enforce', 'test_logic' => 'default', 'help' => 'Intentionally exceeds the limit to verify HTTP 429 response.')
        ),
        'enforcement' => array('driver' => 'hook', 'mappings' => array('enable_api_rate_limiting' => 'limit_login_attempts'))
      );
      // 2. Direct DB Update
      $table = $wpdb->prefix . 'vapt_feature_meta';
      $exists = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $table WHERE feature_key = %s", $key));
      if (!$exists) {
        $wpdb->insert($table, array('feature_key' => $key, 'is_enforced' => 1));
      }
      $wpdb->update($table, array('generated_schema' => json_encode($schema), 'is_enforced' => 1, 'include_verification_engine' => 1), array('feature_key' => $key));
      // 3. Clear Cache
      delete_transient('vapt_active_enforcements');
      // 4. Set Implementation Data if empty
      $meta = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE feature_key = %s", $key), ARRAY_A);
      if (empty($meta['implementation_data'])) {
        $impl = array('enable_api_rate_limiting' => true);
        $wpdb->update($table, array('implementation_data' => json_encode($impl)), array('feature_key' => $key));
      }
      die("<h1>VAPTM: Rate Limit Force Fix Applied! 🛡️</h1><p>Schema Updated. Enforcement Forced = 1. Cache Cleared.</p><a href='/wp-admin/admin.php?page=vapt-builder'>Return to Dashboard</a>");
    }
  }
}

/**
 * 🚨 FORCE FIX: WordPress Version Disclosure Feature
 */
add_action('init', 'vapt_force_fix_wp_version_disclosure');
if (! function_exists('vapt_force_fix_wp_version_disclosure')) {
  function vapt_force_fix_wp_version_disclosure()
  {
    if (isset($_GET['vapt_force_fix_wp_version']) && current_user_can('manage_options')) {
      global $wpdb;
      $key = 'vapt-version-disclosure';
      $table = $wpdb->prefix . 'vapt_feature_meta';
      $schema = array(
        'controls' => array(
          array('type' => 'toggle', 'label' => 'Hide WordPress Version', 'key' => 'hide_wp_version', 'help' => 'Removes the WordPress generator meta tag and signals enforcement via headers.'),
          array('type' => 'test_action', 'label' => 'Verify: Version Hidden', 'key' => 'verif_hide_version', 'test_logic' => 'hide_wp_version', 'help' => 'Checks that the generator tag is removed and plugin enforcement header is present.')
        ),
        'enforcement' => array('driver' => 'hook', 'mappings' => array('hide_wp_version' => 'hide_wp_version'))
      );
      $exists = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $table WHERE feature_key = %s", $key));
      if (!$exists) {
        $wpdb->insert($table, array('feature_key' => $key, 'category' => 'Information Disclosure', 'include_test_method' => 1, 'include_verification' => 1, 'include_verification_engine' => 1, 'is_enforced' => 1));
      }
      $wpdb->update($table, array('generated_schema' => json_encode($schema), 'include_verification_engine' => 1, 'is_enforced' => 1), array('feature_key' => $key));
      $meta = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE feature_key = %s", $key), ARRAY_A);
      if (empty($meta['implementation_data'])) {
        $impl = array('hide_wp_version' => true);
        $wpdb->update($table, array('implementation_data' => json_encode($impl)), array('feature_key' => $key));
      }
      delete_transient('vapt_active_enforcements');
      wp_die("<h1>VAPTM: WordPress Version Disclosure Fix Applied 🛡️</h1><p>The feature <strong>WordPress Version Disclosure</strong> is now fully wired:</p><ul><li>Functional toggle: Hide WordPress Version</li><li>Enforcement driver: hook → hide_wp_version()</li><li>Verification: test_action using hide_wp_version probe</li></ul><p>You can now open the VAPT dashboard, enable <em>Hide WordPress Version</em>, and run the verification test to see real results.</p><a href='/wp-admin/admin.php?page=vapt-builder'>Return to Dashboard</a>");
    }
  }
}

/**
 * 🚨 FORCE FIX: Debug Exposure Feature
 */
add_action('init', 'vapt_force_fix_wp_debug_exposure');
if (! function_exists('vapt_force_fix_wp_debug_exposure')) {
  function vapt_force_fix_wp_debug_exposure()
  {
    if (isset($_GET['vapt_force_fix_wp_debug']) && current_user_can('manage_options')) {
      global $wpdb;
      $key = 'wp-debug-exposure';
      $table = $wpdb->prefix . 'vapt_feature_meta';
      $schema = array(
        'controls' => array(
          array('type' => 'toggle', 'label' => 'Standardize Debug Output', 'key' => 'block_debug_exposure', 'help' => 'Suppresses verbose PHP errors and signals enforcement via headers.'),
          array('type' => 'test_action', 'label' => 'Verify: Debug Exposure Blocked', 'key' => 'verif_debug_block', 'test_logic' => 'universal_probe', 'test_config' => array('method' => 'GET', 'path' => '/', 'expected_headers' => array('X-VAPTC-Enforced' => 'php-debug-exposure')), 'help' => 'Checks for the plugin enforcement header in the home page response.'),
          array('type' => 'test_action', 'label' => 'Verify: debug.log access', 'key' => 'verif_debug_log', 'test_logic' => 'universal_probe', 'test_config' => array('method' => 'GET', 'path' => '/wp-content/debug.log', 'expected_status' => 403), 'help' => 'Checks that access to debug.log returns HTTP 403.')
        ),
        'enforcement' => array('driver' => 'hook', 'mappings' => array('block_debug_exposure' => 'block_debug_exposure'))
      );
      $exists = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $table WHERE feature_key = %s", $key));
      if (!$exists) {
        $wpdb->insert($table, array('feature_key' => $key, 'category' => 'Compliance & Privacy', 'include_test_method' => 1, 'include_verification' => 1, 'include_verification_engine' => 1, 'is_enforced' => 1));
      }
      $wpdb->update($table, array('generated_schema' => json_encode($schema), 'include_verification_engine' => 1, 'is_enforced' => 1), array('feature_key' => $key));
      $meta = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE feature_key = %s", $key), ARRAY_A);
      if (empty($meta['implementation_data'])) {
        $impl = array('block_debug_exposure' => true);
        $wpdb->update($table, array('implementation_data' => json_encode($impl)), array('feature_key' => $key));
      }
      delete_transient('vapt_active_enforcements');
      wp_die("<h1>VAPTM: Debug Exposure Fix Applied 🛡️</h1><p>The feature <strong>WP-DEBUG-EXPOSURE</strong> is now fully wired:</p><ul><li>Functional toggle: Standardize Debug Output</li><li>Enforcement driver: hook → block_debug_exposure()</li><li>Verification 1: Header check for php-debug-exposure</li><li>Verification 2: 403 Block for debug.log</li></ul><a href='/wp-admin/admin.php?page=vapt-builder'>Return to Dashboard</a>");
    }
  }
}

/**
 * Detect Localhost Environment
 */
if (! function_exists('is_vapt_localhost')) {
  function is_vapt_localhost()
  {
    $whitelist = array('127.0.0.1', '::1', 'localhost');
    $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
    $addr = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
    if (in_array($addr, $whitelist) || in_array($host, $whitelist)) {
      return true;
    }
    $dev_suffixes = array('.local', '.test', '.dev', '.wp', '.site');
    foreach ($dev_suffixes as $suffix) {
      if (strpos($host, $suffix) !== false) {
        return true;
      }
    }
    return false;
  }
}

/**
 * Admin Menu Setup
 */
add_action('admin_menu', 'vapt_add_admin_menu');


// Global to store hook suffixes for asset loading
$vapt_hooks = array();

/**
 * Check Strict Permissions
 */
if (! function_exists('vapt_check_permissions')) {
  function vapt_check_permissions()
  {
    if (! is_vapt_superadmin()) {
      wp_die(__('You do not have permission to access the VAPT Builder Dashboard.', 'vapt-builder'));
    }
  }
}

if (! function_exists('vapt_add_admin_menu')) {
  function vapt_add_admin_menu()
  {
    $is_superadmin = is_vapt_superadmin();
    // 1. Parent Menu
    add_menu_page(
      __('VAPT Builder', 'vapt-builder'),
      __('VAPT Builder', 'vapt-builder'),
      'manage_options',
      'vapt-builder',
      'vapt_render_client_status_page',
      'dashicons-shield',
      80
    );
    // 2. Sub-menu 1: Status
    add_submenu_page(
      'vapt-builder',
      __('VAPT Builder-Workbench', 'vapt-builder'),
      __('VAPT Builder-Workbench', 'vapt-builder'),
      'manage_options',
      'vapt-builder',
      'vapt_render_client_status_page'
    );
    // 3. Sub-menu 2: Domain Admin (Superadmin Only)
    if ($is_superadmin) {
      add_submenu_page(
        'vapt-builder',
        __('VAPT Domain Admin', 'vapt-builder'),
        __('VAPT Domain Admin', 'vapt-builder'),
        'manage_options',
        'vapt-domain-admin',
        'vapt_render_admin_page'
      );
    }
  }
}

/**
 * Handle Legacy Slug Redirects
 */
add_action('admin_init', 'vapt_handle_legacy_redirects');
if (! function_exists('vapt_handle_legacy_redirects')) {
  function vapt_handle_legacy_redirects()
  {
    if (!isset($_GET['page'])) return;
    $legacy_slugs = array('vapt-copilot', 'vapt-copilot-main', 'vapt-copilot-status', 'vapt-copilot-domain-build', 'vapt-client');
    if (in_array($_GET['page'], $legacy_slugs)) {
      wp_safe_redirect(admin_url('admin.php?page=vapt-builder'));
      exit;
    }
  }
}

/**
 * Localhost Admin Notice
 */


/**
 * Render Client Status Page
 */
if (! function_exists('vapt_render_client_status_page')) {
  function vapt_render_client_status_page()
  {
?>
    <div class="wrap">
      <h1 class="wp-heading-inline"><?php _e('VAPT Builder', 'vapt-builder'); ?></h1>
      <hr class="wp-header-end" />
      <div id="vapt-client-root">
        <div style="padding: 40px; text-align: center; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-radius: 4px;">
          <span class="spinner is-active" style="float: none; margin: 0 auto;"></span>
          <p><?php _e('Loading Implementation Workbench...', 'vapt-builder'); ?></p>
        </div>
      </div>
    </div>
  <?php
  }
}

/**
 * Render Main Admin Page
 */
if (! function_exists('vapt_render_admin_page')) {
  function vapt_render_admin_page()
  {
    vapt_check_permissions();
    vapt_master_dashboard_page();
  }
}

if (! function_exists('vapt_master_dashboard_page')) {
  function vapt_master_dashboard_page()
  {
    // Verify Identity
    if (! VAPT_Auth::is_authenticated()) {
      $identity = vapt_get_superadmin_identity();
      if (! get_transient('vapt_otp_email_' . $identity['user'])) {
        VAPT_Auth::send_otp();
      }
      VAPT_Auth::render_otp_form();
      return;
    }
  ?>
    <div id="vapt-admin-root" class="wrap">
      <h1><?php _e('VAPT Domain Admin', 'vapt-builder'); ?></h1>
      <div style="padding: 20px; text-align: center;">
        <span class="spinner is-active" style="float: none; margin: 0 auto;"></span>
        <p><?php _e('Loading VAPT Builder...', 'vapt-builder'); ?></p>
      </div>
    </div>
<?php
  }
}

/**
 * Enqueue Admin Assets
 */
add_action('admin_enqueue_scripts', 'vapt_enqueue_admin_assets');

/**
 * Enqueue Assets for React App
 */
function vapt_enqueue_admin_assets($hook)
{
  global $vapt_hooks;
  $GLOBALS['vapt_current_hook'] = $hook;
  $screen = get_current_screen();
  $current_user = wp_get_current_user();
  $is_superadmin = is_vapt_superadmin();
  if (!$screen) return;
  // Enqueue Shared Styles
  wp_enqueue_style('vapt-admin-css', VAPT_URL . 'assets/css/admin.css', array('wp-components'), VAPT_VERSION);
  // 1. Superadmin Dashboard (admin.js)
  if ($screen->id === 'toplevel_page_vapt-domain-admin' || $screen->id === 'vapt-builder_page_vapt-domain-admin') {
    error_log('VAPT Admin Assets Enqueued for: ' . $screen->id);
    // Enqueue Auto-Interface Generator (Module)
    wp_enqueue_script(
      'vapt-interface-generator',
      plugin_dir_url(__FILE__) . 'assets/js/modules/interface-generator.js',
      array(), // No deps, but strictly before admin.js
      VAPT_VERSION,
      true
    );
    // Enqueue Generated Interface UI Component
    wp_enqueue_script(
      'vapt-generated-interface-ui',
      plugin_dir_url(__FILE__) . 'assets/js/modules/generated-interface.js',
      array('wp-element', 'wp-components'),
      VAPT_VERSION,
      true
    );
    // Enqueue Admin Dashboard Script
    wp_enqueue_script(
      'vapt-admin-js',
      plugin_dir_url(__FILE__) . 'assets/js/admin.js',
      array('wp-element', 'wp-components', 'wp-api-fetch', 'wp-i18n', 'vapt-interface-generator', 'vapt-generated-interface-ui'),
      VAPT_VERSION,
      true
    );
    wp_localize_script('vapt-admin-js', 'vaptSettings', array(
      'root' => esc_url_raw(rest_url()),
      'nonce' => wp_create_nonce('wp_rest'),
      'isSuper' => $is_superadmin,
      'pluginVersion' => VAPT_VERSION
    ));
  }
  // 2. Client Dashboard (client.js) - "VAPT Builder" page
  if ($screen->id === 'toplevel_page_vapt-builder' || $screen->id === 'vapt-builder_page_vapt-builder') {
    // Enqueue Generated Interface UI Component (Shared)
    wp_enqueue_script(
      'vapt-generated-interface-ui',
      plugin_dir_url(__FILE__) . 'assets/js/modules/generated-interface.js',
      array('wp-element', 'wp-components'),
      VAPT_VERSION,
      true
    );
    // Enqueue Client Dashboard Script
    wp_enqueue_script(
      'vapt-client-js',
      plugin_dir_url(__FILE__) . 'assets/js/client.js',
      array('wp-element', 'wp-components', 'wp-i18n', 'vapt-generated-interface-ui'),
      VAPT_VERSION,
      true
    );
    wp_localize_script('vapt-client-js', 'vaptSettings', array(
      'root' => esc_url_raw(rest_url()),
      'nonce' => wp_create_nonce('wp_rest'),
      'pluginVersion' => VAPT_VERSION
    ));
  }
}
?>