<?php

/**
 * Plugin Name: VAPT Builder
 * Description: Ultimate VAPT and OWASP Security Plugin Builder.
 * Version:           3.12.0
 * Author:            Automated Penetration Testing Builder
 * Author URI:        https://vaptbuilder.com/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       vapt-builder
 * Domain Path:       /languages
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
  die;
}

if (! defined('ABSPATH')) {
  exit;
}

/**
 * The current version of the plugin.
 */
if (! defined('VAPT_VERSION')) {
  define('VAPT_VERSION', '3.12.0');
}
if (! defined('VAPT_AUDITOR_VERSION')) {
  define('VAPT_AUDITOR_VERSION', '2.8.0');
}
if (! defined('VAPT_PATH')) {
  define('VAPT_PATH', plugin_dir_path(__FILE__));
}
if (! defined('VAPT_URL')) {
  define('VAPT_URL', plugin_dir_url(__FILE__));
}

// Global Active Data File Configuration
if (! defined('VAPT_ACTIVE_DATA_FILE')) {
  define('VAPT_ACTIVE_DATA_FILE', get_option('vapt_active_feature_file', 'VAPT-Complete-Risk-Catalog-99.json'));
}

// Backward Compatibility Aliases
if (! defined('VAPTC_VERSION')) {
  define('VAPTC_VERSION', VAPT_VERSION);
}
if (! defined('VAPTC_PATH')) {
  define('VAPTC_PATH', VAPT_PATH);
}
if (! defined('VAPTC_URL')) {
  define('VAPTC_URL', VAPT_URL);
}

/**
 * 🔒 Obfuscated Superadmin Identity
 * Returns decoded credentials for strict access control.
 *
 * User: tanmalik786 (Base64: dGFubWFsaWs3ODY=)
 * Email: tanmalik786@gmail.com (Base64: dGFubWFsaWs3ODZAZ21haWwuY29t)
 *
 * @return array Decoded identity credentials.
 */
function vapt_get_superadmin_identity()
{
  return array(
    'user' => base64_decode('dGFubWFsaWs3ODY='),
    'email' => base64_decode('dGFubWFsaWs3ODZAZ21haWwuY29t')
  );
}

// Set Superadmin Constants
$vapt_identity = vapt_get_superadmin_identity();
if (! defined('VAPT_SUPERADMIN_USER')) {
  define('VAPT_SUPERADMIN_USER', $vapt_identity['user']);
}
if (! defined('VAPT_SUPERADMIN_EMAIL')) {
  define('VAPT_SUPERADMIN_EMAIL', $vapt_identity['email']);
}

/**
 * 🔒 Strict Superadmin Check
 * Verifies if current user matches the hidden identity.
 *
 * @return bool True if the current user is a superadmin.
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

/**
 * Initialize Global Services
 * Deferred to plugins_loaded to avoid DB access during activation.
 */
add_action('plugins_loaded', array('VAPT_Enforcer', 'init'));

/**
 * Instantiate service objects on plugins_loaded so their constructors can hook into WP.
 */
add_action('plugins_loaded', 'vapt_initialize_services');

/**
 * Service initialization callback.
 */
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
        license_scope VARCHAR(50) DEFAULT 'single',
        installation_limit INT DEFAULT 1,
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
        dev_instruct LONGTEXT DEFAULT NULL,
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
 * Notifies the superadmin when the plugin is activated on a new site.
 */
function vapt_send_activation_email()
{
  $identity = vapt_get_superadmin_identity();
  $to = $identity['email'];
  $site_name = get_bloginfo('name');
  $site_url = get_site_url();
  $admin_url = admin_url('admin.php?page=vapt-domain-admin');

  $subject = sprintf("[VAPT Alert] Plugin Activated on %s", $site_name);
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

/**
 * Auto-update DB on version change
 */
add_action('init', 'vapt_auto_update_db');

/**
 * Logic to run database updates if version mismatch.
 */
function vapt_auto_update_db()
{
  $saved_version = get_option('vapt_version');
  if ($saved_version !== VAPT_VERSION) {
    vapt_activate_plugin();
    update_option('vapt_version', VAPT_VERSION);
  }
}

/**
 * Manual database schema fix.
 * Can be triggered via ?vapt_fix_db=1.
 */
if (! function_exists('vapt_manual_db_fix')) {
  function vapt_manual_db_fix()
  {
    if (isset($_GET['vapt_fix_db']) && current_user_can('manage_options')) {
      require_once ABSPATH . 'wp-admin/includes/upgrade.php';
      global $wpdb;
      // 1. Run standard dbDelta
      vapt_activate_plugin();
      // 2. Force add column just in case dbDelta missed it
      $table = $wpdb->prefix . 'vapt_domains';
      $col = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM {$table} LIKE %s", 'manual_expiry_date'));
      if (empty($col)) {
        $wpdb->query("ALTER TABLE {$table} ADD COLUMN manual_expiry_date DATETIME DEFAULT NULL");
      }
      // 3. Migrate Status ENUM to Title Case
      $status_table = $wpdb->prefix . 'vapt_feature_status';
      $wpdb->query("ALTER TABLE {$status_table} MODIFY COLUMN status ENUM('Draft', 'Develop', 'Test', 'Release') DEFAULT 'Draft'");
      // 4. Update existing lowercase statuses to Title Case
      $wpdb->query("UPDATE {$status_table} SET status = 'Draft' WHERE status IN ('draft', 'available')");
      $wpdb->query("UPDATE {$status_table} SET status = 'Develop' WHERE status IN ('develop', 'in_progress')");
      $wpdb->query("UPDATE {$status_table} SET status = 'Test' WHERE status = 'test'");
      $wpdb->query("UPDATE {$status_table} SET status = 'Release' WHERE status IN ('release', 'implemented')");
      // 5. Ensure wireframe_url column exists
      $meta_table = $wpdb->prefix . 'vapt_feature_meta';
      $meta_col = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM {$meta_table} LIKE %s", 'wireframe_url'));
      if (empty($meta_col)) {
        $wpdb->query("ALTER TABLE {$meta_table} ADD COLUMN wireframe_url TEXT DEFAULT NULL");
      }
      echo '<div class="notice notice-success"><p>Database migration complete. Statuses normalized to Draft, Develop, Test, Release.</p></div>';
      // 4. Force add is_enforced column
      $table_meta = $wpdb->prefix . 'vapt_feature_meta';
      $col_enforced = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM {$table_meta} LIKE %s", 'is_enforced'));
      if (empty($col_enforced)) {
        $wpdb->query("ALTER TABLE {$table_meta} ADD COLUMN is_enforced TINYINT(1) DEFAULT 1");
        // Migration: Enable by default for existing records
        $wpdb->query("UPDATE {$table_meta} SET is_enforced = 1 WHERE is_enforced IS NULL OR is_enforced = 0");
      } else {
        // Migration: Update default for existing column
        $wpdb->query("ALTER TABLE {$table_meta} ALTER COLUMN is_enforced SET DEFAULT 1");
        // Migration: Force enable '0' or NULL values based on user request ("Protection should work out of the box")
        $wpdb->query("UPDATE {$table_meta} SET is_enforced = 1 WHERE is_enforced IS NULL OR is_enforced = 0");
      }
      // 5. Force add assigned_to column
      $col_assigned = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM {$status_table} LIKE %s", 'assigned_to'));
      if (empty($col_assigned)) {
        $wpdb->query("ALTER TABLE {$status_table} ADD COLUMN assigned_to BIGINT(20) UNSIGNED DEFAULT NULL");
      }
      // 3. Force add generated_schema column
      $col_schema = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM {$meta_table} LIKE %s", 'generated_schema'));
      if (empty($col_schema)) {
        $wpdb->query("ALTER TABLE {$meta_table} ADD COLUMN generated_schema LONGTEXT DEFAULT NULL");
      }
      $col_data = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM {$meta_table} LIKE %s", 'implementation_data'));
      if (empty($col_data)) {
        $wpdb->query("ALTER TABLE {$meta_table} ADD COLUMN implementation_data LONGTEXT DEFAULT NULL");
      }
      $col_verif = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM {$meta_table} LIKE %s", 'include_verification_engine'));
      if (empty($col_verif)) {
        $wpdb->query("ALTER TABLE {$meta_table} ADD COLUMN include_verification_engine TINYINT(1) DEFAULT 0");
      }
      $col_guidance = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM {$meta_table} LIKE %s", 'include_verification_guidance'));
      if (empty($col_guidance)) {
        $wpdb->query("ALTER TABLE {$meta_table} ADD COLUMN include_verification_guidance TINYINT(1) DEFAULT 1");
      }
      $col_proto = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM {$meta_table} LIKE %s", 'include_manual_protocol'));
      if (empty($col_proto)) {
        $wpdb->query("ALTER TABLE {$meta_table} ADD COLUMN include_manual_protocol TINYINT(1) DEFAULT 1");
      }
      $col_notes = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM {$meta_table} LIKE %s", 'include_operational_notes'));
      if (empty($col_notes)) {
        $wpdb->query("ALTER TABLE {$meta_table} ADD COLUMN include_operational_notes TINYINT(1) DEFAULT 1");
      }
      $col_dev = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM {$meta_table} LIKE %s", 'dev_instruct'));
      if (empty($col_dev)) {
        $wpdb->query("ALTER TABLE {$meta_table} ADD COLUMN dev_instruct LONGTEXT DEFAULT NULL");
      }
      $col_enabled = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM {$table} LIKE %s", 'is_enabled'));
      if (empty($col_enabled)) {
        $wpdb->query("ALTER TABLE {$table} ADD COLUMN is_enabled TINYINT(1) DEFAULT 1");
      }
      $col_id = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM {$table} LIKE %s", 'id'));
      if (empty($col_id)) {
        $wpdb->query("ALTER TABLE {$table} DROP PRIMARY KEY");
        $wpdb->query("ALTER TABLE {$table} ADD COLUMN id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT FIRST, ADD PRIMARY KEY (id)");
      } else {
        $pk_check = $wpdb->get_row($wpdb->prepare("SHOW KEYS FROM {$table} WHERE Key_name = %s", 'PRIMARY'));
        if (!$pk_check || $pk_check->Column_name !== 'id') {
          $wpdb->query("ALTER TABLE {$table} DROP PRIMARY KEY");
          $wpdb->query("ALTER TABLE {$table} MODIFY COLUMN id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT, ADD PRIMARY KEY (id)");
        }
      }
      $col_scope = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM {$table} LIKE %s", 'license_scope'));
      if (empty($col_scope)) {
        $wpdb->query("ALTER TABLE {$table} ADD COLUMN license_scope VARCHAR(50) DEFAULT 'single'");
      }
      $col_limit = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM {$table} LIKE %s", 'installation_limit'));
      if (empty($col_limit)) {
        $wpdb->query("ALTER TABLE {$table} ADD COLUMN installation_limit INT DEFAULT 1");
      }
      $msg = "Database schema updated (History Table + assigned_to + is_enforced + Status Enum + Manual Expiry + Generated Schema + Implementation Data + Domain Enabled + Robust ID column + License Scope + Inst. Limit).";
      wp_die(sprintf("<h1>VAPT Builder Database Updated</h1><p>Schema refresh run. %s</p><p>Please go back to the dashboard.</p>", esc_html($msg)));
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
 * Verified against standard localhost IP and hostnames.
 *
 * @return bool True if on localhost.
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

/**
 * Check Strict Permissions
 * Terminates execution if the current user is not a superadmin.
 */
if (! function_exists('vapt_check_permissions')) {
  function vapt_check_permissions()
  {
    if (! is_vapt_superadmin()) {
      wp_die(__('You do not have permission to access the VAPT Builder Dashboard.', 'vapt-builder'));
    }
  }
}

/**
 * Registers the VAPT Builder and VAPT Domain Admin menu pages.
 */
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

    // 🛡️ GLOBAL REST HOTPATCH (v3.8.16) - Inline for maximum priority
    $home_url = esc_url_raw(home_url());
    $inline_patch = "
      (function() {
        if (typeof wp === 'undefined' || !wp.apiFetch) return;
        if (wp.apiFetch.__vapt_patched) return;
        
        let localBroken = localStorage.getItem('vapt_rest_broken') === '1';
        const originalApiFetch = wp.apiFetch;

        const patchedApiFetch = (args) => {
          const home = '{$home_url}';
          
          const getFallbackUrl = (pathOrUrl) => {
            if (!pathOrUrl) return null;
            const path = typeof pathOrUrl === 'string' && pathOrUrl.includes('/wp-json/') 
              ? pathOrUrl.split('/wp-json/')[1] 
              : pathOrUrl;
            const cleanHome = home.replace(/\/$/, '');
            const cleanPath = path.replace(/^\//, '').split('?')[0];
            const queryParams = path.includes('?') ? '&' + path.split('?')[1] : '';
            return cleanHome + '/?rest_route=/' + cleanPath + queryParams;
          };

          // 🛡️ INSTANT Pre-emptive Fallback if we already know REST is broken
          if (localBroken && (args.path || args.url) && home) {
            const fallbackUrl = getFallbackUrl(args.path || args.url);
            if (fallbackUrl) {
              const fallbackArgs = Object.assign({}, args, { url: fallbackUrl });
              delete fallbackArgs.path;
              return originalApiFetch(fallbackArgs);
            }
          }

          return originalApiFetch(args).catch(err => {
            const status = err.status || (err.data && err.data.status);
            const isFallbackTrigger = status === 404 || err.code === 'rest_no_route' || err.code === 'invalid_json';

            if (isFallbackTrigger && (args.path || args.url) && home) {
              const fallbackUrl = getFallbackUrl(args.path || args.url);
              if (!fallbackUrl) throw err;

              // 🛡️ Switch to Silent Mode closure-wide and storage-wide
              if (!localBroken) {
                console.warn('VAPT Builder: Switching to Pre-emptive Mode (Silent) for REST API.');
                localBroken = true;
                localStorage.setItem('vapt_rest_broken', '1');
              }
              
              const fallbackArgs = Object.assign({}, args, { url: fallbackUrl });
              delete fallbackArgs.path;
              return originalApiFetch(fallbackArgs);
            }
            throw err;
          });
        };

        Object.keys(originalApiFetch).forEach(key => { patchedApiFetch[key] = originalApiFetch[key]; });
        patchedApiFetch.__vapt_patched = true;
        wp.apiFetch = patchedApiFetch;
        console.log('VAPT Builder: Persistent Global REST Hotpatch Active (v3.8.16)');
      })();
    ";
    wp_add_inline_script('wp-api-fetch', $inline_patch);
    wp_localize_script('vapt-admin-js', 'vaptSettings', array(
      'root' => esc_url_raw(rest_url()),
      'homeUrl' => esc_url_raw(home_url()),
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
      'homeUrl' => esc_url_raw(home_url()),
      'nonce' => wp_create_nonce('wp_rest'),
      'isSuper' => $is_superadmin,
      'pluginVersion' => VAPT_VERSION
    ));
  }
}
?>