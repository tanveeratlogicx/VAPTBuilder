<?php

/**
 * VAPT_Enforcer: The Global Security Hammer
 * 
 * Acts as a generic dispatcher that routes enforcement requests to specific drivers
 * (Htaccess, Hooks, etc.) based on the feature's generated_schema.
 */

if (!defined('ABSPATH')) exit;

class VAPT_Enforcer
{

  public static function init()
  {
    // Listen for workbench saves
    add_action('vapt_feature_saved', array(__CLASS__, 'dispatch_enforcement'), 10, 2);

    // Apply PHP-based hooks at runtime
    self::runtime_enforcement();
  }

  /**
   * Applies all active 'hook' based enforcements on every request
   */
  public static function runtime_enforcement()
  {
    $cache_key = 'vapt_active_enforcements';
    $enforced = get_transient($cache_key);

    if (false === $enforced) {
      global $wpdb;
      $table = $wpdb->prefix . 'vapt_feature_meta';
      $enforced = $wpdb->get_results("
        SELECT m.*, s.status 
        FROM $table m
        LEFT JOIN {$wpdb->prefix}vapt_feature_status s ON m.feature_key = s.feature_key
        WHERE m.is_enforced = 1
      ", ARRAY_A);
      set_transient($cache_key, $enforced, HOUR_IN_SECONDS);
    }

    if (empty($enforced)) return;

    require_once VAPT_PATH . 'includes/enforcers/class-vapt-hook-driver.php';

    foreach ($enforced as $meta) {
      $status = isset($meta['status']) ? strtolower($meta['status']) : 'draft';

      // Override Logic
      $use_override_schema = in_array($status, ['test', 'release']) && !empty($meta['override_schema']);
      $raw_schema = $use_override_schema ? $meta['override_schema'] : $meta['generated_schema'];
      $schema = !empty($raw_schema) ? json_decode($raw_schema, true) : array();

      $use_override_impl = in_array($status, ['test', 'release']) && !empty($meta['override_implementation_data']);
      $raw_impl = $use_override_impl ? $meta['override_implementation_data'] : $meta['implementation_data'];
      $impl_data = !empty($raw_impl) ? json_decode($raw_impl, true) : array();

      $driver = isset($schema['enforcement']['driver']) ? $schema['enforcement']['driver'] : '';

      // Hook driver is universally shared for PHP-based fallback rules
      if ($driver === 'hook' || $driver === 'universal' || $driver === 'htaccess') {
        if (class_exists('VAPT_Hook_Driver')) {
          VAPT_Hook_Driver::apply($impl_data, $schema, $meta['feature_key']);
        }
      }
    }
  }

  /**
   * Entry point for enforcement after a feature is saved
   */
  public static function dispatch_enforcement($key, $data)
  {
    // Clear runtime cache so changes apply instantly
    delete_transient('vapt_active_enforcements');

    $meta = VAPT_DB::get_feature_meta($key);
    if (!$meta) return;

    // Fetch Status for Context
    global $wpdb;
    $status_row = $wpdb->get_row($wpdb->prepare("SELECT status FROM {$wpdb->prefix}vapt_feature_status WHERE feature_key = %s", $key));
    $status = $status_row ? strtolower($status_row->status) : 'draft';

    // Override Logic
    $use_override_schema = in_array($status, ['test', 'release']) && !empty($meta['override_schema']);
    $raw_schema = $use_override_schema ? $meta['override_schema'] : $meta['generated_schema'];
    $schema = !empty($raw_schema) ? json_decode($raw_schema, true) : array();

    if (empty($schema['enforcement'])) return;

    $driver_name = $schema['enforcement']['driver'];

    // 2. Dispatch to the correct driver
    // 2. Dispatch to the correct driver
    if ($driver_name === 'htaccess') {
      // UNIVERSAL FIX: Rebuild based on Server Type
      $server = isset($_SERVER['SERVER_SOFTWARE']) ? strtolower($_SERVER['SERVER_SOFTWARE']) : '';

      if (strpos($server, 'nginx') !== false) {
        self::rebuild_nginx();
      } elseif (strpos($server, 'iis') !== false || strpos($server, 'windows') !== false) {
        self::rebuild_iis();
      } else {
        // Default to Apache/.htaccess
        self::rebuild_htaccess();
      }
    } else {
      // For hooks, we just rely on the runtime loader (next request will pick it up)
      // No explicit action needed other than clearing cache (done above).
    }
  }

  /**
   * Rebuilds Nginx Rules File
   */
  private static function rebuild_nginx()
  {
    require_once VAPT_PATH . 'includes/enforcers/class-vapt-nginx-driver.php';

    $features = self::get_enforced_features();
    $all_rules = [];

    foreach ($features as $meta) {
      $schema = self::resolve_schema($meta);
      $impl = self::resolve_impl($meta);

      if (($schema['enforcement']['driver'] ?? '') === 'htaccess') {
        $rules = VAPT_Nginx_Driver::generate_rules($impl, $schema);
        if ($rules) $all_rules = array_merge($all_rules, $rules);
      }
    }

    VAPT_Nginx_Driver::write_batch($all_rules);
  }

  /**
   * Rebuilds IIS Config
   */
  private static function rebuild_iis()
  {
    require_once VAPT_PATH . 'includes/enforcers/class-vapt-iis-driver.php';
    // Logic placeholder - similar structure to above
  }

  // Helper to fetch enforced features (DRY)
  private static function get_enforced_features()
  {
    global $wpdb;
    $table = $wpdb->prefix . 'vapt_feature_meta';
    return $wpdb->get_results("SELECT m.*, s.status FROM $table m LEFT JOIN {$wpdb->prefix}vapt_feature_status s ON m.feature_key = s.feature_key WHERE m.is_enforced = 1", ARRAY_A);
  }

  // Helpers for Schema/Impl Resolution
  private static function resolve_schema($meta)
  {
    $status = $meta['status'] ?? 'draft';
    $raw = (in_array($status, ['test', 'release']) && !empty($meta['override_schema'])) ? $meta['override_schema'] : $meta['generated_schema'];
    return $raw ? json_decode($raw, true) : [];
  }

  private static function resolve_impl($meta)
  {
    $status = $meta['status'] ?? 'draft';
    $raw = (in_array($status, ['test', 'release']) && !empty($meta['override_implementation_data'])) ? $meta['override_implementation_data'] : $meta['implementation_data'];
    return $raw ? json_decode($raw, true) : [];
  }

  /**
   * Rebuilds the .htaccess file by aggregating rules from ALL enabled features.
   */
  private static function rebuild_htaccess()
  {
    $enforced_features = self::get_enforced_features();

    if (empty($enforced_features)) {
      require_once VAPT_PATH . 'includes/enforcers/class-vapt-htaccess-driver.php';
      if (class_exists('VAPT_Htaccess_Driver')) {
        VAPT_Htaccess_Driver::write_batch(array(), 'root');
      }
      return;
    }

    require_once VAPT_PATH . 'includes/enforcers/class-vapt-htaccess-driver.php';
    if (!class_exists('VAPT_Htaccess_Driver')) return;

    $all_rules = array();

    foreach ($enforced_features as $meta) {
      $schema = self::resolve_schema($meta);
      $impl_data = self::resolve_impl($meta);
      $driver = isset($schema['enforcement']['driver']) ? $schema['enforcement']['driver'] : '';

      if ($driver === 'htaccess') {
        $feature_rules = VAPT_Htaccess_Driver::generate_rules($impl_data, $schema);
        if (!empty($feature_rules)) {
          $all_rules[] = "# Rule for: " . ($meta['feature_key']);
          $all_rules = array_merge($all_rules, $feature_rules);
        }
      }
    }

    VAPT_Htaccess_Driver::write_batch($all_rules, 'root');
  }
}
