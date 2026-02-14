<?php

/**
 * 🚨 FORCE FIX TEMPLATE: [Feature Name]
 * Usage: Paste into `vapt-builder.php` or a mu-plugin to force-fix a stuck feature.
 */

add_action('init', 'vapt_force_fix_YOUR_FEATURE_KEY');

if (! function_exists('vapt_force_fix_YOUR_FEATURE_KEY')) {
  function vapt_force_fix_YOUR_FEATURE_KEY()
  {
    // Trigger URL: ?vapt_force_fix_YOUR_FEATURE_KEY=1
    if (isset($_GET['vapt_force_fix_YOUR_FEATURE_KEY']) && current_user_can('manage_options')) {
      global $wpdb;
      $key = 'YOUR_FEATURE_KEY_FROM_JSON';
      $table = $wpdb->prefix . 'vapt_feature_meta';

      // 1. Define the Correct Schema
      $schema = array(
        'controls' => array(
          array('type' => 'toggle', 'label' => 'Enable Feature', 'key' => 'enable_YOUR_FEATURE_KEY', 'help' => 'Description...'),
          array('type' => 'test_action', 'label' => 'Verify', 'key' => 'verify_it', 'test_logic' => 'universal_probe', 'test_config' => ['path' => '/', 'expected_status' => 200, 'expected_headers' => ['X-VAPTC-Enforced' => 'YOUR_FEATURE_KEY']])
        ),
        'enforcement' => array(
          'driver' => 'hook', // or 'htaccess'
          'mappings' => array('enable_YOUR_FEATURE_KEY' => 'DRIVER_METHOD_OR_RULE')
        )
      );

      // 2. Insert or Update DB
      $exists = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $table WHERE feature_key = %s", $key));
      if (!$exists) {
        $wpdb->insert($table, array('feature_key' => $key, 'is_enforced' => 1));
      }
      $wpdb->update($table, array('generated_schema' => json_encode($schema), 'is_enforced' => 1), array('feature_key' => $key));

      // 3. Force Implementation Data (Turn it ON)
      $meta = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE feature_key = %s", $key), ARRAY_A);
      if (empty($meta['implementation_data'])) {
        $impl = array('enable_YOUR_FEATURE_KEY' => true);
        $wpdb->update($table, array('implementation_data' => json_encode($impl)), array('feature_key' => $key));
      }

      // 4. Clear Caches & Report
      delete_transient('vapt_active_enforcements');
      wp_die("<h1>VAPT Fix Applied: YOUR FEATURE NAME</h1><p>Schema updated and enforcement forced.</p>");
    }
  }
}
