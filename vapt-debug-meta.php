<?php
// Define ABSPATH if not already defined (though running in WP context would have it)
// We need to find wp-load.php. Since we are in wp-content/plugins/VAPTBuilder/, it's 3 levels up.
require_once('../../../wp-load.php');
global $wpdb;
$key = '11';
$table = $wpdb->prefix . 'vapt_feature_meta';
$meta = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE feature_key = %s", $key), ARRAY_A);
echo "KEY: $key\n";
if (!$meta) {
  echo "META NOT FOUND for key $key\n";
  // Let's try to search by column titles in JSON
  exit;
}
echo "IS_ENFORCED: " . $meta['is_enforced'] . "\n";
echo "SCHEMA:\n" . $meta['generated_schema'] . "\n";
echo "IMPL DATA:\n" . $meta['implementation_data'] . "\n";
// unlink(__FILE__);
