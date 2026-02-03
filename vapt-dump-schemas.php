<?php
// Find wp-load.php
$wp_load = __DIR__ . '/../../../wp-load.php';
if (!file_exists($wp_load)) {
  die("Error: wp-load.php not found at $wp_load\n");
}
require_once($wp_load);

global $wpdb;
$table = $wpdb->prefix . 'vapt_feature_meta';
$results = $wpdb->get_results("SELECT feature_key, is_enforced, generated_schema, implementation_data FROM $table", ARRAY_A);

$log = "VAPT SCHEMA DUMP - " . date('Y-m-d H:i:s') . "\n";
foreach ($results as $row) {
  if ($row['is_enforced']) {
    $log .= "-----------------------------------\n";
    $log .= "KEY: " . $row['feature_key'] . "\n";
    $log .= "ENFORCED: YES\n";
    $log .= "SCHEMA: " . $row['generated_schema'] . "\n";
    $log .= "IMPL: " . $row['implementation_data'] . "\n";
  }
}

file_put_contents(__DIR__ . '/vapt-schema-debug.txt', $log);
echo "Dumped " . count($results) . " features to vapt-schema-debug.txt\n";
