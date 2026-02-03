<?php
define('WP_USE_THEMES', false);
require_once('../../../wp-load.php');

global $wpdb;
$table = $wpdb->prefix . 'vapt_feature_meta';
$results = $wpdb->get_results("SELECT * FROM $table WHERE feature_key LIKE '%readme%' OR feature_key LIKE '%info%' OR is_enforced = 1", ARRAY_A);

header('Content-Type: application/json');
echo json_encode($results, JSON_PRETTY_PRINT);
