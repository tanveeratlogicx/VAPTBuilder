<?php
define('WP_USE_THEMES', false);
require_once('../../../wp-load.php');

global $wpdb;
$table = $wpdb->prefix . 'vapt_feature_meta';
$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE feature_key = %s", 'RISK-B99'), ARRAY_A);

header('Content-Type: application/json');
echo json_encode($row, JSON_PRETTY_PRINT);
