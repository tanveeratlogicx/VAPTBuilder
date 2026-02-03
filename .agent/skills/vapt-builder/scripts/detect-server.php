<?php

/**
 * VAPT Server Environment Detector
 * Usage: php detect-server.php
 */

// Basic simulation of WordPress constants if run via CLI inside WP context
// Otherwise, we inspect the system environment directly.

$detection = [
  'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? php_uname(),
  'is_apache'       => false,
  'is_nginx'        => false,
  'is_iis'          => false,
  'modules'         => [],
  'writable'        => []
];

// 1. Detect Server Type
if (stripos($detection['server_software'], 'apache') !== false) {
  $detection['is_apache'] = true;
} elseif (stripos($detection['server_software'], 'nginx') !== false) {
  $detection['is_nginx'] = true;
} elseif (stripos($detection['server_software'], 'microsoft-iis') !== false) {
  $detection['is_iis'] = true;
}

// 2. Detect Apache Modules (if explicitly available or via apache_get_modules)
if (function_exists('apache_get_modules')) {
  $dims = apache_get_modules();
  $detection['modules']['mod_rewrite'] = in_array('mod_rewrite', $dims);
  $detection['modules']['mod_headers'] = in_array('mod_headers', $dims);
} else {
  // Heuristic fallback: Check if .htaccess exists and has RewriteEngine
  if (file_exists(__DIR__ . '/../../../../.htaccess')) {
    $content = file_get_contents(__DIR__ . '/../../../../.htaccess');
    $detection['modules']['mod_rewrite'] = (stripos($content, 'RewriteEngine') !== false);
  }
}

// 3. Check Write Permissions
$paths_to_check = [
  'root_htaccess' => __DIR__ . '/../../../../.htaccess',
  'wp_config'     => __DIR__ . '/../../../../wp-config.php',
  'uploads_dir'   => __DIR__ . '/../../../../wp-content/uploads'
];

foreach ($paths_to_check as $key => $path) {
  if (file_exists($path)) {
    $detection['writable'][$key] = is_writable($path);
  } else {
    // Check parent directory if file doesn't exist
    $dir = dirname($path);
    $detection['writable'][$key] = (is_dir($dir) && is_writable($dir));
  }
}

// Output JSON for the Agent to read
echo json_encode($detection, JSON_PRETTY_PRINT);
