<?php
$file = 't:\~\Local925 Sites\hermasnet\app\public\wp-content\plugins\VAPTBuilder\data\VAPT-Complete-Risk-Catalog-99.json';
$raw = file_get_contents($file);
if ($raw === false) die("Failed to read file");
$data = json_decode($raw, true);
if ($data === null) die("Failed to decode JSON: " . json_last_error_msg());

$count = 0;
$methods = [];
if (!isset($data['risk_catalog'])) die("risk_catalog key missing");

foreach ($data['risk_catalog'] as $item) {
  if (!isset($item['protection']['automated_protection'])) {
    $method = 'missing_protection';
  } else {
    $method = $item['protection']['automated_protection']['method'] ?? 'missing_method';
  }

  if (strpos(strtolower($method), 'htaccess') !== false) {
    $count++;
  }
  if (!isset($methods[$method])) $methods[$method] = 0;
  $methods[$method]++;
}

$out = "Number of features in 99-item catalog with htaccess-related method: " . $count . "\n";
$out .= "All methods found:\n" . print_r($methods, true);

file_put_contents('t:\~\Local925 Sites\hermasnet\app\public\wp-content\plugins\VAPTBuilder\htaccess_count_debug.txt', $out);
echo "Results saved to htaccess_count_debug.txt\n";
