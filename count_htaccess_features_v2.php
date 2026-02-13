<?php
$file = 't:\~\Local925 Sites\hermasnet\app\public\wp-content\plugins\VAPTBuilder\data\VAPT-Complete-Risk-Catalog-99.json';
$data = json_decode(file_get_contents($file), true);
$count = 0;
$methods = [];
foreach ($data['risk_catalog'] as $item) {
  $method = $item['protection']['automated_protection']['method'] ?? 'none';
  if (strpos($method, 'htaccess') !== false) {
    $count++;
  }
  if (!isset($methods[$method])) $methods[$method] = 0;
  $methods[$method]++;
}
echo "Number of features in 99-item catalog with htaccess-related method: " . $count . "\n";
echo "All methods found:\n";
print_r($methods);
