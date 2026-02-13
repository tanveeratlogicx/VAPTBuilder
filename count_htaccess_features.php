<?php
$file = 't:\~\Local925 Sites\hermasnet\app\public\wp-content\plugins\VAPTBuilder\data\VAPT-Complete-Risk-Catalog-99.json';
$data = json_decode(file_get_contents($file), true);
$count = 0;
foreach ($data['risk_catalog'] as $item) {
  if (isset($item['protection']['automated_protection']['method']) && $item['protection']['automated_protection']['method'] === 'htaccess-rules') {
    $count++;
  } elseif (isset($item['protection']['driver']) && $item['protection']['driver'] === 'htaccess') {
    $count++;
  }
}
echo "Number of features in 99-item catalog with htaccess driver: " . $count . "\n";
