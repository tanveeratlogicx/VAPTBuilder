<?php
$file = 't:\~\Local925 Sites\hermasnet\app\public\wp-content\plugins\VAPTBuilder\data\VAPT-SixT-Risk-Catalog-12-U.json';
$data = json_decode(file_get_contents($file), true);
echo "Risks in SixT-12-U: " . count($data['risk_catalog']) . "\n";
foreach ($data['risk_catalog'] as $item) {
  echo "- " . ($item['title'] ?? 'NO TITLE') . "\n";
}
