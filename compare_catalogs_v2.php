<?php
$file12 = 't:\~\Local925 Sites\hermasnet\app\public\wp-content\plugins\VAPTBuilder\data\VAPT-SixT-Risk-Catalog-12-U.json';
$file99 = 't:\~\Local925 Sites\hermasnet\app\public\wp-content\plugins\VAPTBuilder\data\VAPT-Complete-Risk-Catalog-99.json';

$data12 = json_decode(file_get_contents($file12), true);
$data99 = json_decode(file_get_contents($file99), true);

$titles12 = [];
foreach ($data12['risk_catalog'] as $item) {
  $title = isset($item['title']) ? $item['title'] : (isset($item['name']) ? $item['name'] : (isset($item['label']) ? $item['label'] : ''));
  if ($title) $titles12[] = strtolower(trim($title));
}

$titles99 = [];
foreach ($data99['risk_catalog'] as $item) {
  $title = isset($item['title']) ? $item['title'] : (isset($item['name']) ? $item['name'] : (isset($item['label']) ? $item['label'] : ''));
  if ($title) $titles99[] = strtolower(trim($title));
}

$common = array_intersect($titles12, $titles99);

echo "Common titles count: " . count($common) . "\n";
foreach ($common as $t) {
  echo "- " . $t . "\n";
}
