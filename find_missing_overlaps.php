<?php
$file_small = 't:\~\Local925 Sites\hermasnet\app\public\wp-content\plugins\VAPTBuilder\data\VAPT-SixT-Risk-Catalog-12-U.json';
$file_big = 't:\~\Local925 Sites\hermasnet\app\public\wp-content\plugins\VAPTBuilder\data\VAPT-Complete-Risk-Catalog-99.json';

$data_small = json_decode(file_get_contents($file_small), true);
$data_big = json_decode(file_get_contents($file_big), true);

$titles_big = [];
foreach ($data_big['risk_catalog'] as $item) {
  $title = isset($item['title']) ? $item['title'] : (isset($item['name']) ? $item['name'] : (isset($item['label']) ? $item['label'] : ''));
  if ($title) $titles_big[] = strtolower(trim($title));
}

$small_features = [];
if (isset($data_small['risk_catalog'])) $small_features = $data_small['risk_catalog'];
elseif (isset($data_small['features'])) $small_features = $data_small['features'];
else $small_features = $data_small;

echo "Features in SixT-12-U NOT in 99-item catalog:\n";
foreach ($small_features as $f) {
  $title = isset($f['title']) ? $f['title'] : (isset($f['name']) ? $f['name'] : (isset($f['label']) ? $f['label'] : ''));
  if (!$title) continue;

  $low_title = strtolower(trim($title));
  if (!in_array($low_title, $titles_big)) {
    echo "- " . $title . " (ID: " . ($f['risk_id'] ?? $f['id'] ?? 'N/A') . ")\n";
  }
}
