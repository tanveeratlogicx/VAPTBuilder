<?php
$data_dir = 't:\~\Local925 Sites\hermasnet\app\public\wp-content\plugins\VAPTBuilder\data';
$files = array_diff(scandir($data_dir), array('..', '.'));

$all_features = [];

foreach ($files as $file) {
  if (pathinfo($file, PATHINFO_EXTENSION) !== 'json') continue;

  $content = file_get_contents($data_dir . '/' . $file);
  $data = json_decode($content, true);
  if (!is_array($data)) continue;

  $features = [];
  if (isset($data['risk_catalog'])) $features = $data['risk_catalog'];
  elseif (isset($data['features'])) $features = $data['features'];
  elseif (isset($data['wordpress_vapt'])) $features = $data['wordpress_vapt'];
  else $features = $data;

  foreach ($features as $f) {
    $title = isset($f['title']) ? $f['title'] : (isset($f['name']) ? $f['name'] : (isset($f['label']) ? $f['label'] : ''));
    if (!$title) continue;

    $key = strtolower(trim($title));
    if (!isset($all_features[$key])) {
      $all_features[$key] = [];
    }
    $all_features[$key][] = $file;
  }
}

echo "Overlapping Features (Present in 2+ files):\n";
$count = 0;
foreach ($all_features as $title => $files) {
  if (count($files) > 1) {
    echo "- " . $title . " (" . implode(', ', array_unique($files)) . ")\n";
    $count++;
  }
}

echo "\nTotal Overlapping Titles: " . $count . "\n";
