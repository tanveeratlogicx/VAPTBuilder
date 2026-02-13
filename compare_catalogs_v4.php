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

$output = "Overlapping Features (Present in 2+ files):\n";
$count = 0;
foreach ($all_features as $title => $files) {
  $unique_files = array_unique($files);
  if (count($unique_files) > 1) {
    $output .= "- " . $title . " (" . implode(', ', $unique_files) . ")\n";
    $count++;
  }
}

$output .= "\nTotal Overlapping Titles: " . $count . "\n";
file_put_contents('t:\~\Local925 Sites\hermasnet\app\public\wp-content\plugins\VAPTBuilder\overlap_results.txt', $output);
echo "Results saved to overlap_results.txt\n";
