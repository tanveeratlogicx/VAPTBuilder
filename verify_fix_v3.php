<?php
define('VAPT_PATH', 't:\~\Local925 Sites\hermasnet\app\public\wp-content\plugins\VAPTBuilder/');

function sanitize_file_name($file)
{
  return $file;
}
function sanitize_title($text)
{
  return strtolower(str_replace(' ', '-', $text));
}
function __($text, $domain = '')
{
  return $text;
}

// Embedded Logic from get_features for verification
function verify_logic($files_to_load)
{
  $merged_features = [];
  $active_file = reset($files_to_load);

  foreach ($files_to_load as $file) {
    $json_path = VAPT_PATH . 'data/' . sanitize_file_name($file);
    if (!file_exists($json_path)) continue;

    $content = file_get_contents($json_path);
    $raw_data = json_decode($content, true);
    if (!is_array($raw_data)) continue;

    $current_features = [];
    if (isset($raw_data['risk_catalog']) && is_array($raw_data['risk_catalog'])) {
      foreach ($raw_data['risk_catalog'] as $item) {
        if (isset($item['risk_id']) && empty($item['id'])) $item['id'] = $item['risk_id'];
        $current_features[] = $item;
      }
    } elseif (isset($raw_data['features']) && is_array($raw_data['features'])) {
      $current_features = $raw_data['features'];
    } else {
      $current_features = $raw_data;
    }

    foreach ($current_features as $feature) {
      $label = $feature['title'] ?? $feature['name'] ?? $feature['label'] ?? 'Unnamed';
      $dedupe_key = strtolower(trim($label));

      if (isset($merged_features[$dedupe_key])) {
        $merged_features[$dedupe_key]['exists_in_multiple_files'] = true;
        continue;
      }

      $feature['label'] = $label;
      $feature['source_file'] = $file;
      $feature['is_from_active_file'] = ($file === $active_file);
      $feature['exists_in_multiple_files'] = false;
      $merged_features[$dedupe_key] = $feature;
    }
  }
  return array_values($merged_features);
}

$output = "";

$files = ['VAPT-HTAccess-Risk-Catalog-18.json', 'VAPT-Complete-Risk-Catalog-99.json'];
$output .= "Test 1: HTAccess as Active\n";
$res1 = verify_logic($files);
foreach ($res1 as $f) {
  if (strtolower($f['label']) === 'xml-rpc api security') {
    $output .= "XML-RPC: source=" . $f['source_file'] . ", active=" . ($f['is_from_active_file'] ? 'Y' : 'N') . ", multi=" . ($f['exists_in_multiple_files'] ? 'Y' : 'N') . "\n";
  }
}

$files2 = ['VAPT-Complete-Risk-Catalog-99.json', 'VAPT-HTAccess-Risk-Catalog-18.json'];
$output .= "\nTest 2: Complete-99 as Active\n";
$res2 = verify_logic($files2);
foreach ($res2 as $f) {
  if (strtolower($f['label']) === 'xml-rpc api security') {
    $output .= "XML-RPC: source=" . $f['source_file'] . ", active=" . ($f['is_from_active_file'] ? 'Y' : 'N') . ", multi=" . ($f['exists_in_multiple_files'] ? 'Y' : 'N') . "\n";
  }
}

file_put_contents('t:\~\Local925 Sites\hermasnet\app\public\wp-content\plugins\VAPTBuilder\verification_results_final.txt', $output);
echo "Done\n";
