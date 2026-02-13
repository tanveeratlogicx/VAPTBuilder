<?php
// Mocking WordPress and VAPT environment for testing
define('VAPT_PATH', 't:\~\Local925 Sites\hermasnet\app\public\wp-content\plugins\VAPTBuilder/');

class VAPT_DB
{
  public static function get_all_status()
  {
    return [];
  }
  public static function get_history_counts()
  {
    return [];
  }
  public static function get_feature_meta($key)
  {
    return null;
  }
}

function __($text, $domain = '')
{
  return $text;
}
function sanitize_file_name($file)
{
  return $file;
}
function sanitize_title($text)
{
  return strtolower(str_replace(' ', '-', $text));
}

// Simplified mock of the get_features logic
function test_get_features($files_to_load)
{
  require_once VAPT_PATH . 'includes/class-vapt-rest.php';
  $rest = new VAPT_REST();

  // We need to mock the $request object
  $request = new stdClass();
  $request->params = ['file' => implode(',', $files_to_load)];
  $request->get_param = function ($key) use ($request) {
    return $request->params[$key] ?? null;
  };

  // Call the method
  $features = $rest->get_features($request);

  return $features;
}

$output = "";

$files = ['VAPT-HTAccess-Risk-Catalog-18.json', 'VAPT-Complete-Risk-Catalog-99.json'];
$output .= "Testing with files: " . implode(', ', $files) . "\n";
$results = test_get_features($files);

foreach ($results as $f) {
  if (strtolower($f['label']) === 'xml-rpc api security') {
    $output .= "Found XML-RPC:\n";
    $output .= "- source_file: " . $f['source_file'] . "\n";
    $output .= "- is_from_active_file: " . ($f['is_from_active_file'] ? 'TRUE' : 'FALSE') . "\n";
    $output .= "- exists_in_multiple_files: " . ($f['exists_in_multiple_files'] ? 'TRUE' : 'FALSE') . "\n";
    $output .= "- status: " . ($f['status'] ?? 'N/A') . "\n";
  }
}

$files2 = ['VAPT-SixT-Risk-Catalog-12-U.json', 'VAPT-Complete-Risk-Catalog-99.json'];
$output .= "\nTesting with files: " . implode(', ', $files2) . "\n";
$results2 = test_get_features($files2);

foreach ($results2 as $f) {
  if (strpos(strtolower($f['label']), 'wp-cron.php enabled leads to dos') !== false) {
    $output .= "Found wp-cron:\n";
    $output .= "- source_file: " . $f['source_file'] . "\n";
    $output .= "- is_from_active_file: " . ($f['is_from_active_file'] ? 'TRUE' : 'FALSE') . "\n";
    $output .= "- exists_in_multiple_files: " . ($f['exists_in_multiple_files'] ? 'TRUE' : 'FALSE') . "\n";
    $output .= "- status: " . ($f['status'] ?? 'N/A') . "\n";
  }
}

file_put_contents('t:\~\Local925 Sites\hermasnet\app\public\wp-content\plugins\VAPTBuilder\verification_results.txt', $output);
echo "Results saved to verification_results.txt\n";
