<?php

/**
 * Quick Scanner Test
 */

// Prevent direct access
if (!defined('ABSPATH')) {
  exit;
}

require_once plugin_dir_path(__FILE__) . 'includes/class-vapt-scanner.php';

echo "<h2>Scanner Quick Test</h2>";

// Test basic instantiation
echo "<h3>1. Testing Scanner Instantiation</h3>";
try {
  $scanner = new VAPT_Scanner();
  echo "<p style='color: green;'>✓ Scanner instantiated successfully</p>";

  $vulnerabilities = $scanner->get_vulnerabilities();
  echo "<p>Loaded " . count($vulnerabilities) . " vulnerability definitions</p>";
} catch (Exception $e) {
  echo "<p style='color: red;'>✗ Scanner instantiation failed: " . $e->getMessage() . "</p>";
  exit;
}

// Test a simple vulnerability check
echo "<h3>2. Testing Simple Vulnerability Check</h3>";
$test_url = 'https://httpbin.org/html'; // Simple test endpoint

try {
  // Test wordpress version disclosure (should be fast)
  $test_vuln = ['id' => 'wordpress-version-disclosure', 'name' => 'Test', 'severity' => 'low'];
  $method = 'test_' . str_replace('-', '_', $test_vuln['id']);

  if (method_exists($scanner, $method)) {
    echo "<p>Testing method: $method</p>";
    $start = microtime(true);
    $result = $scanner->$method($test_url, $test_vuln);
    $elapsed = microtime(true) - $start;

    echo "<p>Test completed in " . round($elapsed, 2) . " seconds</p>";
    if ($result) {
      echo "<p style='color: orange;'>⚠ Vulnerability found: " . $result['description'] . "</p>";
    } else {
      echo "<p style='color: green;'>✓ No vulnerability found</p>";
    }
  } else {
    echo "<p style='color: red;'>✗ Method $method does not exist</p>";
  }
} catch (Exception $e) {
  echo "<p style='color: red;'>✗ Test failed: " . $e->getMessage() . "</p>";
}

// Show debug log
$debug_log = $scanner->get_debug_log();
if (!empty($debug_log)) {
  echo "<h3>3. Debug Log (Last 10 entries)</h3>";
  echo "<div style='background: #f5f5f5; padding: 10px; max-height: 200px; overflow-y: auto; font-family: monospace; font-size: 12px;'>";
  $last_entries = array_slice($debug_log, -10);
  foreach ($last_entries as $entry) {
    echo htmlspecialchars($entry) . "<br>";
  }
  echo "</div>";
}

echo "<h3>4. Test Complete</h3>";
echo "<p>If you see this, the scanner is working. Check your actual scan for issues.</p>";
