<?php

/**
 * VAPT Scanner Comparison Debug Tool
 * Use this to compare results with other security scanners
 */

// Prevent direct access
if (!defined('ABSPATH')) {
  exit;
}

// Include required files
require_once plugin_dir_path(__FILE__) . 'includes/class-vapt-scanner.php';

function vapt_run_comparison_scan($target_url)
{
  echo "<h2>VAPT Scanner Comparison Analysis</h2>";
  echo "<p><strong>Target URL:</strong> " . esc_html($target_url) . "</p>";
  echo "<p><strong>Scan Time:</strong> " . current_time('mysql') . "</p>";

  // Initialize scanner
  $scanner = new VAPT_Scanner();

  // Get vulnerability definitions
  $vulnerabilities = $scanner->get_vulnerabilities();

  echo "<h3>Scanner Configuration</h3>";
  echo "<ul>";
  echo "<li><strong>HTTP Timeout:</strong> 10 seconds</li>";
  echo "<li><strong>User Agent:</strong> VAPT-Security-Scanner/2.5.5</li>";
  echo "<li><strong>Max Redirects:</strong> 5</li>";
  echo "<li><strong>SSL Verification:</strong> Enabled</li>";
  echo "<li><strong>Batch Size:</strong> 15 vulnerabilities</li>";
  echo "<li><strong>Total Vulnerabilities:</strong> " . count($vulnerabilities) . "</li>";
  echo "</ul>";

  // Test basic connectivity
  echo "<h3>Connectivity Test</h3>";
  $test_response = wp_remote_get($target_url, [
    'timeout' => 10,
    'user-agent' => 'VAPT-Security-Scanner/2.5.5 (WordPress Security Audit)',
    'headers' => [
      'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language' => 'en-US,en;q=0.5',
    ],
    'sslverify' => true,
  ]);

  if (is_wp_error($test_response)) {
    echo "<p style='color: red;'><strong>Connection Failed:</strong> " . $test_response->get_error_message() . "</p>";
    return;
  }

  $code = wp_remote_retrieve_response_code($test_response);
  $headers = wp_remote_retrieve_headers($test_response);
  $body_length = strlen(wp_remote_retrieve_body($test_response));

  echo "<ul>";
  echo "<li><strong>Response Code:</strong> $code</li>";
  echo "<li><strong>Response Size:</strong> " . number_format($body_length) . " bytes</li>";
  echo "<li><strong>Server:</strong> " . (isset($headers['server']) ? $headers['server'] : 'Unknown') . "</li>";
  echo "<li><strong>Content-Type:</strong> " . (isset($headers['content-type']) ? $headers['content-type'] : 'Unknown') . "</li>";
  echo "</ul>";

  // Test implemented vulnerability checks
  echo "<h3>Implemented Vulnerability Tests</h3>";
  $implemented_tests = [
    'wordpress-version-disclosure' => 'WordPress Version Disclosure',
    'directory-listing' => 'Directory Listing',
    'user-enumeration' => 'User Enumeration',
    'readme-exposure' => 'Readme Exposure',
    'sql-injection' => 'SQL Injection',
    'xss-protection' => 'XSS Protection',
    'security-headers' => 'Security Headers',
  ];

  echo "<p>The following vulnerability tests are currently implemented:</p>";
  echo "<ul>";
  foreach ($implemented_tests as $id => $name) {
    echo "<li><strong>$name</strong> ($id)</li>";
  }
  echo "</ul>";

  echo "<p><strong>Note:</strong> " . (count($vulnerabilities) - count($implemented_tests)) . " additional vulnerability checks are defined but not yet implemented.</p>";

  // Show sample test execution
  echo "<h3>Sample Test Execution</h3>";
  echo "<p>Running a few key tests to demonstrate detection logic:</p>";

  $sample_tests = ['wordpress-version-disclosure', 'security-headers'];

  foreach ($sample_tests as $test_id) {
    echo "<h4>Testing: $implemented_tests[$test_id]</h4>";

    // Get the method name
    $method = 'test_' . str_replace('-', '_', $test_id);

    if (method_exists($scanner, $method)) {
      $result = $scanner->$method($target_url, ['id' => $test_id, 'name' => $implemented_tests[$test_id]]);
      if ($result) {
        echo "<div style='background: #ffebee; border: 1px solid #f44336; padding: 10px; margin: 10px 0;'>";
        echo "<strong style='color: #d32f2f;'>VULNERABILITY FOUND</strong><br>";
        echo "<strong>Affected URL:</strong> " . esc_html($result['affected_url']) . "<br>";
        echo "<strong>Description:</strong> " . esc_html($result['description']) . "<br>";
        echo "<strong>Impact:</strong> " . esc_html($result['impact']) . "<br>";
        echo "</div>";
      } else {
        echo "<div style='background: #e8f5e8; border: 1px solid #4caf50; padding: 10px; margin: 10px 0;'>";
        echo "<strong style='color: #2e7d32;'>✓ PASS</strong> - No vulnerability detected";
        echo "</div>";
      }
    }
  }

  // Show debug log
  $debug_log = $scanner->get_debug_log();
  if (!empty($debug_log)) {
    echo "<h3>Debug Log (Last 20 entries)</h3>";
    echo "<div style='background: #f5f5f5; border: 1px solid #ddd; padding: 10px; max-height: 300px; overflow-y: auto; font-family: monospace; font-size: 11px;'>";
    $last_entries = array_slice($debug_log, -20);
    foreach ($last_entries as $entry) {
      echo esc_html($entry) . "<br>";
    }
    echo "</div>";
  }

  echo "<h3>Comparison Tips</h3>";
  echo "<ul>";
  echo "<li><strong>Check User Agents:</strong> Other tools might use different user agents that get different responses</li>";
  echo "<li><strong>Review Headers:</strong> Compare the exact headers being sent</li>";
  echo "<li><strong>Test Endpoints:</strong> Verify if other tools test the same URLs/parameters</li>";
  echo "<li><strong>Timing:</strong> Site content may change between scans</li>";
  echo "<li><strong>Authentication:</strong> Some tools might be logged in while ours tests anonymously</li>";
  echo "<li><strong>Detection Logic:</strong> Different tools use different signatures/patterns</li>";
  echo "</ul>";
}

// Usage example
if (isset($_GET['run_comparison']) && current_user_can('manage_options')) {
  $test_url = isset($_GET['test_url']) ? esc_url_raw($_GET['test_url']) : '';
  if ($test_url) {
    vapt_run_comparison_scan($test_url);
  } else {
    echo "<p>Please provide a test_url parameter.</p>";
  }
} else {
  echo "<p>Add ?run_comparison=1&test_url=https://example.com to run the comparison analysis.</p>";
}
