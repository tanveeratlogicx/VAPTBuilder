<?php

/**
 * VAPT Admin Interface
 */

if (! defined('ABSPATH')) {
  exit;
}

class VAPT_Admin
{

  public function __construct()
  {
    add_action('admin_menu', array($this, 'add_admin_menu'));
    add_action('admin_init', array($this, 'handle_sync_processing'));
    add_action('admin_enqueue_scripts', array($this, 'enqueue_scripts'));
    add_action('wp_ajax_vapt_check_progress', array($this, 'ajax_check_progress'));
    add_action('wp_ajax_vapt_process_scan', array($this, 'ajax_process_scan'));
    add_action('admin_notices', array($this, 'show_nginx_notice'));
  }

  public function show_nginx_notice()
  {
    if (!is_vapt_superadmin()) return;

    $server = isset($_SERVER['SERVER_SOFTWARE']) ? strtolower($_SERVER['SERVER_SOFTWARE']) : '';
    if (strpos($server, 'nginx') === false) return;

    $upload_dir = wp_upload_dir();
    $rules_file = $upload_dir['basedir'] . '/vapt-nginx-rules.conf';

    if (file_exists($rules_file)) {
      $include_path = $rules_file;
?>
      <div class="notice notice-info is-dismissible">
        <p><strong>VAPT Nginx Configuration (Action Required)</strong></p>
        <p>To apply VAPT security rules on Nginx, you must include the generated rules file in your main <code>nginx.conf</code> server block:</p>
        <code style="display:block; padding:10px; background:#fff; margin:5px 0;">include <?php echo esc_html($include_path); ?>;</code>
        <p><em>After adding this line, restart Nginx to apply changes.</em></p>
      </div>
    <?php
    }
  }

  public function ajax_process_scan()
  {
    // This endpoint triggers the actual scan work
    if (!is_vapt_superadmin()) {
      wp_send_json_error('Unauthorized');
    }

    $scan_id = isset($_POST['scan_id']) ? intval($_POST['scan_id']) : 0;
    if (!$scan_id) {
      wp_send_json_error('Invalid ID');
    }

    // Increase time limit for this request
    set_time_limit(300); // 5 minutes
    ini_set('memory_limit', '256M');

    global $wpdb;
    $target_url = $wpdb->get_var($wpdb->prepare("SELECT target_url FROM {$wpdb->prefix}vapt_scans WHERE id = %d", $scan_id));

    error_log("VAPT DEBUG: ajax_process_scan for ID $scan_id. Target URL from DB: " . $target_url);

    if (!$target_url) {
      wp_send_json_error('Scan/URL not found');
    }

    if (class_exists('VAPT_Scanner')) {
      try {
        $scanner = new VAPT_Scanner();
        $offset = isset($_POST['offset']) ? intval($_POST['offset']) : 0;
        error_log("VAPT DEBUG: Starting batch at offset $offset with limit 10");

        $result = $scanner->run_scan($scan_id, $target_url, $offset, 10); // increased batch size

        // Log debug information
        $debug_log = $scanner->get_debug_log();
        if (!empty($debug_log)) {
          $last_debug = array_slice($debug_log, -5); // Last 5 debug entries
          error_log("VAPT DEBUG: Last debug entries: " . implode(" | ", $last_debug));
        }

        error_log("VAPT DEBUG: Batch result: " . json_encode($result));
        wp_send_json_success($result);
      } catch (Exception $e) {
        error_log("VAPT ERROR: Exception in ajax_process_scan: " . $e->getMessage());
        wp_send_json_error('Scan processing error: ' . $e->getMessage());
      }
    } else {
      wp_send_json_error('Scanner class missing');
    }
  }

  public function ajax_check_progress()
  {
    if (!is_vapt_superadmin()) {
      wp_send_json_error('Unauthorized');
    }

    $scan_id = isset($_GET['scan_id']) ? intval($_GET['scan_id']) : 0;
    if (!$scan_id) {
      wp_send_json_error('Invalid Scan ID');
    }

    global $wpdb;
    $scan = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}vapt_scans WHERE id = %d", $scan_id), ARRAY_A);

    if (!$scan) {
      wp_send_json_error('Scan not found');
    }

    $progress = get_option('vapt_scan_progress_' . $scan_id);
    $checked = $progress['checked'] ?? 0;

    // Get real total from active data file
    $vulnerability_data = $this->get_vulnerability_data();
    $total = !empty($vulnerability_data) ? count($vulnerability_data) : ($progress['total'] ?? 0);

    // Get found count
    $found_count = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->prefix}vapt_scan_results WHERE scan_id = %d", $scan_id));

    wp_send_json_success([
      'status' => $scan['status'],
      'checked' => $checked,
      'total' => $total,
      'found' => $found_count,
      'pass' => max(0, $checked - $found_count),
      'current_title' => $progress['current_title'] ?? '',
      'current_category' => $progress['current_category'] ?? '',
      'current_severity' => $progress['current_severity'] ?? ''
    ]);
  }

  private $vulnerabilities_cache = null;

  private function get_vulnerability_data()
  {
    if ($this->vulnerabilities_cache === null) {
      // Use the active data file configured in the workbench
      $active_file = VAPT_ACTIVE_DATA_FILE;
      $file_path = VAPT_PATH . 'data/' . sanitize_file_name($active_file);

      if (file_exists($file_path)) {
        $data = json_decode(file_get_contents($file_path), true);
        if ($data) {
          $raw_vulns = [];
          if (isset($data['risk_catalog'])) {
            $raw_vulns = $data['risk_catalog'];
          } elseif (isset($data['features'])) {
            $raw_vulns = $data['features'];
          } elseif (isset($data['wordpress_vapt'])) {
            $raw_vulns = $data['wordpress_vapt'];
          }

          // Normalize
          $this->vulnerabilities_cache = [];
          foreach ($raw_vulns as $vuln) {
            $this->vulnerabilities_cache[] = [
              'id' => $vuln['risk_id'] ?? $vuln['id'] ?? '',
              'name' => $vuln['title'] ?? $vuln['name'] ?? '',
              'severity' => is_array($vuln['severity'] ?? null) ? ($vuln['severity']['level'] ?? 'medium') : ($vuln['severity'] ?? 'medium'),
              'description' => is_array($vuln['description'] ?? null) ? ($vuln['description']['summary'] ?? '') : ($vuln['description'] ?? ''),
              'impact' => is_array($vuln['description'] ?? null) ? ($vuln['description']['business_impact'] ?? '') : ($vuln['impact'] ?? ''),
              'recommendation' => $vuln['remediation'] ?? (isset($vuln['protection']) ? ($vuln['protection']['automated_protection']['method'] ?? '') : ''),
              'owasp' => is_array($vuln['owasp_mapping'] ?? null) ? ($vuln['owasp_mapping']['owasp_top_10_2021'] ?? '') : ($vuln['owasp_mapping'] ?? ''),
              'cvss' => $vuln['severity']['cvss_score'] ?? null,
              'verification_steps' => isset($vuln['testing']['verification_steps']) ? array_column($vuln['testing']['verification_steps'], 'action') : [],
            ];
          }
        } else {
          $this->vulnerabilities_cache = [];
        }
      } else {
        $this->vulnerabilities_cache = [];
      }
    }
    return $this->vulnerabilities_cache;
  }

  public function add_admin_menu()
  {
    if (is_vapt_superadmin()) {
      add_menu_page(
        'VAPT Auditor',
        'VAPT Auditor',
        'manage_options',
        'vapt-auditor',
        array($this, 'admin_page'),
        'dashicons-shield',
        30
      );
    }
  }

  public function enqueue_scripts($hook)
  {
    if ($hook !== 'toplevel_page_vapt-auditor') {
      return;
    }

    wp_enqueue_script('vapt-admin-js', VAPT_URL . 'assets/js/admin.js', array('jquery'), VAPT_VERSION, true);
    wp_enqueue_style('vapt-admin-css', VAPT_URL . 'assets/css/admin.css', array(), VAPT_VERSION);

    wp_localize_script('vapt-admin-js', 'vapt_ajax', array(
      'ajax_url' => admin_url('admin-ajax.php'),
      'nonce' => wp_create_nonce('vapt_scan_nonce')
    ));
  }

  /**
   * Handle synchronous processing early to avoid "Headers already sent" warnings
   */
  public function handle_sync_processing()
  {
    if (!isset($_GET['page']) || $_GET['page'] !== 'vapt-auditor' || !isset($_GET['sync_process'])) {
      return;
    }

    if (!is_vapt_superadmin()) {
      wp_die(__('You do not have sufficient permissions to access this page.'));
    }

    global $wpdb;
    $scan_id = isset($_GET['scan_id']) ? intval($_GET['scan_id']) : null;

    if (!$scan_id) return;

    // Fetch target URL from database
    $target_url = $wpdb->get_var($wpdb->prepare(
      "SELECT target_url FROM {$wpdb->prefix}vapt_scans WHERE id = %d",
      $scan_id
    ));

    if (!$target_url) {
      wp_die(__('Target URL not found for this scan.'));
    }

    $scanner = new VAPT_Scanner();
    $scanner->run_scan($scan_id, $target_url, 0, 99);

    $redirect_url = add_query_arg([
      'page' => 'vapt-auditor',
      'scan_id' => $scan_id,
      'vapt_sync_done' => 1
    ], admin_url('admin.php'));

    wp_redirect($redirect_url);
    exit;
  }

  public function admin_page()
  {
    global $wpdb;
    if (!is_vapt_superadmin()) {
      wp_die(__('You do not have sufficient permissions to access this page.'));
    }

    $current_scan_id = isset($_GET['scan_id']) ? intval($_GET['scan_id']) : null;
    $target_url = isset($_POST['target_url']) ? esc_url($_POST['target_url']) : '';

    // Handle form submission
    if (isset($_POST['start_scan']) && wp_verify_nonce($_POST['vapt_scan_nonce'], 'start_scan')) {
      error_log("VAPT DEBUG: admin_page START SCAN for: " . $target_url);
      $scanner = new VAPT_Scanner();
      $scan_id = $scanner->start_scan($target_url);
      if ($scan_id === false) {
        echo '<div class="notice notice-error"><p>Failed to start scan. Please check database connection and try again.</p></div>';
      } else {
        $current_scan_id = $scan_id;
        // echo '<div class="notice notice-success"><p>Scan started! Scan ID: ' . $scan_id . '</p></div>'; // Removed explicitly as per user request
      }
    }

    // Get scan results if we have a scan ID
    $scan_results = [];
    $scan_data = null;
    $debug_log = [];

    // Success notice for synchronous processing
    if (isset($_GET['vapt_sync_done'])) {
      echo '<div class="notice notice-success is-dismissible"><p>Synchronous scan processing complete!</p></div>';
    }

    if ($current_scan_id) {
      $scanner = new VAPT_Scanner();
      $report = $scanner->generate_report($current_scan_id);
      if ($report) {
        $scan_results = $report['results'];
        $scan_data = $report['scan'];

        // Restore target URL from scan data if not in POST
        if (empty($target_url) && !empty($scan_data['target_url'])) {
          $target_url = $scan_data['target_url'];
        }
      }

      // Get debug log if available
      if (method_exists($scanner, 'get_debug_log')) {
        $debug_log = $scanner->get_debug_log();
      }
    }

    ?>
    <div class="wrap">
      <h1>VAPT Security Auditor <span class="vapt-version-badge">v<?php echo VAPT_AUDITOR_VERSION; ?></span></h1>

      <div class="vapt-scan-form">
        <h2>Start New Scan</h2>
        <form method="post" action="">
          <?php wp_nonce_field('start_scan', 'vapt_scan_nonce'); ?>
          <table class="form-table">
            <tr>
              <th scope="row"><label for="target_url">Target Website URL</label></th>
              <td>
                <input type="url" id="target_url" name="target_url" value="<?php echo esc_attr($target_url); ?>" class="regular-text" required>
                <p class="description">Enter the full URL of the WordPress website to scan (e.g., https://example.com)</p>
              </td>
            </tr>
          </table>
          <p class="submit">
            <input type="submit" name="start_scan" id="start_scan" class="button button-primary" value="Start Scan">
          </p>
        </form>
      </div>

      <?php
      $active_file = defined('VAPT_ACTIVE_DATA_FILE') ? VAPT_ACTIVE_DATA_FILE : 'VAPT-Complete-Risk-Catalog-99.json';
      $is_complete_catalog = (strpos($active_file, 'Complete-Risk-Catalog-99') !== false);
      ?>
      <div class="vapt-catalog-status" style="margin: 10px 0 20px 0; padding: 10px 15px; background: <?php echo $is_complete_catalog ? '#f0f6fb' : '#fff8e5'; ?>; border-left: 4px solid <?php echo $is_complete_catalog ? '#007cba' : '#ffb900'; ?>; border-radius: 4px;">
        <p style="margin: 0; font-size: 13px;">
          <strong>Active Catalog:</strong> <code><?php echo esc_html($active_file); ?></code>
          <?php if (!$is_complete_catalog): ?>
            <span style="color: #d63638; margin-left: 10px;"><span class="dashicons dashicons-warning" style="font-size: 16px; margin-top: 3px;"></span> <strong>Notice:</strong> You are using a partial catalog. For a full security audit, switch to the 99-item Complete Risk Catalog in the workbench.</span>
          <?php else: ?>
            <span style="color: #46b450; margin-left: 10px;"><span class="dashicons dashicons-yes" style="font-size: 16px; margin-top: 3px;"></span> High-Fidelity 99-Item Audit Enabled.</span>
          <?php endif; ?>
        </p>
      </div>

      <?php if ($current_scan_id): ?>
        <div class="vapt-scan-results">
          <div class="vapt-results-header">
            <h2>Scan Results</h2>
            <div style="margin-bottom: 10px; display: flex; align-items: center; gap: 10px;">
              <a href="<?php echo admin_url('admin.php?page=vapt-auditor&scan_id=' . $current_scan_id); ?>" class="button button-secondary"><span class="dashicons dashicons-update" style="margin-top: 4px; font-size: 16px;"></span> Refresh Results</a>
              <?php
              $is_sync = isset($_GET['sync_process']) || isset($_GET['vapt_sync_done']);
              if ($is_sync) {
                $btn_url = admin_url('admin.php?page=vapt-auditor&scan_id=' . $current_scan_id);
                $btn_class = 'button vapt-btn-async';
                $btn_label = '🔄 Switch to Asynchronous (AJAX)';
                $mode_badge = '<span class="vapt-mode-badge mode-sync">Processing Mode: SYNC (PHP)</span>';
              } else {
                $btn_url = admin_url('admin.php?page=vapt-auditor&scan_id=' . $current_scan_id . '&sync_process=1');
                $btn_class = 'button vapt-btn-sync';
                $btn_label = '🔧 Process Synchronously';
                $mode_badge = '<span class="vapt-mode-badge mode-async">Processing Mode: ASYNC (AJAX)</span>';
              }
              ?>
              <a href="<?php echo $btn_url; ?>" class="<?php echo $btn_class; ?>" <?php echo !$is_sync ? 'onclick="return confirm(\'This will process the entire scan synchronously. Continue?\')"' : ''; ?>>
                <?php echo $btn_label; ?>
              </a>
              <?php echo $mode_badge; ?>
            </div>
          </div>

          <script type="text/javascript">
            var vapt_scan_results = <?php echo json_encode($scan_results ?: []); ?>;
          </script>

          <?php
          // Status Feedback
          $status = $scan_data['status'] ?? 'unknown';

          if ($status === 'running' || $status === 'pending') {
            // Progress Bar Implementation
            // Use current_time('timestamp') to match the timezone of started_at (which comes from current_time('mysql'))
            $started_at_ts = strtotime($scan_data['started_at']);
            $current_ts = current_time('timestamp');
            $elapsed = max(0, $current_ts - $started_at_ts);

            // Fetch real progress from option
            $progress = get_option('vapt_scan_progress_' . $scan_data['id']);
            $checked = $progress['checked'] ?? 0;

            // Get real total from active data file
            $vulnerability_data = $this->get_vulnerability_data();
            $total = !empty($vulnerability_data) ? count($vulnerability_data) : ($progress['total'] ?? 0);

            $percent = $total > 0 ? min(100, round(($checked / $total) * 100)) : 0;

            // Fetch found vulnerabilities count
            $found_count = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$wpdb->prefix}vapt_scan_results WHERE scan_id = %d", $scan_data['id']));
            $pass_count = max(0, $checked - $found_count);

            echo '<div class="vapt-scan-status-container">';
            echo '<p><strong>Scan in progress...</strong> <span class="spinner is-active" style="float:none; margin:0;"></span></p>';
            echo '<p class="description" id="vapt-timer">Scan started ' . $elapsed . ' seconds ago</p>';

            // Progress Bar
            echo '<div class="vapt-progress-bar-wrapper position-relative">';
            echo '<div class="vapt-progress-bar" id="vapt-progress-fill" style="width: ' . $percent . '%"></div>';
            echo '<span id="vapt-progress-text" class="vapt-progress-text">' . $percent . '%</span>';
            echo '</div>';

            // Live Stats
            echo '<div class="vapt-scan-stats">';
            echo '<div class="vapt-stat-item"><strong>Checked:</strong> ' . $checked . ' / ' . $total . '</div>';
            echo '<div class="vapt-stat-item type-success"><strong>Pass:</strong> ' . $pass_count . '</div>';
            echo '<div class="vapt-stat-item type-fail"><strong>Found:</strong> ' . $found_count . '</div>';
            echo '<div id="vapt-current-status-text" class="vapt-stat-item" style="flex: 100%; margin-top: 10px; font-weight: normal; color: #666;">Initializing...</div>';
            echo '</div>';

            echo '<p class="description">Please wait while the scanner analyzes the target.</p>';
            echo '</div>';

            // Add scan ID for JS
            echo '<script>var vaptScanId = ' . $scan_data['id'] . ';</script>';

            // Dynamic Progress JS (AJAX Polling)
            echo "<script>
              jQuery(document).ready(function($) {
                var initialElapsed = " . $elapsed . ";
                var pageLoadTime = new Date().getTime();
                var timerEl = document.getElementById('vapt-timer');
                
                function updateTimer() {
                    var now = new Date().getTime();
                    var sessionElapsed = Math.floor((now - pageLoadTime) / 1000);
                    var totalElapsed = initialElapsed + sessionElapsed;
                    if (timerEl) timerEl.textContent = 'Scan started ' + totalElapsed + ' seconds ago';
                }
                setInterval(updateTimer, 1000);

                var isProcessing = false;

                function processScanBatch(offset) {
                    isProcessing = true;
                    console.log('VAPT: Processing batch at offset ' + offset);
                    
                    $.ajax({
                        url: ajaxurl,
                        type: 'POST',
                        data: {
                            action: 'vapt_process_scan',
                            scan_id: vaptScanId,
                            offset: offset
                        },
                        success: function(response) {
                            if (response.success) {
                                var res = response.data;
                                if (res.status === 'completed') {
                                    console.log('VAPT: Scan completed! Result reload...');
                                    var currentUrl = new URL(window.location.href);
                                    currentUrl.searchParams.set('scan_id', vaptScanId);
                                    window.location.href = currentUrl.toString();
                                } else {
                                    // Recurse
                                    processScanBatch(res.next_offset);
                                }
                            } else {
                                console.error('VAPT Batch Error:', response);
                                isProcessing = false; // Allow resume
                            }
                        },
                        error: function() {
                            console.error('VAPT Batch AJAX Error');
                            isProcessing = false; // Allow resume
                        }
                    });
                }
                
                // Start worker if not started
                // We rely on initial checkProgress to determine start offset

                function checkProgress() {
                    $.ajax({
                        url: ajaxurl,
                        data: {
                            action: 'vapt_check_progress',
                            scan_id: vaptScanId
                        },
                        success: function(response) {
                            console.log('VAPT Progress Response:', response);
                            if (response.success) {
                                var data = response.data;
                                console.log('VAPT Progress Data:', data);

                                // Helper start worker
                                if (!isProcessing && data.status !== 'completed' && data.status !== 'failed') {
                                    console.log('VAPT: Auto-starting batch worker from offset ' + data.checked);
                                    processScanBatch(data.checked);
                                }

                                // Update stats text
                                $('.vapt-stat-item:eq(0)').html('<strong>Checked:</strong> ' + data.checked + ' / ' + data.total);
                                $('.vapt-stat-item:eq(1)').html('<strong>Pass:</strong> ' + data.pass);
                                $('.vapt-stat-item:eq(2)').html('<strong>Found:</strong> ' + data.found);
                                
                                if (data.current_title) {
                                  $('#vapt-current-status-text').html('Scanning: <strong>' + data.current_title + '</strong> - ' + data.current_category + ' (' + data.current_severity + ')');
                                }

                                // Update bar
                                var percent = 0;
                                if (data.total > 0) {
                                    percent = Math.min(100, Math.round((data.checked / data.total) * 100));
                                }
                                $('#vapt-progress-fill').css('width', percent + '%');
                                $('#vapt-progress-text').text(percent + '%');

                                // Handle completion
                                if (data.status === 'completed' || data.status === 'failed') {
                                    console.log('VAPT: Scan finished. Reloading with ID ' + vaptScanId);
                                    
                                    var currentUrl = new URL(window.location.href);
                                    currentUrl.searchParams.set('scan_id', vaptScanId);
                                    window.location.href = currentUrl.toString();
                                } else {
                                    setTimeout(checkProgress, 2000);
                                }
                            } else {
                                setTimeout(checkProgress, 5000);
                            }
                        },
                        error: function() {
                            setTimeout(checkProgress, 5000);
                        }
                    });
                }
                setTimeout(checkProgress, 1000);
              });
            </script>";
          } elseif ($status === 'failed') {
            echo '<div class="notice notice-error inline"><p>Scan failed to complete. Please check error logs.</p></div>';
          } elseif ($status === 'completed' && empty($scan_results)) {
            // Even if empty, we might want to show the stats that everything passed
          }

          if ($status === 'completed') {
            // Calculate Stats
            $progress = get_option('vapt_scan_progress_' . $scan_data['id']);
            $vulnerability_data = $this->get_vulnerability_data();
            $total_checked = !empty($vulnerability_data) ? count($vulnerability_data) : ($progress['total'] ?? 0);
            $total_found = count($scan_results);
            $passed = max(0, $total_checked - $total_found);

            $counts = [
              'critical' => 0,
              'high' => 0,
              'medium' => 0,
              'low' => 0
            ];
            foreach ($scan_results as $r) {
              $sev = strtolower($r['severity']);
              if (isset($counts[$sev])) $counts[$sev]++;
            }

            echo '<div class="vapt-scan-summary-dashboard">';
            echo '<div class="vapt-summary-card total"><span class="vapt-summary-label">Tests Performed</span><span class="vapt-summary-value">' . $total_checked . '</span></div>';
            echo '<div class="vapt-summary-card pass"><span class="vapt-summary-label">Passed</span><span class="vapt-summary-value">' . $passed . '</span></div>';
            foreach ($counts as $sev => $count) {
              echo '<div class="vapt-summary-card ' . $sev . '"><span class="vapt-summary-label">' . ucfirst($sev) . '</span><span class="vapt-summary-value">' . $count . '</span></div>';
            }
            echo '</div>';

            // Filter Bar
            echo '<div class="vapt-filter-bar" style="margin: 20px 0; background: #fff; padding: 15px; border: 1px solid #ccd0d4; border-radius: 4px; display: flex; gap: 20px; align-items: center;">
                    <div class="filter-group">
                        <label for="filter-severity" style="font-weight: 600; margin-right: 8px;">Severity:</label>
                        <select id="filter-severity" class="vapt-filter-select">
                            <option value="">All Severities</option>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label for="filter-search" style="font-weight: 600; margin-right: 8px;">Search:</label>
                        <input type="text" id="filter-search" placeholder="Risk title or ID..." class="regular-text" style="width: 250px;">
                    </div>
                    <div style="margin-left: auto;">
                        <span class="description">Showing <span id="vapt-visible-count">' . $total_found . '</span> findings</span>
                    </div>
                  </div>';

            if (empty($scan_results)) {
              echo '<div class="notice notice-success inline" style="margin-top:20px;"><p><strong>Great job!</strong> No vulnerabilities were found matching the provided signatures.</p></div>';
            } else {
          ?>
              <div class="vapt-auditor-results-wrap">
                <table class="wp-list-table widefat fixed striped" id="vapt-results-table">
                  <thead>
                    <tr>
                      <th class="manage-column column-id sortable" data-sort="id">Risk ID <span class="dashicons dashicons-sort"></span></th>
                      <th class="manage-column column-title sortable" data-sort="title">Vulnerability Title <span class="dashicons dashicons-sort"></span></th>
                      <th class="manage-column column-severity sortable" data-sort="severity">Severity <span class="dashicons dashicons-sort"></span></th>
                      <th class="manage-column column-impact">Impact</th>
                      <th class="manage-column column-actions" style="width: 120px;">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    <?php foreach ($scan_results as $result):
                      $vuln_info = [];
                      $all_vulns = $this->get_vulnerability_data();
                      foreach ($all_vulns as $v) {
                        if ($v['id'] === $result['vulnerability_id']) {
                          $vuln_info = $v;
                          break;
                        }
                      }
                      $severity = strtolower($result['severity']);
                      $impact = $vuln_info['impact'] ?? 'Risk of compromise leading to data breach or system compromise';
                    ?>
                      <tr class="vapt-result-row" data-severity="<?php echo esc_attr($severity); ?>" data-title="<?php echo esc_attr($vuln_info['name'] ?? ''); ?>" data-id="<?php echo esc_attr($result['vulnerability_id']); ?>">
                        <td><code><?php echo esc_html($result['vulnerability_id']); ?></code></td>
                        <td><strong><?php echo esc_html($vuln_info['name'] ?? $result['vulnerability_id']); ?></strong></td>
                        <td><span class="vapt-severity-badge vapt-severity-<?php echo $severity; ?>"><?php echo ucfirst($severity); ?></span></td>
                        <td>
                          <div class="vapt-truncated-text" title="<?php echo esc_attr($impact); ?>"><?php echo esc_html(wp_trim_words($impact, 10)); ?></div>
                        </td>
                        <td>
                          <button class="button vapt-details-btn" data-vuln-id="<?php echo esc_attr($result['vulnerability_id']); ?>">Details</button>
                          <?php if (!empty($result['screenshot_path'])): ?>
                            <a href="<?php echo esc_url(VAPT_URL . 'data/screenshots/' . basename($result['screenshot_path'])); ?>" target="_blank" class="button" title="View Evidence Screenshot"><span class="dashicons dashicons-visibility"></span></a>
                          <?php endif; ?>
                        </td>
                      </tr>
                    <?php endforeach; ?>
                  </tbody>
                </table>
              </div>
          <?php
            }
          }
          ?>

          <!-- Hidden details modal -->
          <div id="vapt-details-modal" class="vapt-modal" style="display: none;">
            <div class="vapt-modal-content" style="max-width: 800px; width: 90%;">
              <span class="vapt-modal-close">&times;</span>
              <div class="vapt-modal-header" style="border-bottom: 2px solid #eee; margin-bottom: 20px; padding-bottom: 10px;">
                <h2 id="modal-title" style="margin: 0; color: #23282d;"></h2>
                <div id="modal-subtitle" class="description" style="margin-top: 5px;"></div>
              </div>
              <div id="modal-content"></div>
              <div class="vapt-modal-footer" style="margin-top: 30px; border-top: 1px solid #eee; padding-top: 15px; text-align: right;">
                <button class="button button-secondary vapt-modal-close">Close Report</button>
              </div>
            </div>
          </div>

        </div>
      <?php endif; ?>

      <?php if (!empty($debug_log)): ?>
        <div class="vapt-debug-section" style="margin-top: 30px;">
          <h2>Debug Log</h2>
          <div class="vapt-debug-controls" style="margin-bottom: 10px;">
            <button type="button" id="toggle-debug-log" class="button">Show/Hide Debug Log</button>
            <button type="button" id="export-debug-log" class="button">Export Debug Log</button>
          </div>
          <div id="debug-log-container" style="display: none; max-height: 400px; overflow-y: auto; background: #f5f5f5; padding: 10px; border: 1px solid #ddd; font-family: monospace; font-size: 12px;">
            <pre><?php echo esc_html(implode("\n", $debug_log)); ?></pre>
          </div>
        </div>

        <script>
          jQuery(document).ready(function($) {
            $('#toggle-debug-log').on('click', function() {
              $('#debug-log-container').toggle();
            });

            $('#export-debug-log').on('click', function() {
              var debugText = <?php echo json_encode(implode("\n", $debug_log)); ?>;
              var blob = new Blob([debugText], {
                type: 'text/plain'
              });
              var url = window.URL.createObjectURL(blob);
              var a = document.createElement('a');
              a.href = url;
              a.download = 'vapt-debug-log-<?php echo $current_scan_id; ?>.txt';
              document.body.appendChild(a);
              a.click();
              document.body.removeChild(a);
              window.URL.revokeObjectURL(url);
            });
          });
        </script>
      <?php endif; ?>

    </div>

    <script type="text/javascript">
      jQuery(document).ready(function($) {
        // Data for modal
        var vulnerabilityData = <?php echo json_encode($this->get_vulnerability_data()); ?>;
        var scanResults = <?php echo json_encode($scan_results); ?>;

        // Filtering Logic
        function applyFilters() {
          var severity = $('#filter-severity').val().toLowerCase();
          var search = $('#filter-search').val().toLowerCase();
          var visibleCount = 0;

          $('.vapt-result-row').each(function() {
            var rowSev = $(this).data('severity');
            var rowTitle = $(this).data('title').toLowerCase();
            var rowId = $(this).data('id').toLowerCase();

            var showSev = severity === '' || rowSev === severity;
            var showSearch = search === '' || rowTitle.includes(search) || rowId.includes(search);

            if (showSev && showSearch) {
              $(this).show();
              visibleCount++;
            } else {
              $(this).hide();
            }
          });
          $('#vapt-visible-count').text(visibleCount);
        }

        $('#filter-severity, #filter-search').on('change keyup', applyFilters);

        // Sorting Logic
        $('.sortable').on('click', function() {
          var table = $(this).closest('table');
          var rows = table.find('tbody tr').get();
          var colIndex = $(this).index();
          var type = $(this).data('sort');
          var isAsc = $(this).hasClass('asc');

          $('.sortable').removeClass('asc desc');
          $(this).addClass(isAsc ? 'desc' : 'asc');

          rows.sort(function(a, b) {
            var valA = $(a).children('td').eq(colIndex).text().toUpperCase();
            var valB = $(b).children('td').eq(colIndex).text().toUpperCase();

            // Severity weighting
            if (type === 'severity') {
              var weights = {
                critical: 1,
                high: 2,
                medium: 3,
                low: 4
              };
              valA = weights[$(a).data('severity')] || 99;
              valB = weights[$(b).data('severity')] || 99;
            }

            if (valA < valB) return isAsc ? 1 : -1;
            if (valA > valB) return isAsc ? -1 : 1;
            return 0;
          });

          $.each(rows, function(index, row) {
            table.children('tbody').append(row);
          });
        });

        // Modal Details
        $('.vapt-details-btn').on('click', function() {
          var vulnId = $(this).data('vuln-id');
          var vuln = vulnerabilityData.find(v => v.id === vulnId);
          var result = scanResults.find(r => r.vulnerability_id === vulnId);

          if (vuln && result) {
            $('#modal-title').text(vuln.name);
            $('#modal-subtitle').html('ID: <code>' + vuln.id + '</code> | Severity: <span class="vapt-severity-badge vapt-severity-' + vuln.severity.toLowerCase() + '">' + vuln.severity + '</span>' + (vuln.cvss ? ' | CVSS: <strong>' + vuln.cvss + '</strong>' : '') + (vuln.owasp ? ' | OWASP: <strong>' + vuln.owasp + '</strong>' : ''));

            var verificationHtml = '';
            if (vuln.verification_steps && vuln.verification_steps.length > 0) {
              verificationHtml = '<h4>Manual Verification Steps</h4><ul style="padding-left: 20px; list-style-type: decimal; margin-top: 10px;">';
              vuln.verification_steps.forEach(function(step) {
                // Strip leading numbers and dots (e.g., "1. " or "2. ") if they exist to avoid double numbering
                var cleanStep = step.replace(/^\d+[\s\.]+\s*/, '');
                verificationHtml += '<li style="margin-bottom: 5px;">' + cleanStep + '</li>';
              });
              verificationHtml += '</ul>';
            }

            var screenshotHtml = '';
            var rawPaths = result.screenshot_paths || result.screenshot_path;
            if (rawPaths) {
              try {
                var paths = (typeof rawPaths === 'string' && rawPaths.startsWith('[')) ? JSON.parse(rawPaths) : [rawPaths];
                if (Array.isArray(paths) && paths.length > 0) {
                  screenshotHtml = '<h4>Audit Evidence Gallery</h4><div class="vapt-evidence-gallery" style="display: flex; gap: 15px; overflow-x: auto; padding: 10px 5px; margin-top: 10px; background: #f0f0f1; border-radius: 6px; border: 1px solid #dcdcde;">';
                  paths.forEach(function(path) {
                    if (!path) return;
                    var screenshotName = path.split(/[\\\\/]/).pop();
                    var screenshotUrl = '<?php echo esc_url(VAPT_URL); ?>data/screenshots/' + screenshotName;
                    screenshotHtml += '<div style="flex: 0 0 200px; border: 1px solid #ccd0d4; padding: 4px; background: #fff; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">' +
                      '<a href="' + screenshotUrl + '" target="_blank"><img src="' + screenshotUrl + '" style="width: 100%; height: auto; display: block; border-radius: 2px;" onerror="this.parentElement.innerHTML=\'<p style=\\\'font-size:10px; padding:10px; color:#666;\\\'>Missing: \' + screenshotName + \'</p>\'"></a>' +
                      '</div>';
                  });
                  screenshotHtml += '</div><p class="description">Click image to view full-size conclusive evidence.</p>';
                }
              } catch (e) {
                console.error("VAPT Image Parse Error:", e);
              }
            }

            var content = '<div class="vapt-modal-details-grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">' +
              '<div class="vapt-detail-col">' +
              '<h4>Description</h4><p>' + (vuln.description || result.description || 'N/A') + '</p>' +
              '<h4>Impact</h4><p>' + (vuln.impact || result.impact || 'N/A') + '</p>' +
              screenshotHtml +
              '</div>' +
              '<div class="vapt-detail-col">' +
              '<h4>Remediation / Recommendation</h4><p>' + (vuln.recommendation || result.recommendation || 'N/A') + '</p>' +
              '<h4>Detection Info</h4>' +
              '<ul>' +
              '<li><strong>Detection Endpoint:</strong> <a href="' + result.affected_url + '" target="_blank" style="word-break: break-all;">' + result.affected_url + '</a></li>' +
              (result.evidence_url && result.evidence_url !== result.affected_url ? '<li><strong>Raw Evidence:</strong> <a href="' + result.evidence_url + '" target="_blank">View Result</a></li>' : '') +
              '<li><strong>Scan Date:</strong> ' + (result.found_at || result.captured_at || 'N/A') + '</li>' +
              '</ul>' +
              verificationHtml +
              '</div>' +
              '</div>';
            $('#modal-content').html(content);
            $('#vapt-details-modal').show();
          }
        });

        $('.vapt-modal-close').on('click', function() {
          $('#vapt-details-modal').hide();
        });

        $(window).on('click', function(event) {
          if (event.target == document.getElementById('vapt-details-modal')) {
            $('#vapt-details-modal').hide();
          }
        });
      });
    </script>
<?php
  }

  private function get_vulnerability_name($id)
  {
    $vulnerabilities = $this->get_vulnerability_data();
    if (!empty($vulnerabilities)) {
      foreach ($vulnerabilities as $vuln) {
        if ($vuln['id'] === $id) {
          return $vuln['name'];
        }
      }
    }
    return $id;
  }
}
