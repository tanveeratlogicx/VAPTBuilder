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
    add_action('admin_enqueue_scripts', array($this, 'enqueue_scripts'));
    add_action('wp_ajax_vapt_check_progress', array($this, 'ajax_check_progress'));
    add_action('wp_ajax_vapt_process_scan', array($this, 'ajax_process_scan'));
  }

  public function ajax_process_scan()
  {
    // This endpoint triggers the actual scan work
    if (!current_user_can('manage_options')) {
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
        error_log("VAPT DEBUG: Starting batch at offset $offset with limit 15");

        $result = $scanner->run_scan($scan_id, $target_url, $offset, 15); // Increased batch size

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
    if (!current_user_can('manage_options')) {
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
    $total = $progress['total'] ?? 99;

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
      $file_path = VAPT_PATH . 'data/Feature-List-99.json';
      if (file_exists($file_path)) {
        $data = json_decode(file_get_contents($file_path), true);
        if ($data && isset($data['features'])) {
          $this->vulnerabilities_cache = $data['features'];
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

  public function admin_page()
  {
    global $wpdb;
    if (!current_user_can('manage_options')) {
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

    // EMERGENCY SYNC PROCESSING - Uncomment this block if AJAX fails
    if ($current_scan_id && isset($_GET['sync_process'])) {
      echo "<h3>Processing scan synchronously...</h3>";
      $scanner = new VAPT_Scanner();
      $result = $scanner->run_scan($current_scan_id, $target_url, 0, 99);
      echo "<pre>Result: " . print_r($result, true) . "</pre>";
      echo "<pre>Debug Log:\n" . implode("\n", $scanner->get_debug_log()) . "</pre>";
      wp_die('Sync processing complete');
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
      <h1>VAPT Security Auditor</h1>

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

      <?php if ($current_scan_id): ?>
        <div class="vapt-scan-results">
          <div class="vapt-results-header">
            <h2>Scan Results</h2>
            <div style="margin-bottom: 10px;">
              <a href="<?php echo admin_url('admin.php?page=vapt-auditor&scan_id=' . $current_scan_id); ?>" class="button button-secondary"><span class="dashicons dashicons-update" style="margin-top: 4px; font-size: 16px;"></span> Refresh Results</a>
              <a href="<?php echo admin_url('admin.php?page=vapt-auditor&scan_id=' . $current_scan_id . '&sync_process=1'); ?>" class="button button-primary" onclick="return confirm('This will process the entire scan synchronously. Continue?')">🔧 Process Synchronously</a>
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
            $total = $progress['total'] ?? 99; // Default to a reasonable number if unknown
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
                                // Retry after delay?
                                setTimeout(function() { processScanBatch(offset); }, 3000);
                            }
                        },
                        error: function() {
                            // Retry after delay
                            setTimeout(function() { processScanBatch(offset); }, 3000);
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
            $total_checked = $progress['total'] ?? 99;
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
            echo '<div class="vapt-summary-card total">
                     <span class="vapt-summary-label">Tests Performed</span>
                     <span class="vapt-summary-value">' . $total_checked . '</span>
                   </div>';
            echo '<div class="vapt-summary-card pass">
                     <span class="vapt-summary-label">Passed</span>
                     <span class="vapt-summary-value">' . $passed . '</span>
                   </div>';

            foreach ($counts as $sev => $count) {
              echo '<div class="vapt-summary-card ' . $sev . '">
                        <span class="vapt-summary-label">' . ucfirst($sev) . '</span>
                        <span class="vapt-summary-value">' . $count . '</span>
                      </div>';
            }
            echo '</div>';

            if (empty($scan_results)) {
              echo '<div class="notice notice-success inline" style="margin-top:20px;"><p><strong>Great job!</strong> No vulnerabilities were found matching the provided signatures.</p></div>';
            }
          }

          // Group results by severity
          $severity_groups = [
            'critical' => [],
            'high' => [],
            'medium' => [],
            'low' => []
          ];

          foreach ($scan_results as $result) {
            $severity = strtolower($result['severity']);
            if (isset($severity_groups[$severity])) {
              $severity_groups[$severity][] = $result;
            }
          }

          foreach (['critical', 'high', 'medium', 'low'] as $severity):
            if (!empty($severity_groups[$severity])):
          ?>
              <div class="vapt-severity-section vapt-severity-<?php echo $severity; ?>">
                <h3><?php echo ucfirst($severity); ?> Severity Vulnerabilities (<?php echo count($severity_groups[$severity]); ?>)</h3>
                <table class="wp-list-table widefat fixed striped">
                  <thead>
                    <tr>
                      <th>Vulnerability ID</th>
                      <th>Title</th>
                      <th>Severity</th>
                      <th>Affected URL</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    <?php foreach ($severity_groups[$severity] as $result): ?>
                      <tr>
                        <td><?php echo esc_html($result['vulnerability_id']); ?></td>
                        <td><?php echo esc_html($this->get_vulnerability_name($result['vulnerability_id'])); ?></td>
                        <td><span class="vapt-severity-badge vapt-severity-<?php echo $severity; ?>"><?php echo ucfirst($severity); ?></span></td>
                        <td><a href="<?php echo esc_url($result['affected_url']); ?>" target="_blank"><?php echo esc_html($result['affected_url']); ?></a></td>
                        <td>
                          <button class="button vapt-details-btn" data-vuln-id="<?php echo esc_attr($result['vulnerability_id']); ?>">Details</button>
                          <?php if (!empty($result['screenshot_path'])): ?>
                            <a href="<?php echo esc_url(VAPT_URL . 'data/screenshots/' . basename($result['screenshot_path'])); ?>" target="_blank" class="button">Screenshot</a>
                          <?php endif; ?>
                        </td>
                      </tr>
                    <?php endforeach; ?>
                  </tbody>
                </table>
              </div>
          <?php
            endif;
          endforeach;
          ?>

          <!-- Hidden details modal -->
          <div id="vapt-details-modal" class="vapt-modal" style="display: none;">
            <div class="vapt-modal-content">
              <span class="vapt-modal-close">&times;</span>
              <h3 id="modal-title"></h3>
              <div id="modal-content"></div>
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
        $('.vapt-details-btn').on('click', function() {
          var vulnId = $(this).data('vuln-id');
          var result = null;

          // Find the result data
          for (var i = 0; i < vapt_scan_results.length; i++) {
            if (vapt_scan_results[i].vulnerability_id === vulnId) {
              result = vapt_scan_results[i];
              break;
            }
          }

          if (result) {
            $('#modal-title').text(result.vulnerability_id);
            var content = '<div class="vapt-modal-details">' +
              '<p><strong>Description:</strong> ' + (result.description || 'N/A') + '</p>' +
              '<p><strong>Impact:</strong> ' + (result.impact || 'N/A') + '</p>' +
              '<p><strong>Recommendation:</strong> ' + (result.recommendation || 'N/A') + '</p>' +
              '<p><strong>Steps to Reproduce:</strong> ' + (result.steps_to_reproduce || 'N/A') + '</p>' +
              '<p><strong>Affected URL:</strong> <a href="' + result.affected_url + '" target="_blank">' + result.affected_url + '</a></p>' +
              (result.evidence_url ? '<p><strong>Evidence URL:</strong> <a href="' + result.evidence_url + '" target="_blank">' + result.evidence_url + '</a></p>' : '') +
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
