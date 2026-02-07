<?php

/**
 * REST API Handler for VAPT Builder
 */

if (! defined('ABSPATH')) {
  exit;
}

class VAPT_REST
{

  public function __construct()
  {
    add_action('rest_api_init', array($this, 'register_routes'));
  }

  public function register_routes()
  {
    register_rest_route('vapt/v1', '/features', array(
      'methods'  => 'GET',
      'callback' => array($this, 'get_features'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/data-files/all', array(
      'methods' => 'GET',
      'callback' => array($this, 'get_all_data_files'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/data-files', array(
      'methods'  => 'GET',
      'callback' => array($this, 'get_data_files'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/update-hidden-files', array(
      'methods' => 'POST',
      'callback' => array($this, 'update_hidden_files'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/reset-limit', array(
      'methods' => 'POST',
      'callback' => array($this, 'reset_rate_limit'),
      'permission_callback' => '__return_true', // Public endpoint for testing (limited to user IP)
    ));


    register_rest_route('vapt/v1', '/features/update', array(
      'methods'  => 'POST',
      'callback' => array($this, 'update_feature'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/features/transition', array(
      'methods'  => 'POST',
      'callback' => array($this, 'transition_feature'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/features/(?P<key>[a-zA-Z0-9_-]+)/history', array(
      'methods'  => 'GET',
      'callback' => array($this, 'get_feature_history'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/features/(?P<key>[a-zA-Z0-9_-]+)/stats', array(
      'methods'  => 'GET',
      'callback' => array($this, 'get_feature_stats'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/features/(?P<key>[a-zA-Z0-9_-]+)/reset', array(
      'methods'  => 'POST',
      'callback' => array($this, 'reset_feature_stats'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/assignees', array(
      'methods'  => 'GET',
      'callback' => array($this, 'get_assignees'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/features/assign', array(
      'methods'  => 'POST',
      'callback' => array($this, 'update_assignment'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/upload-json', array(
      'methods'  => 'POST',
      'callback' => array($this, 'upload_json'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/domains', array(
      'methods'  => 'GET',
      'callback' => array($this, 'get_domains'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/domains/update', array(
      'methods'  => 'POST',
      'callback' => array($this, 'update_domain'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/domains/features', array(
      'methods'  => 'POST',
      'callback' => array($this, 'update_domain_features'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/domains/delete', array(
      'methods'  => 'DELETE',
      'callback' => array($this, 'delete_domain'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/domains/batch-delete', array(
      'methods'  => 'POST',
      'callback' => array($this, 'batch_delete_domains'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/build/generate', array(
      'methods'  => 'POST',
      'callback' => array($this, 'generate_build'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/build/save-config', array(
      'methods'  => 'POST',
      'callback' => array($this, 'save_config_to_root'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/upload-media', array(
      'methods'  => 'POST',
      'callback' => array($this, 'upload_media'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/data-files/meta', array(
      'methods'  => 'POST',
      'callback' => array($this, 'update_file_meta'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/active-file', array(
      'methods'  => array('GET', 'POST'),
      'callback' => array($this, 'handle_active_file'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/build/sync-config', array(
      'methods'  => 'POST',
      'callback' => array($this, 'sync_config_from_file'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    // Scanner routes
    register_rest_route('vapt/v1', '/scan/start', array(
      'methods'  => 'POST',
      'callback' => array($this, 'start_scan'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/scan/(?P<id>\d+)/report', array(
      'methods'  => 'GET',
      'callback' => array($this, 'get_scan_report'),
      'permission_callback' => array($this, 'check_permission'),
    ));

    register_rest_route('vapt/v1', '/scans', array(
      'methods'  => 'GET',
      'callback' => array($this, 'get_scans'),
      'permission_callback' => array($this, 'check_permission'),
    ));
  }

  public function check_permission()
  {
    return is_vapt_superadmin();
  }

  public function get_features($request)
  {
    $default_file = defined('VAPT_ACTIVE_DATA_FILE') ? VAPT_ACTIVE_DATA_FILE : 'VAPT-Complete-Risk-Catalog-99.json';
    $file = $request->get_param('file') ?: $default_file;
    $json_path = VAPT_PATH . 'data/' . sanitize_file_name($file);

    if (! file_exists($json_path)) {
      return new WP_REST_Response(array('error' => 'JSON file not found: ' . $file), 404);
    }

    $content = file_get_contents($json_path);
    $raw_data = json_decode($content, true);

    if (! is_array($raw_data)) {
      return new WP_REST_Response(array('error' => 'Invalid JSON format'), 400);
    }

    $features = [];
    $schema = [];

    if (isset($raw_data['wordpress_vapt']) && is_array($raw_data['wordpress_vapt'])) {
      $features = $raw_data['wordpress_vapt'];
      $schema = isset($raw_data['schema']) ? $raw_data['schema'] : [];
    } elseif (isset($raw_data['features']) && is_array($raw_data['features'])) {
      $features = $raw_data['features'];
      $schema = isset($raw_data['schema']) ? $raw_data['schema'] : [];
    } elseif (isset($raw_data['risk_catalog']) && is_array($raw_data['risk_catalog'])) {
      // 🛡️ ADAPTER: VAPT Risk Catalog Format (v3.0+)
      $raw_features = $raw_data['risk_catalog'];
      $features = array();
      foreach ($raw_features as $item) {
        // 1. Flatten Description
        if (isset($item['description']) && is_array($item['description'])) {
          $item['description'] = isset($item['description']['summary']) ? $item['description']['summary'] : '';
        }
        // 2. Flatten Severity
        if (isset($item['severity']) && is_array($item['severity'])) {
          $item['severity'] = isset($item['severity']['level']) ? $item['severity']['level'] : 'medium';
        }

        // 3. Flatten Test Method (Hybrid Support)
        if (empty($item['test_method']) && isset($item['testing']['test_method'])) {
          $item['test_method'] = $item['testing']['test_method'];
        }

        // 4. Flatten Verification Engine (Hybrid Support)
        if (empty($item['verification_engine']) && isset($item['protection']['automated_protection'])) {
          // Store entire object or just availability/method? Frontend expects string/key usually, 
          // but for checking existence/mapping, the object is fine. 
          // However, for the 'Auto-Detect' to pick 'verification_engine' key, we just need to Ensure KEY exists.
          $item['verification_engine'] = $item['protection']['automated_protection'];
        }
        // 3. Flatten Verification Steps
        if (isset($item['testing']) && isset($item['testing']['verification_steps']) && is_array($item['testing']['verification_steps'])) {
          $steps = [];
          foreach ($item['testing']['verification_steps'] as $step) {
            if (is_array($step) && isset($step['action'])) {
              $steps[] = $step['action'];
            } elseif (is_string($step)) {
              $steps[] = $step;
            }
          }
          $item['verification_steps'] = $steps;
        }
        // 4. Flatten Remediation
        if (isset($item['protection']) && is_array($item['protection'])) {
          // Try to find code in automated protection
          if (isset($item['protection']['automated_protection']['implementation_steps'][0]['code'])) {
            $item['remediation'] = $item['protection']['automated_protection']['implementation_steps'][0]['code'];
          }
        }
        // 5. Map OWASP
        if (isset($item['owasp_mapping']) && isset($item['owasp_mapping']['owasp_top_10_2021'])) {
          $item['owasp'] = $item['owasp_mapping']['owasp_top_10_2021'];
        }

        $features[] = $item;
      }
      $schema = isset($raw_data['schema']) ? $raw_data['schema'] : [];
    } else {
      $features = $raw_data;
    }

    // Default schema if missing
    if (empty($schema)) {
      $schema = array(
        'item_fields' => array('id', 'category', 'title', 'severity', 'description')
      );
    }

    $statuses = VAPT_DB::get_feature_statuses_full();
    $status_map = [];
    foreach ($statuses as $row) {
      $status_map[$row['feature_key']] = array(
        'status' => $row['status'],
        'implemented_at' => $row['implemented_at'],
        'assigned_to' => $row['assigned_to']
      );
    }

    // Security/Scope Check
    $scope = $request->get_param('scope');
    $is_superadmin = is_vapt_superadmin();

    // Batch fetch history counts to avoid N+1 queries
    global $wpdb;
    $history_table = $wpdb->prefix . 'vapt_feature_history';
    $history_counts = $wpdb->get_results("SELECT feature_key, COUNT(*) as count FROM $history_table GROUP BY feature_key", OBJECT_K);

    // Merge with status and meta
    foreach ($features as &$feature) {
      // Robust Title/Label mapping
      $label = '';
      if (isset($feature['name'])) $label = $feature['name'];
      else if (isset($feature['title'])) $label = $feature['title'];
      else if (isset($feature['label'])) $label = $feature['label'];
      else $label = __('Unnamed Feature', 'vapt-builder');

      $feature['label'] = $label;

      // Unique Key Generation
      $key = '';
      if (isset($feature['id'])) $key = $feature['id'];
      else if (isset($feature['key'])) $key = $feature['key'];
      else $key = sanitize_title($label);

      $feature['key'] = $key;

      $st = isset($status_map[$key]) ? $status_map[$key] : array('status' => 'Draft', 'implemented_at' => null, 'assigned_to' => null);

      $feature['status'] = $st['status'];
      $feature['implemented_at'] = $st['implemented_at'];
      $feature['assigned_to'] = $st['assigned_to'];

      // Normalize status synonyms for internal logic
      $norm_status = strtolower($st['status']);
      if ($norm_status === 'implemented') $norm_status = 'release';
      if ($norm_status === 'in_progress') $norm_status = 'develop';
      if ($norm_status === 'testing')     $norm_status = 'test';
      if ($norm_status === 'available')   $norm_status = 'draft';
      $feature['normalized_status'] = $norm_status;
      $feature['status'] = ucfirst($norm_status); // Force Canonical Title Case

      $meta = VAPT_DB::get_feature_meta($key);
      if ($meta) {
        $feature['include_test_method'] = (bool) $meta['include_test_method'];
        $feature['include_verification'] = (bool) $meta['include_verification'];
        $feature['include_verification_engine'] = isset($meta['include_verification_engine']) ? (bool) $meta['include_verification_engine'] : false;
        $feature['include_verification_guidance'] = isset($meta['include_verification_guidance']) ? (bool) $meta['include_verification_guidance'] : true;
        $feature['include_manual_protocol'] = isset($meta['include_manual_protocol']) ? (bool) $meta['include_manual_protocol'] : true;
        $feature['include_operational_notes'] = isset($meta['include_operational_notes']) ? (bool) $meta['include_operational_notes'] : true;
        $feature['is_enforced'] = (bool) $meta['is_enforced'];
        $feature['wireframe_url'] = $meta['wireframe_url'];
        $feature['dev_instruct'] = isset($meta['dev_instruct']) ? $meta['dev_instruct'] : '';

        // Expose Verification Context for AI Prompt
        if (!empty($meta['verification_steps'])) $feature['verification_steps'] = $meta['verification_steps'];
        if (!empty($meta['test_method'])) $feature['test_method'] = $meta['test_method'];

        // Safely decode schema
        $schema_data = array();
        $use_override_schema = in_array($norm_status, ['test', 'release']) && !empty($meta['override_schema']);
        $source_schema_json = $use_override_schema ? $meta['override_schema'] : $meta['generated_schema'];

        if (!empty($source_schema_json)) {
          $decoded = json_decode($source_schema_json, true);
          if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
            $schema_data = $decoded;
            // Mark as overridden for UI awareness
            if ($use_override_schema) $feature['is_overridden'] = true;
          } else {
            error_log(sprintf(
              'VAPT: Corrupted schema JSON for feature %s. JSON Error: %s',
              $key,
              json_last_error_msg()
            ));
            $schema_data = array();
          }
        }

        // 🛡️ AUTO-REPAIR: If .htaccess feature is missing verifiers, inject them.
        if ($key === '.htaccess-security-rules' || $key === '.htaccess-security') {
          $has_actions = false;
          $has_headers_toggle = false;
          if (isset($schema_data['controls'])) {
            foreach ($schema_data['controls'] as $c) {
              if (isset($c['type']) && $c['type'] === 'test_action') $has_actions = true;
              if (isset($c['key']) && $c['key'] === 'enable_security_headers') $has_headers_toggle = true;
            }
          }

          $mapping_content = isset($schema_data['enforcement']['mappings']['enable_security_headers']) ? $schema_data['enforcement']['mappings']['enable_security_headers'] : '';

          if (!$has_headers_toggle || strpos($mapping_content, 'Expose-Headers') === false) {
            $new_controls = array();
            $new_controls[] = array('type' => 'toggle', 'label' => 'Disable Directory Browsing', 'key' => 'disable_directory_browsing', 'help' => "Adds 'Options -Indexes' to .htaccess");
            $new_controls[] = array('type' => 'toggle', 'label' => 'Block XML-RPC Access', 'key' => 'block_xmlrpc', 'help' => 'Prevents access to xmlrpc.php');
            $new_controls[] = array('type' => 'toggle', 'label' => 'Enable Security Headers', 'key' => 'enable_security_headers', 'help' => 'Adds X-Frame-Options, X-XSS-Protection, etc.');
            $new_controls[] = array('type' => 'test_action', 'label' => 'Header Check', 'key' => 'verif_headers', 'test_logic' => 'check_headers', 'help' => 'Inspects live server headers.');
            $new_controls[] = array('type' => 'test_action', 'label' => 'Directory Probe', 'key' => 'verif_directory', 'test_logic' => 'disable_directory_browsing', 'help' => 'Probes /wp-content/uploads/.');
            $new_controls[] = array('type' => 'test_action', 'label' => 'XML-RPC Probe', 'key' => 'verif_xmlrpc', 'test_logic' => 'block_xmlrpc', 'help' => 'Pings xmlrpc.php.');

            $schema_data['controls'] = $new_controls;
            $schema_data['enforcement'] = array(
              'driver' => 'htaccess',
              'target' => 'root',
              'mappings' => array(
                'disable_directory_browsing' => "Options -Indexes",
                'block_xmlrpc' => "<Files xmlrpc.php>\n  Order Deny,Allow\n  Deny from all\n</Files>",
                'enable_security_headers' => "<IfModule mod_headers.c>\n  Header set X-Frame-Options \"SAMEORIGIN\"\n  Header set X-Content-Type-Options \"nosniff\"\n  Header set X-XSS-Protection \"1; mode=block\"\n  Header set Access-Control-Expose-Headers \"X-Frame-Options, X-Content-Type-Options, X-XSS-Protection\"\n</IfModule>"
              )
            );

            VAPT_DB::update_feature_meta($key, array('generated_schema' => json_encode($schema_data), 'include_verification_engine' => 1));
            $feature['include_verification_engine'] = true;
          }
        }

        // 🛡️ AUTO-REPAIR: Rate Limiting Schema Fix
        if (in_array($key, ['limit-login-attempts', 'rate-limiting', 'login-protection', 'api-rate-limiting'])) {
          $has_rate_probe = false;
          if (isset($schema_data['controls'])) {
            foreach ($schema_data['controls'] as $c) {
              if (isset($c['test_logic']) && $c['test_logic'] === 'spam_requests') $has_rate_probe = true;
            }
          }

          if (!$has_rate_probe) {
            $new_controls = array();
            $toggle_key = 'limit_login_attempts';
            if (isset($schema_data['controls'])) {
              foreach ($schema_data['controls'] as $c) {
                if ($c['type'] !== 'test_action') {
                  $new_controls[] = $c;
                  if ($c['type'] === 'toggle') $toggle_key = $c['key'];
                }
              }
            }
            $new_controls[] = array('type' => 'test_action', 'label' => 'Test: Burst Resilience (13 req/min)', 'key' => 'verif_rate_limit', 'test_logic' => 'spam_requests', 'help' => 'Sends a sharp burst of traffic to test server stability.');
            $new_controls[] = array('type' => 'test_action', 'label' => 'Test: Limit Enforcement', 'key' => 'verif_limit_enforce', 'test_logic' => 'default', 'help' => 'Intentionally exceeds the limit to verify HTTP 429 response.');

            $schema_data['controls'] = $new_controls;
            if (!isset($schema_data['enforcement'])) {
              $schema_data['enforcement'] = array('driver' => 'hook', 'mappings' => array());
            }
            $schema_data['enforcement']['driver'] = 'hook';
            $schema_data['enforcement']['mappings'][$toggle_key] = 'limit_login_attempts';

            VAPT_DB::update_feature_meta($key, array('generated_schema' => json_encode($schema_data), 'include_verification_engine' => 1, 'is_enforced' => 1));
            $feature['include_verification_engine'] = true;
            $feature['generated_schema'] = $schema_data;
            $feature['is_enforced'] = true;
          }
        }

        $feature['generated_schema'] = $schema_data;

        $use_override_impl = in_array($norm_status, ['test', 'release']) && !empty($meta['override_implementation_data']);
        $source_impl_json = $use_override_impl ? $meta['override_implementation_data'] : $meta['implementation_data'];
        $impl_data = $source_impl_json ? json_decode($source_impl_json, true) : array();

        // 🧹 DATA CLEANUP
        $migrations = array(
          'disable_xmlrpc' => 'block_xmlrpc',
          'block_indexes' => 'disable_directory_browsing'
        );
        $changed = false;
        foreach ($migrations as $old => $new) {
          if (isset($impl_data[$old])) {
            $impl_data[$new] = $impl_data[$old];
            unset($impl_data[$old]);
            $changed = true;
          }
        }
        if ($changed) {
          VAPT_DB::update_feature_meta($key, array('implementation_data' => json_encode($impl_data)));
        }

        $feature['implementation_data'] = $impl_data;
      }

      $feature['has_history'] = isset($history_counts[$key]) && $history_counts[$key]->count > 0;
    }

    // Filter for Client Scope
    if ($scope === 'client') {
      $domain = $request->get_param('domain');
      $enabled_features = [];

      if ($domain) {
        $dom_row = $wpdb->get_row($wpdb->prepare("SELECT id FROM {$wpdb->prefix}vapt_domains WHERE domain = %s", $domain));
        if ($dom_row) {
          $feat_rows = $wpdb->get_results($wpdb->prepare("SELECT feature_key FROM {$wpdb->prefix}vapt_domain_features WHERE domain_id = %d AND enabled = 1", $dom_row->id), ARRAY_N);
          $enabled_features = array_column($feat_rows, 0);
        }
      }

      $features = array_filter($features, function ($f) use ($enabled_features, $is_superadmin) {
        $s = isset($f['normalized_status']) ? $f['normalized_status'] : strtolower($f['status']);

        if ($s === 'release') {
          return in_array($f['key'], $enabled_features);
        }

        if ($is_superadmin && in_array($s, ['develop', 'test'])) {
          return true;
        }

        return false;
      });
      $features = array_values($features);
    }

    return new WP_REST_Response(array(
      'features' => $features,
      'schema' => $schema,
      'design_prompt' => isset($raw_data['design_prompt']) ? $raw_data['design_prompt'] : null
    ), 200);
  }

  public function get_data_files()
  {
    $data_dir = VAPT_PATH . 'data';
    if (!is_dir($data_dir)) return new WP_REST_Response([], 200);

    $files = array_diff(scandir($data_dir), array('..', '.'));
    $json_files = [];

    $hidden_files = get_option('vapt_hidden_json_files', array());
    $active_file  = defined('VAPT_ACTIVE_DATA_FILE') ? VAPT_ACTIVE_DATA_FILE : 'VAPT-Complete-Risk-Catalog-99.json';

    $hidden_normalized = array_map('sanitize_file_name', $hidden_files);
    $active_normalized = sanitize_file_name($active_file);

    foreach ($files as $file) {
      if (strtolower(pathinfo($file, PATHINFO_EXTENSION)) === 'json') {
        $normalized_current = sanitize_file_name($file);
        $is_active = ($normalized_current === $active_normalized || $file === $active_file);
        $is_hidden = in_array($normalized_current, $hidden_normalized) || in_array($file, $hidden_files);

        if ($is_active || !$is_hidden) {
          $json_files[] = array(
            'label' => $file,
            'value' => $file
          );
        }
      }
    }

    return new WP_REST_Response($json_files, 200);
  }

  // Scanner methods
  public function start_scan($request)
  {
    $target_url = $request->get_param('target_url');
    if (!$target_url || !filter_var($target_url, FILTER_VALIDATE_URL)) {
      return new WP_REST_Response(['error' => 'Invalid target URL'], 400);
    }

    $scanner = new VAPT_Scanner();
    $scan_id = $scanner->start_scan($target_url);

    if ($scan_id === false) {
      return new WP_REST_Response(['error' => 'Failed to start scan'], 500);
    }

    return new WP_REST_Response(['scan_id' => $scan_id, 'status' => 'started'], 200);
  }

  public function get_scan_report($request)
  {
    $scan_id = $request->get_param('id');
    $scanner = new VAPT_Scanner();
    $report = $scanner->generate_report($scan_id);

    if (!$report) {
      return new WP_REST_Response(['error' => 'Scan not found'], 404);
    }

    return new WP_REST_Response($report, 200);
  }

  public function get_scans($request)
  {
    global $wpdb;
    $scans = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}vapt_scans ORDER BY created_at DESC", ARRAY_A);
    return new WP_REST_Response($scans, 200);
  }

  public function update_feature($request)
  {
    $key = $request->get_param('key');
    $status = $request->get_param('status');
    $include_test = $request->get_param('include_test_method');
    $include_verification = $request->get_param('include_verification');
    $is_enforced = $request->get_param('is_enforced');
    $wireframe_url = $request->get_param('wireframe_url');
    $generated_schema = $request->get_param('generated_schema');
    $implementation_data = $request->get_param('implementation_data');
    $reset_history = $request->get_param('reset_history');

    if ($status) {
      $note = $request->get_param('history_note') ?: ($request->get_param('transition_note') ?: '');
      $result = VAPT_Workflow::transition_feature($key, $status, $note);
      if (is_wp_error($result)) {
        return new WP_REST_Response($result, 400);
      }
    }

    $meta_updates = array();
    if ($include_test !== null) $meta_updates['include_test_method'] = $include_test ? 1 : 0;
    if ($include_verification !== null) $meta_updates['include_verification'] = $include_verification ? 1 : 0;

    $include_verification_engine = $request->get_param('include_verification_engine');
    if ($include_verification_engine !== null) $meta_updates['include_verification_engine'] = $include_verification_engine ? 1 : 0;

    $include_verification_guidance = $request->get_param('include_verification_guidance');
    if ($include_verification_guidance !== null) $meta_updates['include_verification_guidance'] = $include_verification_guidance ? 1 : 0;

    $include_manual_protocol = $request->get_param('include_manual_protocol');
    if ($include_manual_protocol !== null) $meta_updates['include_manual_protocol'] = $include_manual_protocol ? 1 : 0;

    $include_operational_notes = $request->get_param('include_operational_notes');
    if ($include_operational_notes !== null) $meta_updates['include_operational_notes'] = $include_operational_notes ? 1 : 0;

    if ($is_enforced !== null) $meta_updates['is_enforced'] = $is_enforced ? 1 : 0;
    if ($wireframe_url !== null) $meta_updates['wireframe_url'] = $wireframe_url;

    $dev_instruct = $request->get_param('dev_instruct');
    if ($dev_instruct !== null) $meta_updates['dev_instruct'] = $dev_instruct;

    if ($request->has_param('generated_schema')) {
      $generated_schema = $request->get_param('generated_schema');
      if ($generated_schema === null) {
        $meta_updates['generated_schema'] = null;
      } else {
        $schema = (is_array($generated_schema) || is_object($generated_schema))
          ? json_decode(json_encode($generated_schema), true)
          : json_decode($generated_schema, true);

        // 🛡️ LIFECYCLE ENFORCEMENT: Schema updates allowed only in Draft/Develop stages
        // Update: 'Test' stage allows updates but saves to OVERRIDE meta (Local customization)
        $current_feat = VAPT_DB::get_feature($key);
        $current_status = $current_feat ? strtolower($current_feat['status']) : 'draft';

        if (!in_array($current_status, ['draft', 'develop', 'test'])) {
          return new WP_REST_Response(array(
            'error' => 'Lifecycle Restriction',
            'message' => 'Design/Schema changes are strictly locked in Release stage. Current status: ' . ucfirst($current_status),
            'code' => 'lifecycle_locked'
          ), 403);
        }

        $is_legacy_format = isset($schema['type']) && in_array($schema['type'], ['wp_config', 'htaccess', 'manual', 'complex_input']);

        if (!$is_legacy_format) {
          $validation = self::validate_schema($schema);
          if (is_wp_error($validation)) {
            return new WP_REST_Response(array(
              'error' => 'Schema validation failed',
              'message' => $validation->get_error_message(),
              'code' => $validation->get_error_code(),
              'schema_received' => $schema
            ), 400);
          }

          // 🛡️ INTELLIGENT ENFORCEMENT (v3.3.9)
          $schema = self::analyze_enforcement_strategy($schema, $key);
        }

        if ($current_status === 'test') {
          $meta_updates['override_schema'] = json_encode($schema);
        } else {
          $meta_updates['generated_schema'] = json_encode($schema);
        }
      }
    }

    if ($request->has_param('implementation_data')) {
      $current_feat = $current_feat ?? VAPT_DB::get_feature($key);
      $current_status = $current_feat ? strtolower($current_feat['status']) : 'draft';

      $implementation_data = $request->get_param('implementation_data');
      $val = ($implementation_data === null) ? null : (is_array($implementation_data) ? json_encode($implementation_data) : $implementation_data);

      if ($current_status === 'test') {
        $meta_updates['override_implementation_data'] = $val;
      } else {
        $meta_updates['implementation_data'] = $val;
      }
    }

    if (! empty($meta_updates)) {
      VAPT_DB::update_feature_meta($key, $meta_updates);
      do_action('vapt_feature_saved', $key, $meta_updates);
    }

    if ($reset_history) {
      global $wpdb;
      $history_table = $wpdb->prefix . 'vapt_feature_history';
      $wpdb->delete($history_table, array('feature_key' => $key), array('%s'));
    }

    return new WP_REST_Response(array('success' => true), 200);
  }

  public function update_file_meta($request)
  {
    $file = $request->get_param('file');
    $key = $request->get_param('key');
    $value = $request->get_param('value');

    if (!$file || !$key) {
      return new WP_REST_Response(array('error' => 'Missing file or key param'), 400);
    }

    $json_path = VAPT_PATH . 'data/' . sanitize_file_name($file);

    if (!file_exists($json_path)) {
      return new WP_REST_Response(array('error' => 'File not found'), 404);
    }

    $content = file_get_contents($json_path);
    $data = json_decode($content, true);

    if (!is_array($data)) {
      return new WP_REST_Response(array('error' => 'Invalid JSON in file'), 500);
    }

    if ($value === null) {
      unset($data[$key]);
    } else {
      $data[$key] = $value;
    }

    $saved = file_put_contents($json_path, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

    if ($saved === false) {
      return new WP_REST_Response(array('error' => 'Failed to write to file'), 500);
    }

    return new WP_REST_Response(array('success' => true, 'updated_key' => $key), 200);
  }

  public function transition_feature($request)
  {
    $key = $request->get_param('key');
    $status = $request->get_param('status');
    $note = $request->get_param('note') ?: '';

    $result = VAPT_Workflow::transition_feature($key, $status, $note);

    if (is_wp_error($result)) {
      return new WP_REST_Response($result, 400);
    }

    return new WP_REST_Response(array('success' => true), 200);
  }

  public function get_feature_history($request)
  {
    $key = $request['key'];
    $history = VAPT_Workflow::get_history($key);

    return new WP_REST_Response($history, 200);
  }

  public function get_feature_stats($request)
  {
    $key = $request['key'];
    require_once(VAPT_PATH . 'includes/enforcers/class-vapt-hook-driver.php');
    if (method_exists('VAPT_Hook_Driver', 'get_feature_stats')) {
      $stats = VAPT_Hook_Driver::get_feature_stats($key);
      return new WP_REST_Response($stats, 200);
    }
    return new WP_REST_Response(['error' => 'Method not supported'], 500);
  }

  public function reset_feature_stats($request)
  {
    $key = $request['key'];
    require_once(VAPT_PATH . 'includes/enforcers/class-vapt-hook-driver.php');
    if (method_exists('VAPT_Hook_Driver', 'reset_feature_stats')) {
      $count = VAPT_Hook_Driver::reset_feature_stats($key);
      return new WP_REST_Response(['success' => true, 'deleted_locks' => $count], 200);
    }
    return new WP_REST_Response(['error' => 'Method not supported'], 500);
  }

  public function upload_json($request)
  {
    $files = $request->get_file_params();
    if (empty($files['file'])) {
      return new WP_REST_Response(array('error' => 'No file uploaded'), 400);
    }

    $file = $files['file'];
    $filename = sanitize_file_name($file['name']);
    $content = file_get_contents($file['tmp_name']);
    $data = json_decode($content, true);

    if (is_null($data)) {
      return new WP_REST_Response(array('error' => 'Invalid JSON'), 400);
    }

    $json_path = VAPT_PATH . 'data/' . $filename;
    file_put_contents($json_path, $content);

    // Auto-unhide if it was hidden
    $hidden_files = get_option('vapt_hidden_json_files', array());
    $normalized_hidden = array_map('sanitize_file_name', $hidden_files);

    if (in_array($filename, $normalized_hidden) || in_array($files['file']['name'], $hidden_files)) {
      $new_hidden = array_filter($hidden_files, function ($f) use ($filename, $files) {
        return sanitize_file_name($f) !== $filename && $f !== $files['file']['name'];
      });
      update_option('vapt_hidden_json_files', array_values($new_hidden));
    }

    return new WP_REST_Response(array('success' => true, 'filename' => $filename), 200);
  }

  public function update_hidden_files($request)
  {
    $hidden_files = $request->get_param('hidden_files');
    if (!is_array($hidden_files)) {
      $hidden_files = array();
    }

    $hidden_files = array_map('sanitize_file_name', $hidden_files);

    update_option('vapt_hidden_json_files', $hidden_files);

    return new WP_REST_Response(array('success' => true, 'hidden_files' => $hidden_files), 200);
  }

  public function reset_rate_limit($request)
  {
    require_once(VAPT_PATH . 'includes/enforcers/class-vapt-hook-driver.php');
    if (class_exists('VAPT_Hook_Driver')) {
      $result = VAPT_Hook_Driver::reset_limit();
      return new WP_REST_Response(array('success' => true, 'debug' => $result), 200);
    }
    return new WP_REST_Response(array('error' => 'Hook driver not found'), 500);
  }

  public function get_all_data_files()
  {
    $data_dir = VAPT_PATH . 'data';
    if (!is_dir($data_dir)) return new WP_REST_Response([], 200);

    $files = array_diff(scandir($data_dir), array('..', '.'));
    $json_files = [];
    $hidden_files = get_option('vapt_hidden_json_files', array());
    $hidden_normalized = array_map('sanitize_file_name', $hidden_files);

    foreach ($files as $file) {
      if (strtolower(pathinfo($file, PATHINFO_EXTENSION)) === 'json') {
        $normalized_current = sanitize_file_name($file);
        $json_files[] = array(
          'filename' => $file,
          'isHidden' => in_array($normalized_current, $hidden_normalized) || in_array($file, $hidden_files)
        );
      }
    }

    return new WP_REST_Response($json_files, 200);
  }

  public function get_domains()
  {
    global $wpdb;
    $domains = VAPT_DB::get_domains();

    foreach ($domains as &$domain) {
      $domain_id = $domain['id'];
      $feat_rows = $wpdb->get_results($wpdb->prepare("SELECT feature_key FROM {$wpdb->prefix}vapt_domain_features WHERE domain_id = %d AND enabled = 1", $domain_id), ARRAY_N);
      $domain['features'] = array_column($feat_rows, 0);
      $domain['imported_at'] = get_option('vapt_imported_at_' . $domain['domain'], null);
    }

    return new WP_REST_Response($domains, 200);
  }

  public function update_domain($request)
  {
    global $wpdb;
    $domain = $request->get_param('domain');
    $is_wildcard = $request->get_param('is_wildcard');
    $license_id = $request->get_param('license_id');
    $license_type = $request->get_param('license_type') ?: 'standard';
    $manual_expiry_date = $request->get_param('manual_expiry_date');
    $auto_renew = $request->get_param('auto_renew') !== null ? ($request->get_param('auto_renew') ? 1 : 0) : null;
    $action = $request->get_param('action');
    $license_scope = $request->get_param('license_scope');
    $installation_limit = $request->get_param('installation_limit');

    $id = $request->get_param('id');
    if ($id) {
      $current = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}vapt_domains WHERE id = %d", $id), ARRAY_A);
      if ($current && !$domain) $domain = $current['domain'];
    } else {
      $current = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}vapt_domains WHERE domain = %s", $domain), ARRAY_A);
    }

    $history = $current && !empty($current['renewal_history']) ? json_decode($current['renewal_history'], true) : array();

    $renewals_count = $request->has_param('renewals_count') ? (int) $request->get_param('renewals_count') : ($current ? (int)$current['renewals_count'] : 0);
    if ($auto_renew === null && $current) $auto_renew = (int)$current['auto_renew'];

    if ($request->has_param('is_wildcard')) {
      $val = $request->get_param('is_wildcard');
      $is_wildcard = (is_string($val)) ? ($val === 'true' || $val === '1') : (bool)$val;
    } else if ($current) {
      $is_wildcard = (int)$current['is_wildcard'];
    }

    if ($request->has_param('is_enabled')) {
      $val = $request->get_param('is_enabled');
      $is_enabled = (is_string($val)) ? ($val === 'true' || $val === '1') : (bool)$val;
    } else if ($current) {
      $is_enabled = (int)$current['is_enabled'];
    } else {
      $is_enabled = 1;
    }
    if ($license_id === null && $current) $license_id = $current['license_id'];
    if ($manual_expiry_date === null && $current) $manual_expiry_date = $current['manual_expiry_date'];
    if ($license_scope === null && $current) $license_scope = $current['license_scope'] ?: 'single';
    if ($installation_limit === null && $current) $installation_limit = $current['installation_limit'] ?: 1;

    if ($manual_expiry_date) {
      $manual_expiry_date = date('Y-m-d 00:00:00', strtotime($manual_expiry_date));
    }

    $today_ts = strtotime(date('Y-m-d 00:00:00'));
    $current_exp_ts = ($current && !empty($current['manual_expiry_date'])) ? strtotime(date('Y-m-d', strtotime($current['manual_expiry_date']))) : 0;
    $new_exp_ts = $manual_expiry_date ? strtotime(date('Y-m-d', strtotime($manual_expiry_date))) : 0;

    if ($action === 'undo' && !empty($history)) {
      $last = array_pop($history);
      $days = (int) $last['duration_days'];
      $manual_expiry_date = date('Y-m-d 00:00:00', strtotime($current['manual_expiry_date'] . " -$days days"));
      $renewals_count = max(0, (int)$current['renewals_count'] - 1);
    } else if ($action === 'reset' && !empty($history)) {
      $temp_expiry_ts = $current_exp_ts;
      $temp_count = $renewals_count;

      while (!empty($history)) {
        $entry = end($history);
        if ($entry['source'] === 'auto') break;

        $days = (int) $entry['duration_days'];
        $potential_expiry_ts = strtotime(date('Y-m-d 00:00:00', $temp_expiry_ts) . " -$days days");

        if ($potential_expiry_ts < $today_ts) break;

        array_pop($history);
        $temp_expiry_ts = $potential_expiry_ts;
        $temp_count = max(0, $temp_count - 1);
      }
      $manual_expiry_date = date('Y-m-d 00:00:00', $temp_expiry_ts);
      $renewals_count = $temp_count;
    } else {
      if ($current && $new_exp_ts > $current_exp_ts) {
        $diff = $new_exp_ts - $current_exp_ts;
        $days = round($diff / 86400);

        if ($days > 0) {
          $source = $request->get_param('renew_source') ?: 'manual';
          $history[] = array(
            'date_added' => current_time('mysql'),
            'duration_days' => $days,
            'license_type' => $license_type,
            'source' => $source
          );
          $renewals_count++;
        }
      }

      if ($auto_renew && $new_exp_ts < $today_ts) {
        $duration = '+30 days';
        $days = 30;
        if ($license_type === 'pro') {
          $duration = '+1 year';
          $days = 365;
        }
        if ($license_type === 'developer') {
          $duration = '+100 years';
          $days = 36500;
        }

        $manual_expiry_date = date('Y-m-d 00:00:00', strtotime($manual_expiry_date . ' ' . $duration));
        $renewals_count++;

        $history[] = array(
          'date_added' => current_time('mysql'),
          'duration_days' => $days,
          'license_type' => $license_type,
          'source' => 'auto'
        );
      }
    }

    $result_id = VAPT_DB::update_domain($domain, $is_wildcard ? 1 : 0, $is_enabled ? 1 : 0, $id, $license_id, $license_type, $manual_expiry_date, $auto_renew, $renewals_count, $history, $license_scope, $installation_limit);

    if ($result_id === false) {
      return new WP_REST_Response(array('error' => 'Database update failed'), 500);
    }

    $fresh = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}vapt_domains WHERE id = %d", $result_id), ARRAY_A);

    return new WP_REST_Response(array('success' => true, 'domain' => $fresh), 200);
  }

  public function delete_domain($request)
  {
    $domain_id = $request->get_param('id');
    if (!$domain_id) {
      return new WP_REST_Response(array('error' => 'Missing domain ID'), 400);
    }

    VAPT_DB::delete_domain($domain_id);
    return new WP_REST_Response(array('success' => true), 200);
  }

  public function batch_delete_domains($request)
  {
    $ids = $request->get_param('ids');
    if (!$ids || !is_array($ids)) {
      return new WP_REST_Response(array('error' => 'Missing or invalid domain IDs'), 400);
    }

    VAPT_DB::batch_delete_domains($ids);
    return new WP_REST_Response(array('success' => true), 200);
  }

  public function update_domain_features($request)
  {
    global $wpdb;
    $domain_id = $request->get_param('domain_id');
    $features = $request->get_param('features');

    if (! is_array($features)) {
      return new WP_REST_Response(array('error' => 'Invalid features format'), 400);
    }

    $table = $wpdb->prefix . 'vapt_domain_features';

    $wpdb->delete($table, array('domain_id' => $domain_id), array('%d'));

    foreach ($features as $key) {
      $wpdb->insert($table, array(
        'domain_id'   => $domain_id,
        'feature_key' => $key,
        'enabled'     => 1
      ), array('%d', '%s', '%d'));
    }

    return new WP_REST_Response(array('success' => true), 200);
  }

  public function generate_build($request)
  {
    $data = $request->get_json_params();
    if (!is_array($data)) {
      $data = [];
    }

    // Merge other parameters
    $data['include_config'] = $request->get_param('include_config');
    $data['include_data'] = $request->get_param('include_data');
    $data['license_scope'] = $request->get_param('license_scope');
    $data['installation_limit'] = $request->get_param('installation_limit');

    // Delegate to Build Class
    require_once VAPT_PATH . 'includes/class-vapt-build.php';
    try {
      $download_url = VAPT_Build::generate($data);
      return new WP_REST_Response(array('success' => true, 'download_url' => $download_url), 200);
    } catch (Exception $e) {
      return new WP_REST_Response(array('success' => false, 'message' => $e->getMessage()), 500);
    }
  }

  public function save_config_to_root($request)
  {
    $domain = $request->get_param('domain');
    $version = $request->get_param('version');
    $features = $request->get_param('features');
    $license_scope = $request->get_param('license_scope') ?: 'single';
    $installation_limit = $request->get_param('installation_limit') ?: 1;

    if (!$domain || !$version) {
      return new WP_REST_Response(array('error' => 'Missing domain or version'), 400);
    }

    require_once VAPT_PATH . 'includes/class-vapt-build.php';
    $config_content = VAPT_Build::generate_config_content($domain, $version, $features, null, $license_scope, $installation_limit);
    $filename = "vapt-{$domain}-config-{$version}.php";
    $filepath = VAPT_PATH . $filename;

    $saved = file_put_contents($filepath, $config_content);

    if ($saved !== false) {
      return new WP_REST_Response(array('success' => true, 'path' => $filepath, 'filename' => $filename), 200);
    } else {
      return new WP_REST_Response(array('error' => 'Failed to write config file to plugin root'), 500);
    }
  }

  public function sync_config_from_file($request)
  {
    $domain = $request->get_param('domain');
    if (!$domain) {
      return new WP_REST_Response(array('error' => 'Missing domain'), 400);
    }

    $files = glob(VAPT_PATH . "vapt-*-config-*.php");
    $matched_file = null;

    if ($files) {
      foreach ($files as $file) {
        if (strpos(basename($file), "vapt-{$domain}-config-") !== false) {
          $matched_file = $file;
          break;
        }
      }
    }

    if (!$matched_file && file_exists(VAPT_PATH . 'vapt-locked-config.php')) {
      $matched_file = VAPT_PATH . 'vapt-locked-config.php';
    }

    if (!$matched_file) {
      return new WP_REST_Response(array('error' => 'No config file found for domain: ' . $domain), 404);
    }

    $content = file_get_contents($matched_file);
    preg_match_all("/define\( 'VAPT_FEATURE_(.*?)', true \);/", $content, $matches);

    $features = array();
    if (!empty($matches[1])) {
      foreach ($matches[1] as $key_upper) {
        $features[] = strtolower($key_upper);
      }
    }

    $version = 'Unknown';
    if (preg_match("/Build Version: (.*?)[\r\n]/", $content, $v_match)) {
      $version = trim($v_match[1]);
    }

    update_option('vapt_imported_at_' . $domain, current_time('mysql'));
    update_option('vapt_imported_version_' . $domain, $version);

    return new WP_REST_Response(array(
      'success' => true,
      'imported_at' => current_time('mysql'),
      'version' => $version,
      'features_count' => count($features),
      'features' => $features
    ), 200);
  }

  public function get_assignees()
  {
    $users = get_users(array('role' => 'administrator'));
    $assignees = array_map(function ($u) {
      return array('id' => $u->ID, 'name' => $u->display_name);
    }, $users);

    return new WP_REST_Response($assignees, 200);
  }

  public function update_assignment($request)
  {
    global $wpdb;
    $key = $request->get_param('key');
    $user_id = $request->get_param('user_id');
    $table_status = $wpdb->prefix . 'vapt_feature_status';
    $wpdb->update($table_status, array('assigned_to' => $user_id ? $user_id : null), array('feature_key' => $key));

    return new WP_REST_Response(array('success' => true), 200);
  }

  public function upload_media($request)
  {
    if (empty($_FILES['file'])) {
      return new WP_Error('no_file', 'No file uploaded', array('status' => 400));
    }

    require_once(ABSPATH . 'wp-admin/includes/file.php');
    require_once(ABSPATH . 'wp-admin/includes/media.php');
    require_once(ABSPATH . 'wp-admin/includes/image.php');

    $upload_dir_filter = function ($uploads) {
      $subdir = '/vapt-wireframes';
      $uploads['subdir'] = $subdir;
      $uploads['path']   = $uploads['basedir'] . $subdir;
      $uploads['url']    = $uploads['baseurl'] . $subdir;

      if (! file_exists($uploads['path'])) {
        wp_mkdir_p($uploads['path']);
      }
      return $uploads;
    };

    add_filter('upload_dir', $upload_dir_filter);

    $file = $_FILES['file'];
    $upload_overrides = array('test_form' => false);

    $movefile = wp_handle_upload($file, $upload_overrides);

    remove_filter('upload_dir', $upload_dir_filter);

    if ($movefile && ! isset($movefile['error'])) {
      $filename = $movefile['file'];
      $attachment = array(
        'guid'           => $movefile['url'],
        'post_mime_type' => $movefile['type'],
        'post_title'     => preg_replace('/\.[^.]+$/', '', basename($filename)),
        'post_content'   => '',
        'post_status'    => 'inherit'
      );

      $attach_id = wp_insert_attachment($attachment, $filename);
      $attach_data = wp_generate_attachment_metadata($attach_id, $filename);
      wp_update_attachment_metadata($attach_id, $attach_data);

      return new WP_REST_Response(array(
        'success' => true,
        'url'     => $movefile['url'],
        'id'      => $attach_id
      ), 200);
    } else {
      return new WP_Error('upload_error', $movefile['error'], array('status' => 500));
    }
  }

  /**
   * 🛡️ INTELLIGENT ENFORCEMENT STRATEGY (v3.3.9)
   * Analyzes the schema and automatically corrects driver selection 
   * if it detects physical file targets being handled by PHP hooks.
   */
  private static function analyze_enforcement_strategy($schema, $feature_key)
  {
    if (!isset($schema['enforcement'])) return $schema;

    $driver = $schema['enforcement']['driver'] ?? 'hook';
    $mappings = $schema['enforcement']['mappings'] ?? array();

    $physical_file_patterns = [
      'readme.html',
      'license.txt',
      'xmlrpc.php',
      'wp-config.php',
      '.env',
      'wp-links-opml.php',
      'debug.log',
      '.htaccess'
    ];

    $block_indicators = ['<Files', 'Require all', 'Deny from', 'Order allow,deny', 'Options -Indexes'];

    $needs_htaccess = false;
    foreach ($mappings as $key => $value) {
      if (!is_string($value)) continue;

      // Check for physical file mentions or Apache directives in mappings
      foreach ($physical_file_patterns as $file) {
        if (stripos($value, $file) !== false) {
          $needs_htaccess = true;
          break 2;
        }
      }

      foreach ($block_indicators as $indicator) {
        if (stripos($value, $indicator) !== false) {
          $needs_htaccess = true;
          break 2;
        }
      }
    }

    // Auto-Correct if driver is 'hook' but needs 'htaccess'
    if ($needs_htaccess && $driver === 'hook') {
      error_log("VAPT Intelligence: Auto-switching driver to 'htaccess' for feature $feature_key based on physical file target.");
      $schema['enforcement']['driver'] = 'htaccess';
      $schema['enforcement']['target'] = $schema['enforcement']['target'] ?? 'root';
    }

    // Auto-Correct Mapping Key Mismatch (feat_key vs feat_enabled)
    if (isset($mappings['feat_key']) && isset($schema['controls'])) {
      $has_feat_key = false;
      $primary_toggle = null;

      foreach ($schema['controls'] as $ctrl) {
        if (isset($ctrl['key']) && $ctrl['key'] === 'feat_key') $has_feat_key = true;
        if (isset($ctrl['type']) && $ctrl['type'] === 'toggle' && isset($ctrl['key'])) {
          $primary_toggle = $ctrl['key'];
        }
      }

      if (!$has_feat_key && $primary_toggle) {
        error_log("VAPT Intelligence: Auto-correcting mapping key 'feat_key' to '$primary_toggle' for feature $feature_key.");
        $schema['enforcement']['mappings'][$primary_toggle] = $mappings['feat_key'];
        unset($schema['enforcement']['mappings']['feat_key']);
      }
    }

    return $schema;
  }

  private static function validate_schema($schema)
  {
    if (!is_array($schema)) {
      return new WP_Error('invalid_schema', 'Schema must be an object/array', array('status' => 400));
    }

    if (!isset($schema['controls']) || !is_array($schema['controls'])) {
      return new WP_Error(
        'invalid_schema',
        'Schema must have a "controls" array',
        array('status' => 400)
      );
    }

    foreach ($schema['controls'] as $index => $control) {
      if (!is_array($control)) {
        return new WP_Error(
          'invalid_schema',
          sprintf('Control at index %d must be an object', $index),
          array('status' => 400)
        );
      }

      if (empty($control['type'])) {
        return new WP_Error(
          'invalid_schema',
          sprintf('Control at index %d must have a "type" field', $index),
          array('status' => 400)
        );
      }

      $no_key_types = ['button', 'info', 'alert', 'section', 'group', 'divider', 'html', 'header', 'label', 'evidence_uploader', 'risk_indicators', 'assurance_badges', 'remediation_steps', 'test_checklist', 'evidence_list'];
      if (empty($control['key']) && !in_array($control['type'], $no_key_types)) {
        return new WP_Error(
          'invalid_schema',
          sprintf('Control at index %d must have a "key" field', $index),
          array('status' => 400)
        );
      }

      $valid_types = ['toggle', 'input', 'select', 'textarea', 'code', 'test_action', 'button', 'info', 'alert', 'section', 'group', 'divider', 'html', 'header', 'label', 'password', 'evidence_uploader', 'risk_indicators', 'assurance_badges', 'remediation_steps', 'test_checklist', 'evidence_list'];
      if (!in_array($control['type'], $valid_types)) {
        return new WP_Error(
          'invalid_schema',
          sprintf(
            'Control at index %d has invalid type "%s". Valid types: %s',
            $index,
            $control['type'],
            implode(', ', $valid_types)
          ),
          array('status' => 400)
        );
      }

      if ($control['type'] === 'test_action') {
        if (empty($control['test_logic'])) {
          return new WP_Error(
            'invalid_schema',
            sprintf(
              'Test action control "%s" must have a "test_logic" field',
              $control['key'] ?? $index
            ),
            array('status' => 400)
          );
        }
      }
    }

    if (isset($schema['enforcement'])) {
      if (!is_array($schema['enforcement'])) {
        return new WP_Error(
          'invalid_schema',
          'Enforcement section must be an object',
          array('status' => 400)
        );
      }

      if (empty($schema['enforcement']['driver'])) {
        return new WP_Error(
          'invalid_schema',
          'Enforcement must specify a "driver" (hook or htaccess)',
          array('status' => 400)
        );
      }

      $valid_drivers = ['hook', 'htaccess', 'universal'];
      if (!in_array($schema['enforcement']['driver'], $valid_drivers)) {
        return new WP_Error(
          'invalid_schema',
          sprintf(
            'Invalid enforcement driver "%s". Valid drivers: %s',
            $schema['enforcement']['driver'],
            implode(', ', $valid_drivers)
          ),
          array('status' => 400)
        );
      }

      if ($schema['enforcement']['driver'] === 'htaccess' && empty($schema['enforcement']['target'])) {
        return new WP_Error(
          'invalid_schema',
          'Htaccess driver must specify a "target" (root or uploads)',
          array('status' => 400)
        );
      }

      if (isset($schema['enforcement']['mappings']) && !is_array($schema['enforcement']['mappings'])) {
        return new WP_Error(
          'invalid_schema',
          'Enforcement mappings must be an object/array',
          array('status' => 400)
        );
      }
    }

    return true;
  }

  public function handle_active_file($request)
  {
    if ($request->get_method() === 'POST') {
      $file = $request->get_param('file');
      if (!$file) {
        return new WP_REST_Response(array('error' => 'No file specified'), 400);
      }
      $filename = sanitize_file_name($file);
      update_option('vapt_active_feature_file', $filename);
      return new WP_REST_Response(array('success' => true, 'active_file' => $filename), 200);
    }

    return new WP_REST_Response(array(
      'active_file' => defined('VAPT_ACTIVE_DATA_FILE') ? VAPT_ACTIVE_DATA_FILE : 'VAPT-Complete-Risk-Catalog-99.json'
    ), 200);
  }
}

new VAPT_REST();
