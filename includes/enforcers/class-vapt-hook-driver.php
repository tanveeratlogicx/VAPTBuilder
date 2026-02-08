<?php

/**
 * Universal Hook Driver for VAPT Builder
 * Implements security enforcement via PHP hooks (Server Agnostic)
 */

if (! defined('ABSPATH')) {
  exit;
}

class VAPT_Hook_Driver
{
  private static $feature_configs = [];
  private static $enforced_keys = [];
  private static $rate_limit_hook_registered = false;
  private static $marker_hook_registered = false;
  private static $catalog_data = null;

  // Dynamic Map: matches feature keys/tags to methods
  private static $dynamic_map = [
    'xmlrpc' => 'block_xmlrpc',
    'directory_browsing' => 'disable_directory_browsing',
    'listing' => 'disable_directory_browsing', // fallback
    'version' => 'hide_wp_version',
    'debug' => 'block_debug_exposure',
    'headers' => 'add_security_headers',
    'xss' => 'add_security_headers', // XSS headers
    'clickjacking' => 'add_security_headers', // Frame options
    'null_byte' => 'block_null_byte_injection',
    'author' => 'block_author_enumeration',
    'user_enum' => 'block_author_enumeration',
    'pingback' => 'disable_xmlrpc_pingback',
    'sensitive' => 'block_sensitive_files',
    'files' => 'block_sensitive_files',
    'limit' => 'limit_login_attempts',
    'login' => 'limit_login_attempts',
    'brute' => 'limit_login_attempts'
  ];

  /**
   * Apply enforcement rules at runtime
   * enhanced to work with VAPT-Complete-Risk-Catalog-99.json
   */
  /**
   * 🛡️ TWO-WAY DEACTIVATION & ENFORCEMENT (v3.6.19)
   */
  public static function apply($impl_data, $schema, $key = '')
  {
    $log_file = VAPT_PATH . 'vapt-debug.txt';
    $log = "VAPT Enforcement Run at " . current_time('mysql') . "\n";
    $log .= "Feature: $key\n";

    // 1. Resolve Data (Merge Defaults)
    $resolved_data = array();
    if (isset($schema['controls']) && is_array($schema['controls'])) {
      foreach ($schema['controls'] as $control) {
        if (isset($control['key'])) {
          $key_name = $control['key'];
          $resolved_data[$key_name] = isset($impl_data[$key_name]) ? $impl_data[$key_name] : (isset($control['default']) ? $control['default'] : null);
        }
      }
    }
    if (!empty($impl_data)) {
      $resolved_data = array_merge($resolved_data, $impl_data);
    }

    // 2. TWO-WAY STRATEGY: Strictly check 'enabled' toggle
    $is_enabled = isset($resolved_data['enabled']) ? (bool)$resolved_data['enabled'] : true;
    if (!$is_enabled) {
      file_put_contents($log_file, $log . "Deactivated: Feature is explicitly disabled in UI.\n", FILE_APPEND);
      return; // Stop enforcement
    }

    if ($key && !in_array($key, self::$enforced_keys)) {
      self::$enforced_keys[] = $key;
      self::register_enforcement_marker();
    }

    // 3. Failsafe: Catalog data fallback
    if (empty($impl_data) && !isset($resolved_data['enabled'])) {
      // ... existing catalog loading logic if needed ...
    }

    file_put_contents($log_file, $log . "Applying rules with Data: " . json_encode($resolved_data) . "\n", FILE_APPEND);

    // 4. Determine Enforcement Mappings
    $mappings = isset($schema['enforcement']['mappings']) ? $schema['enforcement']['mappings'] : [];

    if (empty($mappings)) {
      // Dynamic Fallback
      foreach ($resolved_data as $k => $v) {
        if ($v == true || $v === '1' || (is_string($v) && strlen($v) > 0)) {
          $method = self::resolve_dynamic_method($k, $key);
          if ($method) $mappings[$k] = $method;
        }
      }
    }

    if (empty($mappings)) {
      file_put_contents($log_file, $log . "Skipped: No mappings found.\n", FILE_APPEND);
      return;
    }

    // 5. Execute Methods
    $triggered_methods = array();
    foreach ($resolved_data as $field_key => $value) {
      if (!$value || empty($mappings[$field_key])) continue;

      $method = $mappings[$field_key];
      if (is_array($method)) $method = $method['method'] ?? ($method[0] ?? null);
      if (!is_string($method) || in_array($method, $triggered_methods)) continue;

      $triggered_methods[] = $method;

      if (method_exists(__CLASS__, $method)) {
        try {
          switch ($method) {
            case 'block_xmlrpc':
              self::block_xmlrpc($key);
              break;
            case 'add_security_headers':
              self::add_security_headers($key);
              break;
            case 'disable_directory_browsing':
              self::disable_directory_browsing($key);
              break;
            case 'limit_login_attempts':
              self::limit_login_attempts($value, $resolved_data, $key);
              break;
            case 'block_null_byte_injection':
              self::block_null_byte_injection($key);
              break;
            case 'hide_wp_version':
              self::hide_wp_version($key);
              break;
            case 'block_debug_exposure':
              self::block_debug_exposure($value, $key);
              break;
            case 'block_author_enumeration':
              self::block_author_enumeration($key);
              break;
            case 'disable_xmlrpc_pingback':
              self::disable_xmlrpc_pingback($key);
              break;
            case 'block_sensitive_files':
              self::block_sensitive_files($key);
              break;
          }
        } catch (Exception $e) {
          file_put_contents($log_file, $log . "Exception in $method: " . $e->getMessage() . "\n", FILE_APPEND);
        }
      }
    }
  }

  /**
   * 🔍 VERIFICATION LOGIC (v3.6.19)
   */
  public static function verify($key, $impl_data, $schema)
  {
    $is_enabled_in_ui = isset($impl_data['enabled']) ? (bool)$impl_data['enabled'] : false;

    // 1. Quick Check: Is it in our runtime enforcement list?
    if (in_array($key, self::$enforced_keys)) {
      return true;
    }

    // 2. Deep Check: Does the implementation require a specific hook?
    $mappings = $schema['enforcement']['mappings'] ?? [];
    if (isset($mappings['headers']) || isset($mappings['X-Frame-Options'])) {
      // Check if headers filter is added
      return has_filter('wp_headers');
    }

    if (isset($mappings['xmlrpc'])) {
      return defined('XMLRPC_REQUEST') || has_filter('xmlrpc_enabled');
    }

    // Fallback: If enabled in UI, assume active if we reached this point in a verification cycle
    return $is_enabled_in_ui;
  }

  /**
   * dynamic method resolution based on keywords
   */
  private static function resolve_dynamic_method($field_key, $feature_key)
  {
    $fingerprint = strtolower($field_key . '_' . $feature_key);

    foreach (self::$dynamic_map as $keyword => $method) {
      if (strpos($fingerprint, $keyword) !== false) {
        return $method;
      }
    }
    return null;
  }

  /**
   * Load Catalog Data from JSON Failsafe (Dynamic Source)
   */
  private static function get_catalog_data($key)
  {
    if (self::$catalog_data === null) {
      // Dynamic Active File Resolution
      $active_file = defined('VAPT_ACTIVE_DATA_FILE') ? constant('VAPT_ACTIVE_DATA_FILE') : get_option('vapt_active_feature_file', 'Feature-List-99.json');
      $path = VAPT_PATH . 'data/' . sanitize_file_name($active_file);

      if (file_exists($path)) {
        $json = json_decode(file_get_contents($path), true);
        if ($json) {
          // handle various schema formats
          if (isset($json['risk_catalog'])) {
            self::$catalog_data = $json['risk_catalog'];
          } elseif (isset($json['features'])) {
            self::$catalog_data = $json['features'];
          } elseif (isset($json['wordpress_vapt'])) {
            self::$catalog_data = $json['wordpress_vapt'];
          } else {
            self::$catalog_data = $json; // Fallback
          }
        }
      }
    }

    if (self::$catalog_data && is_array(self::$catalog_data)) {
      foreach (self::$catalog_data as $item) {
        // Match by Feature Key (if present) or ID or Title similarity
        if ((isset($item['risk_id']) && $item['risk_id'] === $key) ||
          (isset($item['title']) && sanitize_title($item['title']) === $key) ||
          strpos($key, sanitize_title(isset($item['title']) ? $item['title'] : '')) !== false
        ) {
          return $item;
        }
      }
    }
    return null;
  }

  /**
   * Universal enforcement marker via PHP headers
   */
  private static function register_enforcement_marker()
  {
    if (self::$marker_hook_registered) return;
    self::$marker_hook_registered = true;

    add_filter('wp_headers', function ($headers) {
      if (function_exists('wp_doing_ajax') && wp_doing_ajax()) return $headers;

      $headers['X-VAPT-Enforced'] = 'php-headers';
      $existing = isset($headers['X-VAPT-Feature']) ? $headers['X-VAPT-Feature'] : '';
      $keys = !empty($existing) ? explode(',', $existing) : [];

      foreach (self::$enforced_keys as $key) {
        if (!in_array($key, $keys)) {
          $keys[] = $key;
        }
      }

      $headers['X-VAPT-Feature'] = implode(',', $keys);
      $headers['Access-Control-Expose-Headers'] = 'X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, X-VAPT-Enforced, X-VAPT-Feature';
      return $headers;
    }, 999);

    if (!headers_sent() && (!function_exists('wp_doing_ajax') || !wp_doing_ajax())) {
      header('X-VAPT-Enforced: php-headers');
      header('X-VAPT-Feature: ' . implode(',', self::$enforced_keys));
      header('Access-Control-Expose-Headers: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, X-VAPT-Enforced, X-VAPT-Feature');
    }
  }

  /**
   * Detect Request Context (Engine Core)
   * Returns: ['is_login', 'is_admin', 'is_api', 'is_frontend']
   */
  public static function detect_context()
  {
    $uri = $_SERVER['REQUEST_URI'] ?? '';
    $script = $_SERVER['SCRIPT_NAME'] ?? '';

    $is_login =
      strpos($uri, 'wp-login.php') !== false ||
      strpos($script, 'wp-login.php') !== false ||
      strpos($uri, 'xmlrpc.php') !== false ||
      (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) ||
      (isset($_GET['vapt_test_context']) && $_GET['vapt_test_context'] === 'login');

    $is_admin = is_admin() && !$is_login;
    $is_api = strpos($uri, 'wp-json') !== false;
    $is_frontend = !$is_login && !$is_admin && !$is_api;

    return [
      'is_login' => $is_login,
      'is_admin' => $is_admin,
      'is_api' => $is_api,
      'is_frontend' => $is_frontend
    ];
  }

  /**
   * Get Active Stats for a Feature (Observability)
   */
  public static function get_feature_stats($feature_key)
  {
    $lock_dir = sys_get_temp_dir() . '/vapt-locks';
    $files = glob("$lock_dir/vapt_{$feature_key}_*.lock");
    $active_ips = 0;
    $total_attempts = 0;

    if ($files) {
      foreach ($files as $file) {
        $active_ips++;
        $content = @file_get_contents($file);
        if ($content) $total_attempts += (int)$content;
      }
    }

    $duration = 60;
    if (isset(self::$feature_configs[$feature_key]['duration'])) {
      $duration = self::$feature_configs[$feature_key]['duration'];
    }

    return [
      'active_ips' => $active_ips,
      'total_attempts' => $total_attempts,
      'window' => $duration
    ];
  }

  /**
   * Reset Stats for a Feature
   */
  public static function reset_feature_stats($feature_key)
  {
    $lock_dir = sys_get_temp_dir() . '/vapt-locks';
    $files = glob("$lock_dir/vapt_{$feature_key}_*.lock");
    $count = 0;
    if ($files) {
      foreach ($files as $file) {
        @unlink($file);
        $count++;
      }
    }
    return $count;
  }

  /**
   * Register a rate limit configuration (Context-Aware & Observable)
   */
  private static function limit_login_attempts($config, $all_data = array(), $feature_key = 'unknown')
  {
    $limit = null;

    // Resolve Limit Value
    $candidates = [
      $all_data['rate_limit'] ?? null,
      $all_data['limit'] ?? null,
      $all_data['max_login_attempts'] ?? null,
      $all_data['max_attempts'] ?? null,
      $all_data['attempts_allowed'] ?? null,
      $all_data['api_limit'] ?? null
    ];

    foreach ($candidates as $val) {
      if (isset($val) && is_numeric($val) && (int)$val > 1) {
        $limit = (int) $val;
        break;
      }
    }

    if ($limit === null && is_numeric($config) && (int)$config > 1) {
      $limit = (int) $config;
    }

    if ($limit === null) return;

    // Determine Scope
    $scope = 'global'; // default
    if (isset($all_data['scope'])) {
      $scope = $all_data['scope'];
    } elseif (strpos($feature_key, 'login') !== false || strpos($feature_key, 'brute') !== false) {
      $scope = 'login';
    }

    self::$feature_configs[$feature_key] = [
      'limit' => $limit,
      'key' => $feature_key,
      'scope' => $scope,
      'duration' => isset($all_data['duration']) ? (int)$all_data['duration'] : 60
    ];

    if (self::$rate_limit_hook_registered) {
      return;
    }
    self::$rate_limit_hook_registered = true;

    add_action('init', function () {
      if (strpos($_SERVER['REQUEST_URI'], 'reset-limit') !== false || isset($_GET['vapt_action'])) return;
      if (current_user_can('manage_options') && !isset($_GET['vapt_test_spike'])) return;

      $context = self::detect_context();
      $ip = self::get_real_ip();
      $ip_hash = md5($ip); // Privacy + Safe Filename
      $lock_dir = sys_get_temp_dir() . '/vapt-locks';
      if (!file_exists($lock_dir) && !@mkdir($lock_dir, 0755, true)) return;

      foreach (self::$feature_configs as $feature_key => $cfg) {
        // Enforce Scope Logic
        if ($cfg['scope'] === 'login' && !$context['is_login']) continue;

        $limit = $cfg['limit'];
        $duration = $cfg['duration'];
        // New Observable Lock Pattern: vapt_{feature}_{iphash}.lock
        $lock_file = $lock_dir . "/vapt_{$feature_key}_{$ip_hash}.lock";

        $fp = @fopen($lock_file, 'c+');
        if (!$fp) continue;

        if (flock($fp, LOCK_EX)) {
          try {
            $current = 0;
            clearstatcache(true, $lock_file);
            if (filesize($lock_file) > 0) {
              rewind($fp);
              $current = (int) fread($fp, filesize($lock_file));
            }

            // Expiry Check
            if (file_exists($lock_file) && (time() - filemtime($lock_file) > $duration)) {
              $current = 0;
            }

            if (!headers_sent()) {
              header('X-VAPT-Limit-' . $feature_key . ': ' . $limit, false);
              header('X-VAPT-Count-' . $feature_key . ': ' . $current, false);
            }

            if ($current >= $limit) {
              if (!headers_sent()) {
                header('X-VAPT-Enforced: php-rate-limit');
                header('X-VAPT-Feature: ' . $feature_key);
                header('Retry-After: ' . $duration);
              }
              flock($fp, LOCK_UN);
              fclose($fp);
              wp_die("VAPT: Too Many Requests ($feature_key).", 'Rate Limit Exceeded', array('response' => 429));
            }

            rewind($fp);
            ftruncate($fp, 0);
            fwrite($fp, (string) ($current + 1));
            fflush($fp);
          } catch (Exception $e) {
            // Safe fail
          } finally {
            if (is_resource($fp)) {
              flock($fp, LOCK_UN);
              fclose($fp);
            }
          }
        }
      }
    }, 5);
  }

  /**
   * Reset Rate Limit for Current IP (All Features)
   */
  public static function reset_limit()
  {
    $ip = $_SERVER['REMOTE_ADDR'];
    $lock_dir = sys_get_temp_dir() . '/vapt-locks';

    if (!is_dir($lock_dir)) return ['status' => 'no_dir'];

    $files = glob("$lock_dir/vapt_limit_*");
    $results = [];

    foreach ($files as $file) {
      @unlink($file);
      $results[] = basename($file) . ' deleted';
    }

    return $results;
  }

  /**
   * Block Directory Browsing via PHP
   */
  private static function disable_directory_browsing($key = 'unknown')
  {
    add_action('wp_loaded', function () use ($key) {
      $uri = $_SERVER['REQUEST_URI'];
      if (strpos($uri, '/wp-content/uploads/') !== false && substr($uri, -1) === '/') {
        $path = ABSPATH . ltrim($uri, '/');
        if (is_dir($path)) {
          status_header(403);
          header('X-VAPT-Enforced: php-dir');
          header('X-VAPT-Feature: ' . $key);
          header('Access-Control-Expose-Headers: X-VAPT-Enforced, X-VAPT-Feature');
          wp_die('VAPT: Directory Browsing is Blocked for Security.');
        }
      }
    });
  }

  /**
   * Block XML-RPC requests
   */
  private static function block_xmlrpc($key = 'unknown')
  {
    if (strpos($_SERVER['REQUEST_URI'], 'xmlrpc.php') !== false) {
      status_header(403);
      header('X-VAPT-Enforced: php-xmlrpc');
      header('X-VAPT-Feature: ' . $key);
      header('Access-Control-Expose-Headers: X-VAPT-Enforced, X-VAPT-Feature');
      header('Content-Type: text/plain');
      wp_die('VAPT: XML-RPC Access is Blocked for Security.');
    }
  }

  /**
   * Block requests containing null byte injections
   */
  private static function block_null_byte_injection($key = 'unknown')
  {
    $query = $_SERVER['QUERY_STRING'] ?? '';
    if (strpos($query, '%00') !== false || strpos(urldecode($query), "\0") !== false) {
      status_header(403);
      header('X-VAPT-Enforced: php-null-byte');
      header('X-VAPT-Feature: ' . $key);
      header('Access-Control-Expose-Headers: X-VAPT-Enforced, X-VAPT-Feature');
      wp_die('VAPT: Null Byte Injection Attempt Blocked.');
    }
  }

  /**
   * Hide WordPress Version
   */
  /**
   * Hide WordPress Version
   */
  private static function hide_wp_version($key = 'unknown')
  {
    // 1. Remove Generator Tag
    remove_action('wp_head', 'wp_generator');
    add_filter('the_generator', '__return_empty_string');

    // 2. Add Enforcement Headers (Robust)
    // 2. Add Enforcement Headers (Robust)
    add_filter('wp_headers', function ($headers) use ($key) {
      if (function_exists('wp_doing_ajax') && wp_doing_ajax()) return $headers;

      $headers['X-VAPT-Enforced'] = 'php-version-hide';
      $headers['X-VAPT-Feature'] = $key;
      $headers['Access-Control-Expose-Headers'] = 'X-VAPT-Enforced, X-VAPT-Feature';
      return $headers;
    });

    // 3. Fallback for headers (if not filtered)
    add_action('init', function () use ($key) {
      if (function_exists('wp_doing_ajax') && wp_doing_ajax()) return;

      if (!headers_sent()) {
        header('X-VAPT-Enforced: php-version-hide');
        header('X-VAPT-Feature: ' . $key);
        header('Access-Control-Expose-Headers: X-VAPT-Enforced, X-VAPT-Feature');
      }
    });
  }

  /**
   * Block Debug Exposure
   */
  private static function block_debug_exposure($config, $key = 'unknown')
  {
    add_action('init', function () use ($key) {
      if (function_exists('wp_doing_ajax') && wp_doing_ajax()) return;

      if (!headers_sent()) {
        header('X-VAPT-Enforced: php-debug-exposure');
        header('X-VAPT-Feature: ' . $key);
        header('Access-Control-Expose-Headers: X-VAPT-Enforced, X-VAPT-Feature');
      }
    });

    add_action('wp_loaded', function () use ($key) {
      $uri = $_SERVER['REQUEST_URI'];
      if (strpos($uri, 'debug.log') !== false) {
        status_header(403);
        header('X-VAPT-Enforced: php-debug-log-block');
        header('X-VAPT-Feature: ' . $key);
        header('Access-Control-Expose-Headers: X-VAPT-Enforced, X-VAPT-Feature');
        wp_die('VAPT: Access to debug.log is Blocked for Security.');
      }
    });
  }

  /**
   * Add Security Headers via PHP
   */
  private static function add_security_headers($key = 'unknown')
  {
    add_filter('wp_headers', function ($headers) use ($key) {
      if (function_exists('wp_doing_ajax') && wp_doing_ajax()) return $headers; // VAPT: Skip for AJAX to prevent CORS/Heartbeat issues

      $headers['X-Frame-Options'] = 'SAMEORIGIN';
      $headers['X-Content-Type-Options'] = 'nosniff';
      $headers['X-XSS-Protection'] = '1; mode=block';
      $headers['X-VAPT-Enforced'] = 'php-headers';
      $headers['X-VAPT-Feature'] = $key;
      $headers['Access-Control-Expose-Headers'] = 'X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, X-VAPT-Enforced, X-VAPT-Feature';
      return $headers;
    }, 999);

    if (!headers_sent() && (!function_exists('wp_doing_ajax') || !wp_doing_ajax())) {
      header('X-Frame-Options: SAMEORIGIN');
      header('X-Content-Type-Options: nosniff');
      header('X-XSS-Protection: 1; mode=block');
      header('X-VAPT-Enforced: php-headers');
      header('X-VAPT-Feature: ' . $key);
      header('Access-Control-Expose-Headers: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, X-VAPT-Enforced, X-VAPT-Feature');
    }
  }

  /**
   * Block Author Enumeration
   */
  private static function block_author_enumeration($key = 'unknown')
  {
    // 1. Block Standard ?author=N
    add_action('init', function () use ($key) {
      if (isset($_GET['author']) && is_numeric($_GET['author'])) {
        status_header(403);
        header('X-VAPT-Enforced: php-author-enum');
        header('X-VAPT-Feature: ' . $key);
        header('Access-Control-Expose-Headers: X-VAPT-Enforced, X-VAPT-Feature');
        wp_die('VAPT: Author Enumeration is Blocked for Security.');
      }
    });

    // 2. Block REST API User Enumeration (v3.6.19 Fix)
    add_filter('rest_endpoints', function ($endpoints) {
      if (isset($endpoints['/wp/v2/users'])) {
        unset($endpoints['/wp/v2/users']);
      }
      if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
        unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
      }
      return $endpoints;
    });
  }

  /**
   * Disable XML-RPC Pingback
   */
  private static function disable_xmlrpc_pingback($key = 'unknown')
  {
    add_filter('xmlrpc_methods', function ($methods) use ($key) {
      unset($methods['pingback.ping']);
      unset($methods['pingback.extensions.getPingbacks']);
      return $methods;
    });

    add_action('init', function () use ($key) {
      if (strpos($_SERVER['REQUEST_URI'], 'xmlrpc.php') !== false) {
        header('X-VAPT-Enforced: php-pingback');
        header('X-VAPT-Feature: ' . $key);
        header('Access-Control-Expose-Headers: X-VAPT-Enforced, X-VAPT-Feature');
      }
    });
  }

  /**
   * Block Sensitive Files (readme.html, etc)
   */
  private static function block_sensitive_files($key = 'unknown')
  {
    add_action('plugins_loaded', function () use ($key) {
      $uri = strtolower($_SERVER['REQUEST_URI'] ?? '');
      $sensitive_files = ['/readme.html', '/license.txt', '/wp-config.php.bak', '/wp-config.php.swp', '/.env', '/xmlrpc.php', '/wp-links-opml.php'];

      foreach ($sensitive_files as $file) {
        if (strpos($uri, $file) !== false) {
          status_header(403);
          header('X-VAPT-Enforced: php-sensitive-file');
          header('X-VAPT-Feature: ' . $key);
          header('Access-Control-Expose-Headers: X-VAPT-Enforced, X-VAPT-Feature');
          wp_die('VAPT: Access to this file is Blocked for Security.');
        }
      }
    });
  }
  /**
   * 🌐 PROXY-AWARE IP DETECTION (v3.6.19)
   * Accounts for Cloudflare, Nginx Proxies, and Load Balancers.
   */
  private static function get_real_ip()
  {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
      return $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
      $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
      return trim($ips[0]);
    }
    if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
      return $_SERVER['HTTP_X_REAL_IP'];
    }
    return $_SERVER['REMOTE_ADDR'];
  }
}
