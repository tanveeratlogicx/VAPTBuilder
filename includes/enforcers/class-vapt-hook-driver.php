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
  private static $rate_limit_hook_registered = false;

  /**
   * Apply enforcement rules at runtime
   */
  public static function apply($impl_data, $schema, $key = '')
  {
    $log_file = VAPT_PATH . 'vapt-debug.txt';
    $log = "VAPT Enforcement Run at " . current_time('mysql') . "\n";
    $log .= "Feature: $key\n";

    if (empty($schema['enforcement']['mappings'])) {
      file_put_contents($log_file, $log . "Skipped: Missing mappings.\n", FILE_APPEND);
      return;
    }
    $mappings = $schema['enforcement']['mappings'];

    $resolved_data = array();
    if (isset($schema['controls']) && is_array($schema['controls'])) {
      foreach ($schema['controls'] as $control) {
        if (isset($control['key'])) {
          $key_name = $control['key'];
          $resolved_data[$key_name] = isset($impl_data[$key_name]) ? $impl_data[$key_name] : (isset($control['default']) ? $control['default'] : null);
        }
      }
    }
    $resolved_data = array_merge($resolved_data, $impl_data);

    file_put_contents($log_file, $log . "Applying rules with Data: " . json_encode($resolved_data) . "\n", FILE_APPEND);

    $triggered_methods = array();
    foreach ($resolved_data as $field_key => $value) {
      if (!$value || empty($mappings[$field_key])) continue;

      $method = $mappings[$field_key];
      if (in_array($method, $triggered_methods)) continue;
      $triggered_methods[] = $method;

      switch ($method) {
        case 'block_xmlrpc':
          self::block_xmlrpc($key);
          break;
        case 'enable_security_headers':
          self::add_security_headers($key);
          break;
        case 'disable_directory_browsing':
          self::disable_directory_browsing($key);
          break;
        case 'limit_login_attempts':
          if ($key === 'xml-rpc-api-security') break;
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
      }
    }
  }

  /**
   * Register a rate limit configuration for a specific feature
   */
  private static function limit_login_attempts($config, $all_data = array(), $feature_key = 'unknown')
  {
    $limit = null;

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

    if ($limit === null) {
      foreach ($all_data as $k => $v) {
        if (is_numeric($v) && (int)$v > 1) {
          $limit = (int)$v;
          break;
        }
      }
    }

    if ($limit === null) {
      file_put_contents(VAPT_PATH . 'vapt-debug.txt', "[SKIPPED] Feature: $feature_key - No valid limit found in data.\n", FILE_APPEND);
      return;
    }

    $log_info = "[RESOLVED] Feature: $feature_key, Limit: $limit, Config: $config\n";
    file_put_contents(VAPT_PATH . 'vapt-debug.txt', $log_info, FILE_APPEND);

    self::$feature_configs[$feature_key] = [
      'limit' => $limit,
      'key' => $feature_key
    ];

    if (self::$rate_limit_hook_registered) {
      return;
    }
    self::$rate_limit_hook_registered = true;

    add_action('init', function () {
      if (strpos($_SERVER['REQUEST_URI'], 'reset-limit') !== false || isset($_GET['vapt_action'])) return;

      if (current_user_can('manage_options') && !isset($_GET['vapt_test_spike'])) {
        return;
      }

      $ip = $_SERVER['REMOTE_ADDR'];
      $lock_dir = sys_get_temp_dir() . '/vapt-locks';
      if (!file_exists($lock_dir) && !@mkdir($lock_dir, 0755, true)) return;

      foreach (self::$feature_configs as $feature_key => $cfg) {
        $limit = $cfg['limit'];
        $lock_file = $lock_dir . '/vapt_limit_' . md5($ip . $feature_key) . '.lock';

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

            if (file_exists($lock_file) && (time() - filemtime($lock_file) > 60)) {
              $current = 0;
            }

            if (!headers_sent()) {
              header('X-VAPT-Limit-' . $feature_key . ': ' . $limit, false);
              header('X-VAPT-Count-' . $feature_key . ': ' . $current, false);

              header('X-VAPT-Limit: ' . $limit);
              header('X-VAPT-Count: ' . $current);
            }

            if ($current >= $limit) {
              if (!headers_sent()) {
                header('X-VAPT-Enforced: php-rate-limit');
                header('X-VAPT-Feature: ' . $feature_key);
                header('Retry-After: 60');
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
  private static function hide_wp_version($key = 'unknown')
  {
    remove_action('wp_head', 'wp_generator');
    add_filter('the_generator', '__return_empty_string');
    add_action('init', function () use ($key) {
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
      $headers['X-Frame-Options'] = 'SAMEORIGIN';
      $headers['X-Content-Type-Options'] = 'nosniff';
      $headers['X-XSS-Protection'] = '1; mode=block';
      $headers['X-VAPT-Enforced'] = 'php-headers';
      $headers['X-VAPT-Feature'] = $key;
      $headers['Access-Control-Expose-Headers'] = 'X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, X-VAPT-Enforced, X-VAPT-Feature';
      return $headers;
    }, 999);

    if (!headers_sent()) {
      header('X-Frame-Options: SAMEORIGIN');
      header('X-Content-Type-Options: nosniff');
      header('X-XSS-Protection: 1; mode=block');
      header('X-VAPT-Enforced: php-headers');
      header('X-VAPT-Feature: ' . $key);
      header('Access-Control-Expose-Headers: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, X-VAPT-Enforced, X-VAPT-Feature');
    }
  }
}
