<?php

/**
 * VAPT_Htaccess_Driver
 * Handles enforcement of rules into .htaccess
 */

if (!defined('ABSPATH')) exit;

class VAPT_Htaccess_Driver
{
  /**
   * Whitelist of allowed .htaccess directives for security
   * Prevents injection of dangerous PHP/Server directives
   */
  private static $allowed_directives = [
    'Options',
    'Header',
    'Files',
    'FilesMatch',
    'IfModule',
    'Order',
    'Deny',
    'Allow',
    'Directory',
    'DirectoryMatch'
  ];

  /**
   * Dangerous patterns that should never be allowed
   */
  private static $dangerous_patterns = [
    '/php_value/i',
    '/php_admin_value/i',
    '/SetEnvIf.*passthrough/i',
    '/RewriteRule.*passthrough/i',
    '/RewriteRule.*exec/i',
    '/<FilesMatch.*\.php/i',
    '/php_flag\s/i',
    '/AddHandler.*php/i',
    '/Action\s/i',
    '/SetHandler\s/i'
  ];

  public static function enforce($data, $schema)
  {
    $log = "[Htaccess Debug " . date('Y-m-d H:i:s') . "] Enforce Called.\n";
    $log .= "Data Keys: " . implode(',', array_keys($data)) . "\n";
    $enf_config = isset($schema['enforcement']) ? $schema['enforcement'] : array();
    $target_key = isset($enf_config['target']) ? $enf_config['target'] : 'root';

    $htaccess_path = ABSPATH . '.htaccess';
    if ($target_key === 'uploads') {
      $upload_dir = wp_upload_dir();
      $htaccess_path = $upload_dir['basedir'] . '/.htaccess';
    }

    if (empty($data) && $target_key !== 'root') {
      if (file_exists($htaccess_path)) {
        @unlink($htaccess_path);
      }
      return;
    }

    $dir = dirname($htaccess_path);
    if (!is_dir($dir)) {
      wp_mkdir_p($dir);
    }

    $content = "";
    if (file_exists($htaccess_path)) {
      $content = file_get_contents($htaccess_path);
    }

    // Support both old and new markers for replacement during transition
    $start_marker = "# BEGIN VAPT SECURITY RULES";
    $end_marker = "# END VAPT SECURITY RULES";

    $old_start_marker = "# BEGIN VAPTC SECURITY RULES";
    $old_end_marker = "# END VAPTC SECURITY RULES";

    $rules = array();
    $mappings = isset($enf_config['mappings']) ? $enf_config['mappings'] : array();

    foreach ($mappings as $key => $directive) {
      if (!empty($data[$key])) {
        $validation = self::validate_htaccess_directive($directive);
        if ($validation['valid']) {
          $rules[] = $directive;
        } else {
          error_log(sprintf(
            'VAPT: Invalid .htaccess directive rejected for feature %s (key: %s). Reason: %s',
            $schema['feature_key'] ?? 'unknown',
            $key,
            $validation['reason']
          ));
          set_transient(
            'vapt_htaccess_validation_error_' . time(),
            sprintf(
              'Security: Invalid .htaccess directive rejected for "%s". Reason: %s',
              $key,
              $validation['reason']
            ),
            300
          );
        }
      }
    }

    $rules_string = "";
    if (!empty($rules)) {
      $rules_string = "\n" . $start_marker . "\n" . implode("\n\n", $rules) . "\n" . $end_marker . "\n";
    }
    file_put_contents(WP_CONTENT_DIR . '/vapt-htaccess-debug.txt', $log, FILE_APPEND);

    if ($target_key === 'root') {
      // Try new pattern first
      $pattern = "/# BEGIN VAPT SECURITY RULES.*?# END VAPT SECURITY RULES/s";
      $old_pattern = "/# BEGIN VAPTC SECURITY RULES.*?# END VAPTC SECURITY RULES/s";

      if (preg_match($pattern, $content)) {
        $new_content = preg_replace($pattern, trim($rules_string), $content);
      } else if (preg_match($old_pattern, $content)) {
        $new_content = preg_replace($old_pattern, trim($rules_string), $content);
      } else {
        if (strpos($content, "# END WordPress") !== false) {
          $new_content = str_replace("# END WordPress", "# END WordPress\n" . $rules_string, $content);
        } else {
          $new_content = $content . $rules_string;
        }
      }
    } else {
      $new_content = trim($rules_string);
      if (empty($new_content)) {
        if (file_exists($htaccess_path)) @unlink($htaccess_path);
        return;
      }
    }

    if (!empty($new_content) || file_exists($htaccess_path)) {
      $result = @file_put_contents($htaccess_path, trim($new_content) . "\n");
      if ($result === false) {
        error_log("VAPT: Failed to write .htaccess to $htaccess_path. Check file permissions.");
        set_transient(
          'vapt_htaccess_write_error_' . time(),
          "Failed to update .htaccess file. Please check file permissions.",
          300
        );
      }
    }
  }

  private static function validate_htaccess_directive($directive)
  {
    if (empty($directive) || !is_string($directive)) {
      return ['valid' => false, 'reason' => 'Directive must be a non-empty string'];
    }

    foreach (self::$dangerous_patterns as $pattern) {
      if (preg_match($pattern, $directive)) {
        return [
          'valid' => false,
          'reason' => sprintf('Contains dangerous pattern: %s', $pattern)
        ];
      }
    }

    if (preg_match('/<[^>]*php[^>]*>/i', $directive)) {
      return ['valid' => false, 'reason' => 'Contains PHP-related tags'];
    }

    if (preg_match('/[<>{}]/', $directive) && !preg_match('/<(?:IfModule|Files|Directory|FilesMatch|DirectoryMatch)/i', $directive)) {
      return ['valid' => false, 'reason' => 'Contains unescaped special characters'];
    }

    if (strlen($directive) > 4096) {
      return ['valid' => false, 'reason' => 'Directive exceeds maximum length (4096 characters)'];
    }

    return ['valid' => true, 'reason' => ''];
  }
}
