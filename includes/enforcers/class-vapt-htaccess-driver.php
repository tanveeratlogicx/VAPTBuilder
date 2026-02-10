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
    'DirectoryMatch',
    'Require'
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

  /**
   * Generates a list of valid .htaccess rules based on the provided data and schema.
   * Does NOT write to file.
   *
   * @param array $data Implementation data (user inputs)
   * @param array $schema Feature schema containing enforcement mappings
   * @return array List of valid .htaccess directives
   */
  public static function generate_rules($data, $schema)
  {
    // 🛡️ TWO-WAY DEACTIVATION (v3.6.19)
    $is_enabled = isset($data['enabled']) ? (bool)$data['enabled'] : true;
    if (!$is_enabled) {
      return array(); // Return empty set if disabled
    }

    $enf_config = isset($schema['enforcement']) ? $schema['enforcement'] : array();
    $rules = array();
    $mappings = isset($enf_config['mappings']) ? $enf_config['mappings'] : array();

    // 1. Iterate mappings and bind data
    foreach ($mappings as $key => $directive) {
      // v3.8.4: Use isset and non-empty check instead of empty() to allow '0' or false values in sub-controls
      if (isset($data[$key]) && $data[$key] !== '') {
        $processed_directive = $directive;

        // Variable Substitution Logic (v3.7.0 / v3.8.4 enhanced)
        if (strpos($directive, '{{') !== false) {
          $processed_directive = preg_replace_callback('/\{\{([a-zA-Z0-9_\-]+)\}\}/', function ($matches) use ($data, $key) {
            $placeholder = $matches[1];

            // Case A: {{value}} refers to the main control's value
            if ($placeholder === 'value') {
              return $data[$key];
            }

            // Case B: Reference to another control
            if (isset($data[$placeholder])) {
              return $data[$placeholder];
            }

            return '';
          }, $directive);
        }

        // Final sanitation for htaccess (ensure no malicious characters if dynamically injected)
        // Note: prepare_directive handles IfModule wrapping
        $processed_directive = self::prepare_directive($processed_directive);
        $validation = self::validate_htaccess_directive($processed_directive);

        if ($validation['valid']) {
          $rules[] = $processed_directive;
        } else {
          error_log(sprintf(
            'VAPT: Invalid .htaccess directive rejected for feature %s (key: %s). Reason: %s',
            $schema['feature_key'] ?? 'unknown',
            $key,
            $validation['reason']
          ));
        }
      }
    }

    // 2. Wrap collected rules in a marker header for verification
    if (!empty($rules)) {
      $feature_key = isset($schema['feature_key']) ? $schema['feature_key'] : 'unknown';
      $enforcer_headers = array();
      $enforcer_headers[] = "<IfModule mod_headers.c>";
      $enforcer_headers[] = "  Header set X-VAPT-Enforced \"htaccess\"";
      // Sanitize feature_key for header
      $safe_feature_key = preg_replace('/[^a-zA-Z0-9_\-]/', '', $feature_key);
      $enforcer_headers[] = "  Header append X-VAPT-Feature \"$safe_feature_key\"";
      $enforcer_headers[] = "</IfModule>";

      // Prepend headers so they appear at the top of the feature block
      $rules = array_merge($enforcer_headers, $rules);
    }

    return $rules;
  }

  /**
   * 🔍 VERIFICATION LOGIC (v3.6.19)
   * Phisically checks the .htaccess file for the feature marker.
   */
  public static function verify($key, $impl_data, $schema)
  {
    $target_key = $schema['enforcement']['target'] ?? 'root';
    $htaccess_path = ABSPATH . '.htaccess';
    if ($target_key === 'uploads') {
      $upload_dir = wp_upload_dir();
      $htaccess_path = $upload_dir['basedir'] . '/.htaccess';
    }

    if (!file_exists($htaccess_path)) {
      return false;
    }

    $content = file_get_contents($htaccess_path);
    // Look for the specific feature key within our VAPT block
    return (strpos($content, "X-VAPT-Feature \"$key\"") !== false);
  }

  /**
   * Writes a complete batch of rules to the .htaccess file, replacing the previous VAPT block.
   *
   * @param array $all_rules_array Flat array of all .htaccess rules to write
   * @param string $target_key 'root' or 'uploads'
   * @return bool Success status
   */
  public static function write_batch($all_rules_array, $target_key = 'root')
  {
    $log = "[Htaccess Batch Write " . date('Y-m-d H:i:s') . "] Writing " . count($all_rules_array) . " rules.\n";

    $htaccess_path = ABSPATH . '.htaccess';
    if ($target_key === 'uploads') {
      $upload_dir = wp_upload_dir();
      $htaccess_path = $upload_dir['basedir'] . '/.htaccess';
    }

    // Ensure directory exists
    $dir = dirname($htaccess_path);
    if (!is_dir($dir)) {
      wp_mkdir_p($dir);
    }

    // Read existing content
    $content = "";
    if (file_exists($htaccess_path)) {
      $content = file_get_contents($htaccess_path);
    }

    // Prepare new VAPT block
    $start_marker = "# BEGIN VAPT SECURITY RULES";
    $end_marker = "# END VAPT SECURITY RULES";
    $rules_string = "";

    if (!empty($all_rules_array)) {
      $rules_string = "\n" . $start_marker . "\n" . implode("\n\n", $all_rules_array) . "\n" . $end_marker . "\n";
    }

    // Replace or Append
    // 1. Remove old block if exists (supporting both old/new markers)
    $pattern = "/# BEGIN VAPT SECURITY RULES.*?# END VAPT SECURITY RULES/s";
    $old_pattern = "/# BEGIN VAPTC SECURITY RULES.*?# END VAPTC SECURITY RULES/s";

    $new_content = $content;

    if (preg_match($pattern, $content)) {
      $new_content = preg_replace($pattern, trim($rules_string), $content);
    } else if (preg_match($old_pattern, $content)) {
      $new_content = preg_replace($old_pattern, trim($rules_string), $content);
    } else {
      // Append if not found
      if ($target_key === 'root') {
        if (strpos($content, "# END WordPress") !== false) {
          $new_content = str_replace("# END WordPress", "# END WordPress\n" . $rules_string, $content);
        } else {
          $new_content = $content . $rules_string;
        }
      } else {
        // For non-root (like uploads), usually we control the whole file, but let's be safe and just append/replace block
        // Actually for uploads, we might just be the only owner. 
        // But adhering to the block strategy is safer.
        $new_content = $content . $rules_string;
      }
    }

    // Clean up empty lines? 
    // Just ensure we don't end up with huge gaps.

    // Write
    if ($new_content !== $content || !file_exists($htaccess_path)) {
      // Safety Backup
      if (file_exists($htaccess_path)) {
        @copy($htaccess_path, $htaccess_path . '.bak');
      }

      $result = @file_put_contents($htaccess_path, trim($new_content) . "\n");
      if ($result !== false) {
        $log .= "Write SUCCESS: " . strlen($new_content) . " bytes written to $htaccess_path. Backup created.\n";
        delete_transient('vapt_active_enforcements');
      } else {
        $log .= "Write FAILURE: Could not write to $htaccess_path. Check file permissions.\n";
        error_log("VAPT: Failed to write .htaccess to $htaccess_path.");
        set_transient('vapt_htaccess_write_error_' . time(), "Failed to update .htaccess file. check perms.", 300);
        return false;
      }
    } else {
      $log .= "No changes detected. Write skipped.\n";
    }

    // Persistent Log
    $debug_file = WP_CONTENT_DIR . '/vapt-htaccess-debug.txt';
    @file_put_contents($debug_file, $log, FILE_APPEND);

    return true;
  }

  /**
   * Legacy method for single-feature enforcement.
   * Now proxies to generate + write, BUT logic warns this is partial.
   * Kept for signature compatibility.
   */
  public static function enforce($data, $schema)
  {
    // Note: Direct calling of this will overwrite the file with ONLY this feature's rules.
    // This should only be used if we are sure we want that, or during testing.
    //Ideally, we should trigger a full rebuild from Enforcer instead.
    $rules = self::generate_rules($data, $schema);
    self::write_batch($rules, isset($schema['enforcement']['target']) ? $schema['enforcement']['target'] : 'root');
  }

  /**
   * Automatically wraps directives in <IfModule> if they are not already wrapped.
   * This is a safety measure to prevent server crashes if an Apache module is missing.
   */
  private static function prepare_directive($directive)
  {
    $directive = trim($directive);
    if (empty($directive)) return $directive;

    // If already wrapped in IfModule, skip
    if (stripos($directive, '<IfModule') === 0) {
      return $directive;
    }

    // Wrap mod_headers directives
    if (stripos($directive, 'Header ') === 0) {
      return "<IfModule mod_headers.c>\n  $directive\n</IfModule>";
    }

    // Wrap mod_rewrite directives
    if (stripos($directive, 'RewriteEngine') === 0 || stripos($directive, 'RewriteRule') === 0 || stripos($directive, 'RewriteCond') === 0) {
      return "<IfModule mod_rewrite.c>\n  $directive\n</IfModule>";
    }

    return $directive;
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
