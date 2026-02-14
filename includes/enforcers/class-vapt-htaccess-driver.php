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
    // 🛡️ TWO-WAY DEACTIVATION (v3.12.3 - Intelligent Detection)
    $is_enabled = true;
    if (isset($data['enabled'])) {
      $is_enabled = (bool)$data['enabled'];
    } else {
      // If 'enabled' is missing, check if any mapped toggle is set to false
      $mappings = $enf_config['mappings'] ?? array();
      foreach ($mappings as $key => $directive) {
        if (isset($data[$key]) && ($data[$key] === false || $data[$key] === 0 || $data[$key] === '0')) {
          // If the primary enforcement mapping is a toggle and it's OFF, consider feature disabled
          $is_enabled = false;
          break;
        }
      }
    }

    if (!$is_enabled) {
      return array(); // Return empty set if disabled
    }

    $enf_config = isset($schema['enforcement']) ? $schema['enforcement'] : array();
    $rules = array();
    $mappings = isset($enf_config['mappings']) ? $enf_config['mappings'] : array();

    // DEBUG: Log what we're receiving
    error_log('VAPT DEBUG generate_rules - Data received: ' . print_r($data, true));
    error_log('VAPT DEBUG generate_rules - Mappings: ' . print_r(array_keys($mappings), true));


    // 1. Iterate mappings and bind data
    foreach ($mappings as $key => $directive) {
      if (!empty($data[$key])) {
        // [ENHANCEMENT] Variable Substitution (v3.12.0)
        $directive = self::substitute_variables($directive);

        // [v3.12.4] Fix literal \n escaping
        $directive = str_replace('\n', "\n", $directive);

        // [v3.12.7] Strip VAPTBuilder RISK-XXX comments
        $directive = preg_replace('/^#\s*VAPTBuilder\s+RISK-\d+:.*$/m', '', $directive);
        $directive = trim($directive);

        $processed_directive = self::prepare_directive($directive);
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

    // 2. Wrap collected rules in a marker header for verification (v3.12.5 - Compacted)
    if (!empty($rules)) {
      $feature_key = isset($schema['feature_key']) ? $schema['feature_key'] : 'unknown';
      // Compact headers into single block
      $rules = array_merge(
        ["<IfModule mod_headers.c>\n  Header set X-VAPT-Enforced \"htaccess\"\n  Header append X-VAPT-Feature \"$feature_key\"\n</IfModule>"],
        $rules
      );
    }

    return $rules;
  }

  /**
   * 🔍 VERIFICATION LOGIC (v3.12.6 - Enhanced Debug)
   * Physically checks the .htaccess file for the feature marker.
   */
  public static function verify($key, $impl_data, $schema)
  {
    $target_key = $schema['enforcement']['target'] ?? 'root';
    $htaccess_path = ABSPATH . '.htaccess';
    if ($target_key === 'uploads') {
      $upload_dir = wp_upload_dir();
      $htaccess_path = $upload_dir['basedir'] . '/.htaccess';
    }

    error_log("VAPT VERIFY: Checking for feature '$key' in $htaccess_path");

    if (!file_exists($htaccess_path)) {
      error_log("VAPT VERIFY: File does not exist: $htaccess_path");
      return false;
    }

    $content = file_get_contents($htaccess_path);
    $search_string = "X-VAPT-Feature \"$key\"";
    $found = (strpos($content, $search_string) !== false);

    error_log("VAPT VERIFY: Looking for '$search_string' - " . ($found ? 'FOUND' : 'NOT FOUND'));

    // Look for the specific feature key within our VAPT block
    return $found;
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
      $rules_string = "\n" . $start_marker . "\n" . implode("\n", $all_rules_array) . "\n" . $end_marker . "\n";
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
   * [v3.12.6] Enhanced formatting with proper indentation and spacing
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

    // Wrap mod_rewrite directives with enhanced formatting
    if (stripos($directive, 'RewriteEngine') === 0 || stripos($directive, 'RewriteCond') === 0 || stripos($directive, 'RewriteRule') === 0) {
      // Check if directive contains a comment line (starts with #)
      $lines = explode("\n", $directive);
      $formatted_lines = [];

      foreach ($lines as $line) {
        $trimmed = trim($line);
        if (empty($trimmed)) {
          $formatted_lines[] = '';
        } elseif (strpos($trimmed, '#') === 0) {
          // Comment line - add blank line before it and indent
          if (!empty($formatted_lines) && end($formatted_lines) !== '') {
            $formatted_lines[] = '';
          }
          $formatted_lines[] = '  ' . $trimmed;
        } else {
          // Regular directive - indent
          $formatted_lines[] = '  ' . $trimmed;
        }
      }

      return "<IfModule mod_rewrite.c>\n" . implode("\n", $formatted_lines) . "\n</IfModule>";
    }

    return $directive;
  }

  /**
   * Substitutes template variables like {{site_url}} with actual values.
   */
  private static function substitute_variables($directive)
  {
    $site_url = get_site_url();
    $home_url = get_home_url();
    $admin_url = get_admin_url();

    $replacements = [
      '{{site_url}}' => $site_url,
      '{{home_url}}' => $home_url,
      '{{admin_url}}' => $admin_url,
      '{{domain}}'   => parse_url($site_url, PHP_URL_HOST),
    ];

    return str_replace(array_keys($replacements), array_values($replacements), $directive);
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
