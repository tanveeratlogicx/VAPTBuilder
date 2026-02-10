<?php

/**
 * VAPT_Nginx_Driver
 * Handles enforcement of rules for Nginx via a generated include file.
 */

if (!defined('ABSPATH')) exit;

class VAPT_Nginx_Driver
{
  /**
   * Generates a list of valid Nginx directives based on the provided data and schema.
   *
   * @param array $data Implementation data (user inputs)
   * @param array $schema Feature schema containing enforcement mappings
   * @return array List of valid Nginx directives
   */
  public static function generate_rules($data, $schema)
  {
    // 🛡️ TWO-WAY DEACTIVATION (v3.6.19)
    $is_enabled = isset($data['enabled']) ? (bool)$data['enabled'] : true;
    if (!$is_enabled) {
      return array();
    }

    $enf_config = isset($schema['enforcement']) ? $schema['enforcement'] : array();
    $rules = array();
    $mappings = isset($enf_config['mappings']) ? $enf_config['mappings'] : array();

    foreach ($mappings as $key => $directive) {
      if (!empty($data[$key])) {
        // Translation Layer: Convert Apache-style hints to Nginx if needed, 
        // OR rely on direct Nginx mappings if provided in schema.
        // For now, we assume mappings might need translation or are purely conceptual keys.

        $nginx_rule = self::translate_to_nginx($key, $directive);

        if ($nginx_rule) {
          $rules[] = $nginx_rule;
        }
      }
    }

    if (!empty($rules)) {
      $feature_key = isset($schema['feature_key']) ? $schema['feature_key'] : 'unknown';
      array_unshift($rules, "# Rule for: $feature_key");
      $rules[] = "add_header X-VAPT-Feature \"$feature_key\" always;"; // Marker for verify
    }

    return $rules;
  }

  /**
   * 🔍 VERIFICATION LOGIC (v3.6.19)
   */
  public static function verify($key, $impl_data, $schema)
  {
    $upload_dir = wp_upload_dir();
    $file_path = $upload_dir['basedir'] . '/vapt-nginx-rules.conf';

    if (!file_exists($file_path)) {
      return false;
    }

    $content = file_get_contents($file_path);
    return (strpos($content, "X-VAPT-Feature \"$key\"") !== false);
  }

  /**
   * Translates common VAPT keys/Apache directives to Nginx syntax.
   */
  private static function translate_to_nginx($key, $directive)
  {
    // 1. Headers
    // Apache: Header [always] set X-Frame-Options "SAMEORIGIN"
    // Nginx: add_header X-Frame-Options "SAMEORIGIN" always;
    if (strpos($directive, 'Header ') !== false && strpos($directive, 'set ') !== false) {
      $clean = str_replace(['Header ', 'always ', 'set ', '"'], ['', '', '', ''], $directive);
      $parts = explode(' ', trim($clean), 2);
      if (count($parts) == 2) {
        return 'add_header ' . $parts[0] . ' "' . $parts[1] . '" always;';
      }
    }

    // 2. Directory Listing
    // Apache: Options -Indexes
    // Nginx: autoindex off;
    if (strpos($directive, 'Options -Indexes') !== false) {
      return 'autoindex off;';
    }

    // 3. Block Files (xmlrpc, etc)
    // Apache: <Files xmlrpc.php> ... </Files>
    // Nginx: location = /xmlrpc.php { deny all; }
    if ($key === 'block_xmlrpc') {
      return 'location = /xmlrpc.php { deny all; return 403; }';
    }

    // 4. Block Dot Files
    if ($key === 'block_sensitive_files') {
      return 'location ~ /\. { deny all; return 403; }';
    }

    // 5. Generic File Blocking (regex)
    // Apache: <FilesMatch ...>
    // Nginx: location ~ ...
    if (strpos($directive, '<Files') !== false) {
      // Fallback: convert common file blocks manually if known
      if (strpos($directive, 'debug.log') !== false) {
        return 'location ~ /debug\.log$ { deny all; return 403; }';
      }
    }

    return null;
  }

  /**
   * Writes a complete batch of rules to wp-content/uploads/vapt-nginx-rules.conf
   */
  public static function write_batch($all_rules_array)
  {
    $upload_dir = wp_upload_dir();
    $file_path = $upload_dir['basedir'] . '/vapt-nginx-rules.conf';

    $content = "# VAPT Builder - Auto Generated Nginx Rules\n";
    $content .= "# Include this file in your nginx.conf server block.\n";
    $content .= "# Last Updated: " . date('Y-m-d H:i:s') . "\n\n";

    $content .= implode("\n", $all_rules_array);

    $result = @file_put_contents($file_path, $content);

    if ($result !== false) {
      // Set a persistent option to verify file matches current state?
      // Or just transient for admin notice?
      set_transient('vapt_nginx_rules_updated', $file_path, HOUR_IN_SECONDS * 24);
      return true;
    }

    return false;
  }
}
