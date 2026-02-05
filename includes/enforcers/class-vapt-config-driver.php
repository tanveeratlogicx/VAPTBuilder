<?php

/**
 * VAPT_Config_Driver
 * Handles enforcement of rules into wp-config.php
 */

if (!defined('ABSPATH')) exit;

class VAPT_Config_Driver
{
  /**
   * Generates a list of valid wp-config.php defines based on the provided data and schema.
   *
   * @param array $data Implementation data (user inputs)
   * @param array $schema Feature schema containing enforcement mappings
   * @return array List of define statements
   */
  public static function generate_rules($data, $schema)
  {
    $enf_config = isset($schema['enforcement']) ? $schema['enforcement'] : array();
    $rules = array();
    $mappings = isset($enf_config['mappings']) ? $enf_config['mappings'] : array();

    foreach ($mappings as $key => $constant) {
      if (isset($data[$key])) {
        $value = $data[$key];

        // Convert to PHP literal
        if (is_bool($value)) {
          $val_str = $value ? 'true' : 'false';
        } elseif (is_numeric($value)) {
          $val_str = $value;
        } else {
          $val_str = "'" . addslashes((string)$value) . "'";
        }

        $rules[] = "define('$constant', $val_str);";
      }
    }

    return $rules;
  }

  /**
   * Writes a complete batch of rules to wp-config.php, replacing the previous VAPT block.
   *
   * @param array $all_rules_array Flat array of all define statements to write
   * @return bool Success status
   */
  public static function write_batch($all_rules_array)
  {
    $paths = [];
    if (defined('ABSPATH')) {
      $base = rtrim(ABSPATH, DIRECTORY_SEPARATOR);
      $paths[] = $base . DIRECTORY_SEPARATOR . 'wp-config.php';
      $paths[] = dirname($base) . DIRECTORY_SEPARATOR . 'wp-config.php';
    }

    $wp_config_path = null;
    foreach ($paths as $path) {
      if (@is_file($path) && @is_readable($path) && @is_writable($path)) {
        $wp_config_path = $path;
        break;
      }
    }

    if (!$wp_config_path) {
      error_log("VAPT: wp-config.php not writable or not found.");
      return false;
    }

    $content = file_get_contents($wp_config_path);
    $line_ending = (strpos($content, "\r\n") !== false) ? "\r\n" : "\n";
    $lines = explode($line_ending, $content);

    $start_marker = "// BEGIN VAPT CONFIG RULES";
    $end_marker = "// END VAPT CONFIG RULES";

    // 1. Identify constants we are managing in this batch (to prevent duplicates)
    $managed_constants = [];
    foreach ($all_rules_array as $rule) {
      if (preg_match("/define\s*\(\s*['\"](.+?)['\"]/i", $rule, $m)) {
        $managed_constants[] = $m[1];
      }
    }

    // 2. Filter existing content: remove old VAPT blocks and any existing definitions of our constants
    $new_lines = [];
    $in_vapt_block = false;
    foreach ($lines as $line) {
      $trimmed = trim($line);

      if ($trimmed === $start_marker) {
        $in_vapt_block = true;
        continue;
      }
      if ($trimmed === $end_marker) {
        $in_vapt_block = false;
        continue;
      }
      if ($in_vapt_block) continue;

      // Clean up legacy single-line markers
      if (strpos($trimmed, "// Added by VAPT Security") !== false) continue;

      // Check if this line defines one of our managed constants
      // Robust regex: matches define('CONST', ... or define("CONST", ... with varying whitespace
      $is_managed = false;
      foreach ($managed_constants as $const) {
        if (preg_match("/^\s*define\s*\(\s*['\"]" . preg_quote($const, '/') . "['\"]/i", $trimmed)) {
          $is_managed = true;
          break;
        }
      }
      if ($is_managed) continue;

      $new_lines[] = $line;
    }

    // 3. Prepare new VAPT block
    $vapt_block = [];
    if (!empty($all_rules_array)) {
      $vapt_block[] = $start_marker;
      foreach ($all_rules_array as $rule) {
        $vapt_block[] = $rule;
      }
      $vapt_block[] = $end_marker;
    }

    // 4. Insert before "That's all, stop editing" or at end
    $insert_idx = -1;
    $marker = "That's all, stop editing";
    foreach ($new_lines as $i => $line) {
      if (stripos($line, $marker) !== false) {
        $insert_idx = $i;
        break;
      }
    }

    if ($insert_idx !== -1) {
      array_splice($new_lines, $insert_idx, 0, $vapt_block);
    } else {
      // Fallback: Before wp-settings.php
      foreach ($new_lines as $i => $line) {
        if (strpos($line, 'wp-settings.php') !== false) {
          $insert_idx = $i;
          break;
        }
      }
      if ($insert_idx !== -1) {
        array_splice($new_lines, $insert_idx, 0, $vapt_block);
      } else {
        $new_lines = array_merge($new_lines, $vapt_block);
      }
    }

    $final_content = implode($line_ending, $new_lines);

    // 5. Final Safety: Check if content changed before writing + Backup
    if ($final_content !== $content) {
      @copy($wp_config_path, $wp_config_path . '.bak');
      $written = @file_put_contents($wp_config_path, $final_content) !== false;
      if ($written) {
        error_log("VAPT: wp-config.php updated successfully. Backup created.");
      }
      return $written;
    }

    return true;
  }
}
