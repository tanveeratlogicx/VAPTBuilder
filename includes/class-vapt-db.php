<?php

/**
 * Database Helper Class for VAPT Builder
 */

if (! defined('ABSPATH')) {
  exit;
}

class VAPT_DB
{

  /**
   * Get all feature statuses
   */
  public static function get_feature_statuses()
  {
    global $wpdb;
    $table = $wpdb->prefix . 'vapt_feature_status';
    $results = $wpdb->get_results("SELECT * FROM $table", ARRAY_A);

    $statuses = [];
    foreach ($results as $row) {
      $statuses[$row['feature_key']] = $row['status'];
    }
    return $statuses;
  }

  /**
   * Update feature status with timestamp
   */
  public static function update_feature_status($key, $status)
  {
    global $wpdb;
    $table = $wpdb->prefix . 'vapt_feature_status';

    $data = array(
      'feature_key' => $key,
      'status'      => $status,
    );

    if ($status === 'Release') {
      $data['implemented_at'] = current_time('mysql');
    } else {
      $data['implemented_at'] = null;
    }

    return $wpdb->replace(
      $table,
      $data,
      array('%s', '%s', '%s')
    );
  }

  /**
   * Get a single feature record (status + timestamps)
   */
  public static function get_feature($key)
  {
    global $wpdb;
    $table = $wpdb->prefix . 'vapt_feature_status';
    return $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE feature_key = %s", $key), ARRAY_A);
  }

  /**
   * Get feature status including implemented_at
   */
  public static function get_feature_statuses_full()
  {
    global $wpdb;
    $table = $wpdb->prefix . 'vapt_feature_status';
    return $wpdb->get_results("SELECT * FROM $table", ARRAY_A);
  }

  /**
   * Get feature metadata
   */
  public static function get_feature_meta($key)
  {
    global $wpdb;
    $table = $wpdb->prefix . 'vapt_feature_meta';
    return $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE feature_key = %s", $key), ARRAY_A);
  }

  /**
   * Update feature metadata/toggles
   */
  public static function update_feature_meta($key, $data)
  {
    global $wpdb;
    $table = $wpdb->prefix . 'vapt_feature_meta';

    // 1. Define Strict Column-Format Mapping (Must match DB Schema in vapt-builder.php)
    // NOTE: 'override_schema' and 'override_implementation_data' are not in current schema version.
    $schema_map = array(
      'feature_key'                   => '%s',
      'category'                      => '%s',
      'test_method'                   => '%s',
      'verification_steps'            => '%s',
      'include_test_method'           => '%d',
      'include_verification'          => '%d',
      'include_verification_engine'   => '%d',
      'include_verification_guidance' => '%d',
      'include_manual_protocol'       => '%d',
      'include_operational_notes'     => '%d',
      'is_enforced'                   => '%d',
      'wireframe_url'                 => '%s',
      'generated_schema'              => '%s',
      'implementation_data'           => '%s',
      'dev_instruct'                  => '%s'
    );

    // 2. Fetch existing to merge
    $existing = self::get_feature_meta($key);
    $merged_data = $existing ? array_merge($existing, $data) : $data;

    // Ensure key is set
    $merged_data['feature_key'] = $key;

    // 3. Construct Query Data explicitly in order
    $final_data = array();
    $formats = array();

    foreach ($schema_map as $col => $fmt) {
      if (array_key_exists($col, $merged_data)) {
        $final_data[$col] = $merged_data[$col];
        $formats[] = $fmt;
      } else {
        // If missing in data/existing, set default based on type
        // This handles fresh inserts where $existing is null
        if ($col === 'feature_key') {
          $final_data[$col] = $key;
        } else {
          $final_data[$col] = ($fmt === '%d') ? 0 : null;
          // Special defaults
          if (in_array($col, ['include_verification_guidance', 'include_manual_protocol', 'include_operational_notes'])) {
            $final_data[$col] = 1;
          }
        }
        $formats[] = $fmt;
      }
    }

    return $wpdb->replace(
      $table,
      $final_data,
      $formats
    );
  }

  /**
   * Get all domains
   */
  public static function get_domains()
  {
    global $wpdb;
    $table = $wpdb->prefix . 'vapt_domains';
    return $wpdb->get_results("SELECT * FROM $table", ARRAY_A);
  }

  /**
   * Add or update domain
   */
  public static function update_domain($domain, $is_wildcard = 0, $is_enabled = 1, $id = null, $license_id = '', $license_type = 'standard', $manual_expiry_date = null, $auto_renew = 0, $renewals_count = 0, $renewal_history = null, $license_scope = 'single', $installation_limit = 1)
  {
    global $wpdb;
    $table = $wpdb->prefix . 'vapt_domains';

    // [SAFETY] Check if essential columns exist
    $id_col = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM $table LIKE %s", 'id'));
    if (empty($id_col)) {
      error_log('VAPT: "id" column missing in domains table. Attempting to add...');
      $wpdb->query("ALTER TABLE $table DROP PRIMARY KEY");
      $wpdb->query("ALTER TABLE $table ADD COLUMN id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT FIRST, ADD PRIMARY KEY (id)");
    }

    $renewal_col = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM $table LIKE %s", 'renewal_history'));
    if (empty($renewal_col)) {
      $wpdb->query("ALTER TABLE $table ADD COLUMN renewal_history TEXT DEFAULT NULL AFTER renewals_count");
    }

    $scope_col = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM $table LIKE %s", 'license_scope'));
    if (empty($scope_col)) {
      $wpdb->query("ALTER TABLE $table ADD COLUMN license_scope VARCHAR(50) DEFAULT 'single'");
    }

    $limit_col = $wpdb->get_results($wpdb->prepare("SHOW COLUMNS FROM $table LIKE %s", 'installation_limit'));
    if (empty($limit_col)) {
      $wpdb->query("ALTER TABLE $table ADD COLUMN installation_limit INT DEFAULT 1");
    }

    $domain = trim($domain);

    // Check for existing record to preserve first_activated_at
    if ($id) {
      $existing = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE id = %d", $id));
    } else {
      // Case insensitive lookup for domain name
      $existing = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE LOWER(domain) = LOWER(%s)", $domain));
    }

    $first_activated_at = $existing ? $existing->first_activated_at : null;

    // Only set first_activated_at if it's new and we have a license
    if (!$first_activated_at && $license_id) {
      $first_activated_at = current_time('mysql');
    }

    $data = array(
      'domain'             => $domain,
      'is_wildcard'        => $is_wildcard,
      'is_enabled'         => $is_enabled,
      'license_id'         => $license_id,
      'license_type'       => $license_type,
      'first_activated_at' => $first_activated_at,
      'manual_expiry_date' => $manual_expiry_date,
      'auto_renew'         => $auto_renew,
      'renewals_count'     => $renewals_count,
      'renewal_history'    => is_array($renewal_history) ? json_encode($renewal_history) : $renewal_history,
      'license_scope'      => $license_scope,
      'installation_limit' => intval($installation_limit),
    );

    $formats = array('%s', '%d', '%d', '%s', '%s', '%s', '%s', '%d', '%d', '%s', '%s', '%d');

    if ($existing) {
      error_log('VAPT: DB Found Existing Record (ID: ' . $existing->id . '). Updating...');
      $success = $wpdb->update($table, $data, array('id' => $existing->id), $formats, array('%d'));
      if ($success === false) {
        error_log('VAPT: DB Update Error: ' . $wpdb->last_error);
        return false;
      }
      return $existing->id;
    } else {
      error_log('VAPT: DB No Record Found. Inserting new domain: ' . $domain);
      $success = $wpdb->insert($table, $data, $formats);
      if ($success === false) {
        error_log('VAPT: DB Insert Error: ' . $wpdb->last_error);
        return false;
      }
      $new_id = $wpdb->insert_id;
      error_log('VAPT: DB Insert Success. New ID: ' . $new_id);
      return $new_id;
    }
  }

  /**
   * Record a build
   */
  public static function record_build($domain, $version, $features)
  {
    global $wpdb;
    $table = $wpdb->prefix . 'vapt_domain_builds';

    return $wpdb->insert(
      $table,
      array(
        'domain'    => $domain,
        'version'   => $version,
        'features'  => maybe_serialize($features),
        'timestamp' => current_time('mysql'),
      ),
      array('%s', '%s', '%s', '%s')
    );
  }

  /**
   * Get build history for a domain
   */
  public static function get_build_history($domain = '')
  {
    global $wpdb;
    $table = $wpdb->prefix . 'vapt_domain_builds';
    if ($domain) {
      return $wpdb->get_results($wpdb->prepare("SELECT * FROM $table WHERE domain = %s ORDER BY timestamp DESC", $domain), ARRAY_A);
    }
    return $wpdb->get_results("SELECT * FROM $table ORDER BY timestamp DESC", ARRAY_A);
  }

  /**
   * Delete a domain and its features
   */
  public static function delete_domain($domain_id)
  {
    global $wpdb;
    $wpdb->delete($wpdb->prefix . 'vapt_domains', array('id' => $domain_id), array('%d'));
    $wpdb->delete($wpdb->prefix . 'vapt_domain_features', array('domain_id' => $domain_id), array('%d'));
    return true;
  }
  /**
   * Delete multiple domains and their features
   */
  public static function batch_delete_domains($domain_ids)
  {
    global $wpdb;
    if (empty($domain_ids) || !is_array($domain_ids)) return false;

    $ids_string = implode(',', array_map('intval', $domain_ids));

    $wpdb->query("DELETE FROM {$wpdb->prefix}vapt_domains WHERE id IN ($ids_string)");
    $wpdb->query("DELETE FROM {$wpdb->prefix}vapt_domain_features WHERE domain_id IN ($ids_string)");

    return true;
  }
}
