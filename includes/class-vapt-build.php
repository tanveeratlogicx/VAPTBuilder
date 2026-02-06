<?php

/**
 * Build Generator for VAPT Builder
 */

if (! defined('ABSPATH')) {
  exit;
}

class VAPT_Build
{
  /**
   * Generate a build ZIP for a specific domain
   */
  public static function generate($data)
  {
    $domain = sanitize_text_field($data['domain']);
    $features = isset($data['features']) ? $data['features'] : [];
    $version = sanitize_text_field($data['version']);
    $white_label = $data['white_label'];
    $generate_type = isset($data['generate_type']) ? $data['generate_type'] : 'full_build';

    // 1. Setup Build Paths
    $upload_dir = wp_upload_dir();
    $base_storage_dir = $upload_dir['basedir'] . '/VAPT-Builds'; // Custom Storage Path

    // Ensure storage directory exists
    if (!file_exists($base_storage_dir)) {
      wp_mkdir_p($base_storage_dir);
      // Secure the directory
      file_put_contents($base_storage_dir . '/index.php', '<?php // Silence is golden');
      file_put_contents($base_storage_dir . '/.htaccess', 'Options -Indexes');
    }

    $build_slug = sanitize_title($domain . '-' . $version);
    $build_dir = $base_storage_dir . '/' . $domain . '/' . $version;
    wp_mkdir_p($build_dir);

    // Temp dir for assembly
    $temp_dir = get_temp_dir() . 'vapt-build-' . time() . '-' . wp_generate_password(8, false);
    wp_mkdir_p($temp_dir);

    $plugin_slug = sanitize_title($white_label['text_domain'] ?: $white_label['name']);
    $plugin_dir = $temp_dir . '/' . $plugin_slug;
    wp_mkdir_p($plugin_dir);

    // 2. Output Config Content (Generated)
    $active_data_file_name = null;
    if (isset($data['include_data']) && ($data['include_data'] === true || $data['include_data'] === 'true' || $data['include_data'] === 1)) {
      $active_data_file_name = get_option('vapt_active_feature_file', 'Feature-List-99.json');
    }

    $license_scope = isset($data['license_scope']) ? $data['license_scope'] : 'single';
    $domain_limit = isset($data['installation_limit']) ? intval($data['installation_limit']) : 1;

    $config_content = self::generate_config_content($domain, $version, $features, $active_data_file_name, $license_scope, $domain_limit);

    // If Config Only -> Save and ZIP just that
    if ($generate_type === 'config_only') {
      $config_filename = "vapt-{$domain}-config-{$version}.php";
      file_put_contents($build_dir . '/' . $config_filename, $config_content);
      return $build_dir . '/' . $config_filename; // Return path to file directly
    }

    // 3. Full Build: Copy Plugin Files Recursively
    self::copy_plugin_files(VAPT_PATH, $plugin_dir, $active_data_file_name);

    // 4. Inject Config File (If Requested)
    if (!isset($data['include_config']) || $data['include_config'] === true || $data['include_config'] === 'true' || $data['include_config'] === 1) {
      file_put_contents($plugin_dir . "/config-{$domain}.php", $config_content);
    }

    // 5. Rewrite Main Plugin File Headers & Logic
    self::rewrite_main_plugin_file($plugin_dir, $plugin_slug, $white_label, $version, $domain);

    // 6. Generate Documentation
    self::generate_docs($plugin_dir, $domain, $version, $features);

    // 7. Create ZIP Archive
    $zip_filename = "{$plugin_slug}-{$version}.zip";
    $zip_path = $build_dir . '/' . $zip_filename;

    $zip = new ZipArchive();
    if ($zip->open($zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
      self::add_dir_to_zip($plugin_dir, $zip, $plugin_slug);
      $zip->close();
    }

    // Cleanup Temp
    self::recursive_rmdir($temp_dir);

    // Return URL to the ZIP
    $base_storage_url = $upload_dir['baseurl'] . '/VAPT-Builds';
    return $base_storage_url . '/' . $domain . '/' . $version . '/' . $zip_filename;
  }

  public static function generate_config_content($domain, $version, $features, $active_data_file = null, $license_scope = 'single', $domain_limit = 1)
  {
    $config = "<?php\n";
    $config .= "/**\n * VAPT Builder Configuration for $domain\n * Build Version: $version\n */\n\n";
    $config .= "if ( ! defined( 'ABSPATH' ) ) { exit; }\n\n";

    $config .= "// Domain Locking & Licensing\n";
    $config .= "define( 'VAPT_DOMAIN_LOCKED', '" . esc_sql($domain) . "' );\n";
    $config .= "define( 'VAPT_BUILD_VERSION', '" . esc_sql($version) . "' );\n";
    $config .= "define( 'VAPT_LICENSE_SCOPE', '" . esc_sql($license_scope) . "' );\n";
    $config .= "define( 'VAPT_DOMAIN_LIMIT', " . intval($domain_limit) . " );\n";

    if ($active_data_file) {
      $config .= "define( 'VAPT_ACTIVE_DATA_FILE', '" . esc_sql($active_data_file) . "' );\n";
    }

    $config .= "\n// Active Features\n";
    foreach ($features as $key) {
      $config .= "define( 'VAPT_FEATURE_" . strtoupper(str_replace('-', '_', $key)) . "', true );\n";
    }

    return $config;
  }

  private static function copy_plugin_files($source, $dest, $active_data_file = null)
  {
    $iterator = new RecursiveIteratorIterator(
      new RecursiveDirectoryIterator($source, RecursiveDirectoryIterator::SKIP_DOTS),
      RecursiveIteratorIterator::SELF_FIRST
    );

    $exclusions = ['.git', '.vscode', 'node_modules', 'brain', 'tests', 'vapt-debug.txt', 'Implementation Plan'];

    foreach ($iterator as $item) {
      $subPath = $iterator->getSubPathName();

      // Check Exclusions
      foreach ($exclusions as $exclude) {
        if (strpos($subPath, $exclude) === 0) continue 2;
      }

      // Handle Data Directory
      if (strpos($subPath, 'data') === 0) {
        if ($active_data_file && strpos($subPath, 'data\\' . $active_data_file) !== false || $active_data_file && strpos($subPath, 'data/' . $active_data_file) !== false) {
          // Allow this specific file
        } else {
          continue;
        }
      }


      if ($item->isDir()) {
        if (!file_exists($dest . DIRECTORY_SEPARATOR . $subPath)) {
          mkdir($dest . DIRECTORY_SEPARATOR . $subPath);
        }
      } else {
        copy($item, $dest . DIRECTORY_SEPARATOR . $subPath);
      }
    }
  }

  private static function rewrite_main_plugin_file($plugin_dir, $plugin_slug, $white_label, $version, $domain)
  {
    // We need to copy vapt-builder.php to [plugin-slug].php and modify headers
    $source_main = VAPT_PATH . 'vapt-builder.php';
    $dest_main = $plugin_dir . '/' . $plugin_slug . '.php'; // Rename main file

    $content = file_get_contents($source_main);

    // Rewrite Headers
    $headers = "/**\n";
    $headers .= " * Plugin Name: " . $white_label['name'] . "\n";
    $headers .= " * Plugin URI: " . $white_label['plugin_uri'] . "\n";
    $headers .= " * Description: " . $white_label['description'] . "\n";
    $headers .= " * Version: " . $version . "\n";
    $headers .= " * Author: " . $white_label['author'] . "\n";
    $headers .= " * Author URI: " . $white_label['author_uri'] . "\n";
    $headers .= " * Text Domain: " . $white_label['text_domain'] . "\n";
    $headers .= " */\n";

    // Regex replace the existing header block
    $content = preg_replace('/\/\*\*.*?\*\//s', $headers, $content, 1);

    // Inject Domain Guard & Config Loader
    $guard_code = "\n// VAPT Builder Client Build Configuration\n";
    $guard_code .= "if ( file_exists( plugin_dir_path( __FILE__ ) . 'config-{$domain}.php' ) ) {\n";
    $guard_code .= "    require_once plugin_dir_path( __FILE__ ) . 'config-{$domain}.php';\n";
    $guard_code .= "}\n\n";

    $guard_code .= "// Domain Integrity & Multi-Site Guard\n";
    $guard_code .= "if ( defined('VAPT_LICENSE_SCOPE') ) {\n";
    $guard_code .= "    \$current_host = \$_SERVER['HTTP_HOST'];\n";
    $guard_code .= "    if ( VAPT_LICENSE_SCOPE === 'single' ) {\n";
    $guard_code .= "        if ( \$current_host !== VAPT_DOMAIN_LOCKED ) {\n";
    $guard_code .= "            vapt_handle_unauthorized_domain( \$current_host, VAPT_DOMAIN_LOCKED );\n";
    $guard_code .= "        }\n";
    $guard_code .= "    } else if ( VAPT_LICENSE_SCOPE === 'multisite' ) {\n";
    $guard_code .= "        \$allowed_limit = defined('VAPT_DOMAIN_LIMIT') ? intval(VAPT_DOMAIN_LIMIT) : 0;\n";
    $guard_code .= "        if ( \$allowed_limit > 0 ) {\n";
    $guard_code .= "            \$activated_domains = get_option('vapt_activated_domains', array());\n";
    $guard_code .= "            if ( !in_array(\$current_host, \$activated_domains) ) {\n";
    $guard_code .= "                if ( count(\$activated_domains) >= \$allowed_limit ) {\n";
    $guard_code .= "                    vapt_handle_unauthorized_domain( \$current_host, 'Multi-Site Limit Exceeded' );\n";
    $guard_code .= "                } else {\n";
    $guard_code .= "                    \$activated_domains[] = \$current_host;\n";
    $guard_code .= "                    update_option('vapt_activated_domains', \$activated_domains);\n";
    $guard_code .= "                }\n";
    $guard_code .= "            }\n";
    $guard_code .= "        }\n";
    $guard_code .= "    }\n";
    $guard_code .= "}\n\n";

    $guard_code .= "function vapt_handle_unauthorized_domain( \$host, \$target ) {\n";
    $guard_code .= "    \$admin_email = '" . sanitize_email(VAPT_SUPERADMIN_EMAIL) . "';\n";
    $guard_code .= "    \$subject = 'Security Alert: Unauthorized VAPT Builder Usage';\n";
    $guard_code .= "    \$message = 'The VAPT Builder plugin was detected on an unauthorized domain: ' . \$host . ' (Locked to: ' . \$target . ')';\n";
    $guard_code .= "    wp_mail(\$admin_email, \$subject, \$message);\n\n";
    $guard_code .= "    if ( !function_exists('is_admin') || !is_admin() ) {\n";
    $guard_code .= "        wp_die('<h1>Security Alert</h1><p>This security plugin is not licensed for this domain.</p>', 'VAPT Licensing');\n";
    $guard_code .= "    }\n";
    $guard_code .= "}\n";

    // Insert after defined('ABSPATH') check
    $content = str_replace("if (! defined('ABSPATH')) {\n  exit;\n}", "if (! defined('ABSPATH')) {\n  exit;\n}\n" . $guard_code, $content);

    // Remove the original file from the copy if it was copied by the recursive copier
    if (file_exists($plugin_dir . '/vapt-builder.php')) unlink($plugin_dir . '/vapt-builder.php');
    if (file_exists($plugin_dir . '/vapt-copilot.php')) unlink($plugin_dir . '/vapt-copilot.php');

    file_put_contents($dest_main, $content);
  }

  private static function generate_docs($dir, $domain, $version, $features)
  {
    $readme = "# VAPT Builder Security Build for $domain\n\n";
    $readme .= "Version: $version\n";
    $readme .= "Generated: " . date('Y-m-d') . "\n\n";
    $readme .= "## Active Protection Modules\n";
    foreach ($features as $f) {
      $readme .= "- " . strtoupper(str_replace('-', ' ', $f)) . "\n";
    }
    file_put_contents($dir . '/README.md', $readme);
  }

  private static function add_dir_to_zip($dir, $zip, $zip_path)
  {
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir), RecursiveIteratorIterator::LEAVES_ONLY);
    foreach ($files as $name => $file) {
      if (! $file->isDir()) {
        $file_path = $file->getRealPath();
        $relative_path = $zip_path . '/' . substr($file_path, strlen($dir) + 1);
        $zip->addFile($file_path, $relative_path);
      }
    }
  }

  private static function recursive_rmdir($dir)
  {
    if (is_dir($dir)) {
      $objects = scandir($dir);
      foreach ($objects as $object) {
        if ($object != "." && $object != "..") {
          if (is_dir($dir . "/" . $object) && !is_link($dir . "/" . $object))
            self::recursive_rmdir($dir . "/" . $object);
          else
            unlink($dir . "/" . $object);
        }
      }
      rmdir($dir);
    }
  }
}
