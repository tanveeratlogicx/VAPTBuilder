<?php

/**
 * VAPT Builder - IDE Stubs
 * 
 * This file is for development purposes only. It provides dummy definitions for 
 * WordPress core functions to silence IDE undefined function errors (e.g. Intelephense).
 * 
 * It is wrapped in a conditional guard to ensure it never interferes with an actual 
 * WordPress environment.
 */

if (!class_exists('WP_User')) {
  /**
   * Stub: WP_User Class
   */
  class WP_User
  {
    public $ID = 0;
    public $user_login = '';
    public $user_email = '';
    public function exists()
    {
      return false;
    }
  }
}

if (!function_exists('add_action')) {

  /**
   * Stub: WordPress Core Functions
   */
  function add_action($tag, $function_to_add, $priority = 10, $accepted_args = 1) {}
  function plugin_dir_path($file)
  {
    return '';
  }
  function plugin_dir_url($file)
  {
    return '';
  }
  function register_activation_hook($file, $function) {}

  /**
   * Stub: WP_User Class
   */
  class WP_User
  {
    public $ID = 0;
    public $user_login = '';
    public $user_email = '';
    public function exists()
    {
      return false;
    }
  }

  function wp_get_current_user()
  {
    return new WP_User();
  }
  function dbDelta($sql) {}
  function wp_mkdir_p($path) {}
  function get_bloginfo($show = 'name', $filter = 'raw')
  {
    return '';
  }
  function get_site_url($blog_id = null, $path = '', $scheme = null)
  {
    return '';
  }
  function admin_url($path = '', $scheme = 'admin')
  {
    return '';
  }
  function wp_mail($to, $subject, $message, $headers = '', $attachments = array()) {}
  function update_option($option, $value, $autoload = null) {}
  function get_option($option, $default = false)
  {
    return '';
  }
  function esc_html($text)
  {
    return $text;
  }
  function esc_url_raw($url, $protocols = null)
  {
    return $url;
  }
  function add_menu_page($page_title, $menu_title, $capability, $menu_slug, $function = '', $icon_url = '', $position = null) {}
  function add_submenu_page($parent_slug, $page_title, $menu_title, $capability, $menu_slug, $function = '') {}
  function wp_safe_redirect($location, $status = 302) {}
  function _e($text, $domain = 'default') {}
  function __($text, $domain = 'default')
  {
    return $text;
  }
  function get_transient($transient) {}
  function set_transient($transient, $value, $expiration = 0) {}
  function get_current_screen()
  {
    return new stdClass();
  }
  function wp_enqueue_style($handle, $src = '', $deps = array(), $ver = false, $media = 'all') {}
  function wp_enqueue_script($handle, $src = '', $deps = array(), $ver = false, $in_footer = false) {}
  function wp_localize_script($handle, $object_name, $l10n) {}
  function rest_url($path = '', $scheme = 'rest')
  {
    return '';
  }
  function wp_create_nonce($action = -1)
  {
    return '';
  }
  function wp_die($message = '', $title = '', $args = array()) {}
  function current_time($type, $gmt = 0)
  {
    return '';
  }
  function current_user_can($capability, ...$args)
  {
    return true;
  }
  function sanitize_text_field($str)
  {
    return $str;
  }

  // Constants
  if (!defined('ABSPATH')) define('ABSPATH', '');
  if (!defined('WPINC')) define('WPINC', '');
}
