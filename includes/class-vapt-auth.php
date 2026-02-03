<?php

/**
 * Superadmin OTP Authentication for VAPT Builder
 */

if (! defined('ABSPATH')) {
  exit;
}

class VAPT_Auth
{
  public function __construct()
  {
    add_action('admin_init', array($this, 'handle_otp_verification'));
  }

  /**
   * Check if the current user is authenticated
   */
  public static function is_authenticated()
  {
    $user_id = get_current_user_id();
    if (!$user_id) {
      return false;
    }

    $session = get_transient('vapt_auth_' . $user_id);
    if (!$session) {
      return false;
    }

    return true;
  }

  /**
   * Send OTP to the superadmin email
   */
  public static function send_otp()
  {
    $identity = vapt_get_superadmin_identity();
    $otp = wp_generate_password(6, false, false);
    $hashed_otp = wp_hash_password($otp);

    // Store OTP in transient for 10 minutes
    // Email Only per user request
    set_transient('vapt_otp_email_' . $identity['user'], $hashed_otp, 10 * MINUTE_IN_SECONDS);

    // 1. Send Email
    $message = sprintf(
      __('Your VAPT Builder verification code is: %s. This code will expire in 10 minutes.', 'vapt-builder'),
      $otp
    );
    wp_mail($identity['email'], __('VAPT Builder - Verification Code', 'vapt-builder'), $message);
  }

  /**
   * Handle OTP verification from the form
   */
  public function handle_otp_verification()
  {
    if (! isset($_POST['vapt_otp_nonce']) || ! wp_verify_nonce($_POST['vapt_otp_nonce'], 'vapt_verify_otp')) {
      return;
    }

    if (! isset($_POST['vapt_email_otp'])) {
      return;
    }

    $identity = vapt_get_superadmin_identity();
    $submitted_otp = sanitize_text_field($_POST['vapt_email_otp']);
    $stored_otp = get_transient('vapt_otp_email_' . $identity['user']);

    if ($stored_otp && wp_check_password($submitted_otp, $stored_otp)) {
      // Successful verification
      $user_id = get_current_user_id();
      set_transient('vapt_auth_' . $user_id, array(
        'user' => $identity['user'],
        'time' => time()
      ), 2 * HOUR_IN_SECONDS);

      delete_transient('vapt_otp_email_' . $identity['user']);

      wp_safe_redirect(admin_url('admin.php?page=vapt-domain-admin'));
      exit;
    }
  }

  /**
   * Render the OTP verification form
   */
  public static function render_otp_form()
  {
    if (isset($_GET['resend_otp'])) {
      self::send_otp();
    }
?>
    <style>
      .vapt-otp-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: linear-gradient(135deg, #1a237e 0%, #0d47a1 100%);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 999999;
        color: #fff;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
      }

      .vapt-otp-box {
        background: rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(10px);
        padding: 40px;
        border-radius: 12px;
        box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
        width: 100%;
        max-width: 400px;
        text-align: center;
        border: 1px solid rgba(255, 255, 255, 0.1);
        position: relative;
      }

      .vapt-otp-box h2 {
        margin: 0 0 10px;
        font-size: 24px;
        font-weight: 600;
        color: #fff;
      }

      .vapt-otp-box p {
        margin-bottom: 30px;
        color: rgba(255, 255, 255, 0.7);
        line-height: 1.5;
      }

      .vapt-otp-input {
        width: 100%;
        padding: 15px;
        border-radius: 8px;
        border: none;
        background: rgba(255, 255, 255, 0.9);
        font-size: 20px;
        text-align: center;
        letter-spacing: 5px;
        margin-bottom: 20px;
        color: #1a237e;
        font-weight: bold;
      }

      .vapt-otp-submit {
        width: 100%;
        padding: 15px;
        border-radius: 8px;
        border: none;
        background: #00e676;
        color: #1a237e;
        font-size: 16px;
        font-weight: 600;
        cursor: pointer;
        transition: transform 0.2s, background 0.2s;
      }

      .vapt-otp-submit:hover {
        background: #00c853;
        transform: translateY(-2px);
      }

      .vapt-otp-error {
        margin-top: 15px;
        color: #ff5252;
        font-weight: 500;
        background: rgba(255, 0, 0, 0.1);
        padding: 10px;
        border-radius: 4px;
      }

      .vapt-resend {
        margin-top: 20px;
        display: block;
        color: rgba(255, 255, 255, 0.6);
        text-decoration: none;
        font-size: 14px;
      }

      .vapt-resend:hover {
        color: #fff;
      }
    </style>
    <div class="vapt-otp-overlay">
      <div class="vapt-otp-box">
        <div style="font-size: 40px; margin-bottom: 20px;">🛡️</div>
        <h2><?php _e('Identity Verification', 'vapt-builder'); ?></h2>
        <p><?php _e('Enter the 6-digit code sent to your Email.', 'vapt-builder'); ?></p>
        <form method="POST" action="">
          <?php wp_nonce_field('vapt_verify_otp', 'vapt_otp_nonce'); ?>
          <input type="text" name="vapt_email_otp" class="vapt-otp-input" placeholder="000000" maxlength="6" autofocus required autocomplete="one-time-code" />
          <button type="submit" name="vapt_otp_submit" class="vapt-otp-submit"><?php _e('Verify & Access', 'vapt-builder'); ?></button>
        </form>
        <?php
        if (isset($_POST['vapt_otp_submit'])) {
          echo '<div class="vapt-otp-error">' . __('Invalid or expired code. Please try again.', 'vapt-builder') . '</div>';
        }
        if (isset($_GET['resend_otp'])) {
          echo '<div style="margin-top:10px; color:#00e676;">' . __('A new code has been sent!', 'vapt-builder') . '</div>';
        }
        ?>
        <a href="<?php echo esc_url(add_query_arg('resend_otp', '1')); ?>" class="vapt-resend"><?php _e('Didn\'t receive the code? Resend', 'vapt-builder'); ?></a>
      </div>
    </div>
<?php
  }
}
