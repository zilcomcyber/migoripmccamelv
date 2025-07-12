<?php
require_once __DIR__ . '/../config.php';

/**
 * Password Recovery and Account Activation System
 */

/**
 * Generate secure token for password reset or account activation
 */
function generate_secure_token($length = 64) {
    return bin2hex(random_bytes($length / 2));
}

/**
 * Send password reset email
 */
function send_password_reset_email($email) {
    global $pdo;
    
    try {
        // Check if admin exists and is active
        $stmt = $pdo->prepare("SELECT id, name, email, is_active FROM admins WHERE email = ?");
        $stmt->execute([$email]);
        $admin = $stmt->fetch();
        
        if (!$admin) {
            return ['success' => false, 'message' => 'No account found with that email address.'];
        }
        
        if (!$admin['is_active']) {
            return ['success' => false, 'message' => 'Your account is deactivated. Please contact the system administrator.'];
        }
        
        // Generate reset token
        $token = generate_secure_token();
        $expires_at = date('Y-m-d H:i:s', strtotime('+1 hour')); // Token expires in 1 hour
        
        // Store token in database
        $stmt = $pdo->prepare("INSERT INTO password_reset_tokens (admin_id, token, expires_at, used) VALUES (?, ?, ?, 0) 
                              ON DUPLICATE KEY UPDATE token = VALUES(token), expires_at = VALUES(expires_at), used = 0, created_at = NOW()");
        $stmt->execute([$admin['id'], $token, $expires_at]);
        
        // Create reset link
        $reset_link = BASE_URL . "resetPassword.php?token=" . $token;
        
        // Send email
        $subject = "Password Reset Request - " . APP_NAME;
        $message = get_password_reset_email_template($admin['name'], $reset_link);
        
        $result = send_system_email($admin['email'], $subject, $message);
        
        if ($result) {
            log_activity('password_reset_requested', "Password reset requested for email: " . $email, $admin['id']);
            return ['success' => true, 'message' => 'Password reset instructions have been sent to your email address.'];
        } else {
            return ['success' => false, 'message' => 'Failed to send password reset email. Please try again later.'];
        }
        
    } catch (Exception $e) {
        error_log("Password reset error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred. Please try again later.'];
    }
}

/**
 * Verify reset token and allow password change
 */
function verify_reset_token($token) {
    global $pdo;
    
    try {
        $stmt = $pdo->prepare("
            SELECT prt.*, a.id as admin_id, a.name, a.email 
            FROM password_reset_tokens prt 
            JOIN admins a ON prt.admin_id = a.id 
            WHERE prt.token = ? AND prt.expires_at > NOW() AND prt.used = 0 AND a.is_active = 1
        ");
        $stmt->execute([$token]);
        return $stmt->fetch();
    } catch (Exception $e) {
        error_log("Token verification error: " . $e->getMessage());
        return false;
    }
}

/**
 * Reset password using valid token
 */
function reset_password_with_token($token, $new_password) {
    global $pdo;
    
    try {
        $pdo->beginTransaction();
        
        // Verify token
        $token_data = verify_reset_token($token);
        if (!$token_data) {
            return ['success' => false, 'message' => 'Invalid or expired reset token.'];
        }
        
        // Hash new password
        $password_hash = password_hash($new_password, PASSWORD_DEFAULT);
        
        // Update password
        $stmt = $pdo->prepare("UPDATE admins SET password_hash = ?, updated_at = NOW() WHERE id = ?");
        $stmt->execute([$password_hash, $token_data['admin_id']]);
        
        // Mark token as used
        $stmt = $pdo->prepare("UPDATE password_reset_tokens SET used = 1, used_at = NOW() WHERE token = ?");
        $stmt->execute([$token]);
        
        $pdo->commit();
        
        log_activity('password_reset_completed', "Password reset completed for admin ID: " . $token_data['admin_id'], $token_data['admin_id']);
        
        return ['success' => true, 'message' => 'Your password has been successfully reset. You can now login with your new password.'];
        
    } catch (Exception $e) {
        $pdo->rollBack();
        error_log("Password reset completion error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred while resetting your password. Please try again.'];
    }
}

/**
 * Send account activation email
 */
function send_activation_email($admin_id) {
    global $pdo;
    
    try {
        // Get admin details
        $stmt = $pdo->prepare("SELECT id, name, email, is_active FROM admins WHERE id = ?");
        $stmt->execute([$admin_id]);
        $admin = $stmt->fetch();
        
        if (!$admin) {
            return ['success' => false, 'message' => 'Admin not found.'];
        }
        
        // Generate activation token
        $token = generate_secure_token();
        $expires_at = date('Y-m-d H:i:s', strtotime('+24 hours')); // Token expires in 24 hours
        
        // Store token in database
        $stmt = $pdo->prepare("INSERT INTO account_activation_tokens (admin_id, token, expires_at, used) VALUES (?, ?, ?, 0) 
                              ON DUPLICATE KEY UPDATE token = VALUES(token), expires_at = VALUES(expires_at), used = 0, created_at = NOW()");
        $stmt->execute([$admin['id'], $token, $expires_at]);
        
        // Create activation link
        $activation_link = BASE_URL . "activateAccount.php?token=" . $token;
        
        // Send email
        $subject = "Account Activation Required - " . APP_NAME;
        $message = get_activation_email_template($admin['name'], $activation_link);
        
        $result = send_system_email($admin['email'], $subject, $message);
        
        if ($result) {
            log_activity('activation_email_sent', "Activation email sent to admin ID: " . $admin_id, $admin_id);
            return ['success' => true, 'message' => 'Activation email sent successfully.'];
        } else {
            return ['success' => false, 'message' => 'Failed to send activation email.'];
        }
        
    } catch (Exception $e) {
        error_log("Activation email error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred while sending activation email.'];
    }
}

/**
 * Activate account using token
 */
function activate_account_with_token($token) {
    global $pdo;
    
    try {
        $pdo->beginTransaction();
        
        // Verify token
        $stmt = $pdo->prepare("
            SELECT aat.*, a.id as admin_id, a.name, a.email 
            FROM account_activation_tokens aat 
            JOIN admins a ON aat.admin_id = a.id 
            WHERE aat.token = ? AND aat.expires_at > NOW() AND aat.used = 0
        ");
        $stmt->execute([$token]);
        $token_data = $stmt->fetch();
        
        if (!$token_data) {
            return ['success' => false, 'message' => 'Invalid or expired activation token.'];
        }
        
        // Activate account
        $stmt = $pdo->prepare("UPDATE admins SET is_active = 1, email_verified = 1, updated_at = NOW() WHERE id = ?");
        $stmt->execute([$token_data['admin_id']]);
        
        // Mark token as used
        $stmt = $pdo->prepare("UPDATE account_activation_tokens SET used = 1, used_at = NOW() WHERE token = ?");
        $stmt->execute([$token]);
        
        $pdo->commit();
        
        log_activity('account_activated', "Account activated for admin ID: " . $token_data['admin_id'], $token_data['admin_id']);
        
        return ['success' => true, 'message' => 'Your account has been successfully activated. You can now login.'];
        
    } catch (Exception $e) {
        $pdo->rollBack();
        error_log("Account activation error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred while activating your account. Please try again.'];
    }
}

/**
 * Send reactivation notification email
 */
function send_reactivation_email($admin_id) {
    global $pdo;
    
    try {
        // Get admin details
        $stmt = $pdo->prepare("SELECT id, name, email FROM admins WHERE id = ?");
        $stmt->execute([$admin_id]);
        $admin = $stmt->fetch();
        
        if (!$admin) {
            return ['success' => false, 'message' => 'Admin not found.'];
        }
        
        // Send email
        $subject = "Account Reactivated - " . APP_NAME;
        $message = get_reactivation_email_template($admin['name']);
        
        $result = send_system_email($admin['email'], $subject, $message);
        
        if ($result) {
            log_activity('reactivation_email_sent', "Reactivation email sent to admin ID: " . $admin_id, $admin_id);
            return ['success' => true, 'message' => 'Reactivation email sent successfully.'];
        } else {
            return ['success' => false, 'message' => 'Failed to send reactivation email.'];
        }
        
    } catch (Exception $e) {
        error_log("Reactivation email error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred while sending reactivation email.'];
    }
}

/**
 * Enhanced email sending function
 */
function send_system_email($to_email, $subject, $message, $from_admin_id = null) {
    try {
        // Email headers
        $from_email = 'noreply@migoricounty.go.ke';
        $from_name = 'Migori County PMC System';

        $headers = [
            'From' => "$from_name <$from_email>",
            'Reply-To' => $from_email,
            'Content-Type' => 'text/html; charset=UTF-8',
            'X-Mailer' => 'Migori County PMC System',
            'MIME-Version' => '1.0'
        ];

        $header_string = '';
        foreach ($headers as $key => $value) {
            $header_string .= "$key: $value\r\n";
        }

        // Send email
        $result = mail($to_email, $subject, $message, $header_string);

        // Log email attempt
        log_activity('system_email_sent', "System email sent to $to_email with subject: $subject", $from_admin_id);

        return $result;

    } catch (Exception $e) {
        error_log("System email sending error: " . $e->getMessage());
        return false;
    }
}

/**
 * Email Templates
 */

function get_password_reset_email_template($admin_name, $reset_link) {
    return "
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset='UTF-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1.0'>
        <title>Password Reset Request</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #003366, #0066cc); color: white; padding: 30px 20px; text-align: center; border-radius: 10px 10px 0 0; margin: -20px -20px 30px -20px; }
            .header h1 { margin: 0; font-size: 24px; }
            .content { margin: 20px 0; }
            .reset-button { display: inline-block; background: #0066cc; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }
            .reset-button:hover { background: #0052a3; }
            .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #666; text-align: center; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h1>Password Reset Request</h1>
                <p>Migori County PMC System</p>
            </div>
            
            <div class='content'>
                <p>Hello <strong>$admin_name</strong>,</p>
                
                <p>We received a request to reset your password for your Migori County PMC System administrator account.</p>
                
                <p>To reset your password, click the button below:</p>
                
                <div style='text-align: center;'>
                    <a href='$reset_link' class='reset-button'>Reset My Password</a>
                </div>
                
                <p>Or copy and paste this link into your browser:</p>
                <p style='word-break: break-all; background: #f8f9fa; padding: 10px; border-radius: 5px;'>$reset_link</p>
                
                <div class='warning'>
                    <strong>Security Notice:</strong>
                    <ul style='margin: 10px 0;'>
                        <li>This link will expire in 1 hour for security reasons</li>
                        <li>If you didn't request this password reset, please ignore this email</li>
                        <li>Never share this link with anyone</li>
                    </ul>
                </div>
                
                <p>If you're having trouble with the button above, contact your system administrator.</p>
            </div>
            
            <div class='footer'>
                <p>This is an automated message from Migori County PMC System.<br>
                Please do not reply to this email.</p>
                <p>&copy; " . date('Y') . " Migori County Government. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    ";
}

function get_activation_email_template($admin_name, $activation_link) {
    return "
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset='UTF-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1.0'>
        <title>Account Activation Required</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #28a745, #20c997); color: white; padding: 30px 20px; text-align: center; border-radius: 10px 10px 0 0; margin: -20px -20px 30px -20px; }
            .header h1 { margin: 0; font-size: 24px; }
            .content { margin: 20px 0; }
            .activate-button { display: inline-block; background: #28a745; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }
            .activate-button:hover { background: #218838; }
            .info-box { background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #666; text-align: center; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h1>Welcome to PMC System!</h1>
                <p>Account Activation Required</p>
            </div>
            
            <div class='content'>
                <p>Hello <strong>$admin_name</strong>,</p>
                
                <p>Your administrator account has been created for the Migori County PMC System. To activate your account and start using the system, please click the activation button below:</p>
                
                <div style='text-align: center;'>
                    <a href='$activation_link' class='activate-button'>Activate My Account</a>
                </div>
                
                <p>Or copy and paste this link into your browser:</p>
                <p style='word-break: break-all; background: #f8f9fa; padding: 10px; border-radius: 5px;'>$activation_link</p>
                
                <div class='info-box'>
                    <strong>Important Information:</strong>
                    <ul style='margin: 10px 0;'>
                        <li>This activation link will expire in 24 hours</li>
                        <li>You must activate your account before you can login</li>
                        <li>After activation, you can login with your assigned credentials</li>
                    </ul>
                </div>
                
                <p>Once your account is activated, you'll have access to the PMC System dashboard where you can manage projects, view reports, and perform your assigned administrative tasks.</p>
                
                <p>If you have any questions or need assistance, please contact your system administrator.</p>
            </div>
            
            <div class='footer'>
                <p>This is an automated message from Migori County PMC System.<br>
                Please do not reply to this email.</p>
                <p>&copy; " . date('Y') . " Migori County Government. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    ";
}

function get_reactivation_email_template($admin_name) {
    $login_url = BASE_URL . "login.php";
    
    return "
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset='UTF-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1.0'>
        <title>Account Reactivated</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f4f4f4; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .header { background: linear-gradient(135deg, #17a2b8, #007bff); color: white; padding: 30px 20px; text-align: center; border-radius: 10px 10px 0 0; margin: -20px -20px 30px -20px; }
            .header h1 { margin: 0; font-size: 24px; }
            .content { margin: 20px 0; }
            .login-button { display: inline-block; background: #007bff; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }
            .login-button:hover { background: #0056b3; }
            .success-box { background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #666; text-align: center; }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='header'>
                <h1>Account Reactivated</h1>
                <p>Welcome Back to PMC System</p>
            </div>
            
            <div class='content'>
                <p>Hello <strong>$admin_name</strong>,</p>
                
                <div class='success-box'>
                    <strong>Good News!</strong> Your administrator account for the Migori County PMC System has been reactivated.
                </div>
                
                <p>You can now access the system again with your existing login credentials. All your previous data and settings have been preserved.</p>
                
                <div style='text-align: center;'>
                    <a href='$login_url' class='login-button'>Login to PMC System</a>
                </div>
                
                <p><strong>What you can do now:</strong></p>
                <ul>
                    <li>Access the PMC System dashboard</li>
                    <li>Manage your assigned projects</li>
                    <li>View and respond to citizen feedback</li>
                    <li>Generate reports and analytics</li>
                    <li>Perform all your administrative tasks</li>
                </ul>
                
                <p>If you experience any issues logging in or need assistance, please contact your system administrator.</p>
                
                <p>Thank you for your continued service to Migori County.</p>
            </div>
            
            <div class='footer'>
                <p>This is an automated message from Migori County PMC System.<br>
                Please do not reply to this email.</p>
                <p>&copy; " . date('Y') . " Migori County Government. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    ";
}

?>
