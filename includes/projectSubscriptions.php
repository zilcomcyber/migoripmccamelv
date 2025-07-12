<?php
/**
 * Project Subscription Management System
 * Handles email subscriptions for project updates
 */

class ProjectSubscriptionManager {
    private $pdo;
    
    public function __construct($pdo) {
        $this->pdo = $pdo;
    }
    
    /**
     * Subscribe user to project updates
     */
    public function subscribe($project_id, $email, $ip_address = null, $user_agent = null) {
        try {
            // Validate email
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                return ['success' => false, 'message' => 'Please enter a valid email address'];
            }
            
            // Check if already subscribed
            $stmt = $this->pdo->prepare("SELECT id, is_active, email_verified FROM project_subscriptions WHERE project_id = ? AND email = ?");
            $stmt->execute([$project_id, $email]);
            $existing = $stmt->fetch();
            
            if ($existing) {
                if ($existing['is_active']) {
                    return ['success' => false, 'message' => 'You are already subscribed to updates for this project'];
                } else {
                    // Reactivate subscription
                    $stmt = $this->pdo->prepare("UPDATE project_subscriptions SET is_active = 1, subscribed_at = NOW() WHERE id = ?");
                    $stmt->execute([$existing['id']]);
                    return ['success' => true, 'message' => 'Your subscription has been reactivated'];
                }
            }
            
            // Create new subscription
            $subscription_token = bin2hex(random_bytes(32));
            $verification_token = bin2hex(random_bytes(32));
            
            $stmt = $this->pdo->prepare("
                INSERT INTO project_subscriptions 
                (project_id, email, subscription_token, verification_token, ip_address, user_agent) 
                VALUES (?, ?, ?, ?, ?, ?)
            ");
            
            $result = $stmt->execute([
                $project_id, 
                $email, 
                $subscription_token, 
                $verification_token,
                $ip_address ?: ($_SERVER['REMOTE_ADDR'] ?? 'unknown'),
                $user_agent ?: ($_SERVER['HTTP_USER_AGENT'] ?? 'unknown')
            ]);
            
            if ($result) {
                // Send verification email
                $this->sendVerificationEmail($project_id, $email, $verification_token);
                
                log_activity('project_subscription', "New subscription for project ID: $project_id from email: $email");
                
                return [
                    'success' => true, 
                    'message' => 'Subscription successful! Please check your email to verify your subscription.',
                    'subscription_token' => $subscription_token
                ];
            }
            
            return ['success' => false, 'message' => 'Failed to create subscription. Please try again.'];
            
        } catch (Exception $e) {
            error_log("Subscription error: " . $e->getMessage());
            return ['success' => false, 'message' => 'An error occurred. Please try again later.'];
        }
    }
    
    /**
     * Verify email subscription
     */
    public function verifyEmail($verification_token) {
        try {
            $stmt = $this->pdo->prepare("
                UPDATE project_subscriptions 
                SET email_verified = 1, verification_token = NULL 
                WHERE verification_token = ? AND email_verified = 0
            ");
            
            $result = $stmt->execute([$verification_token]);
            
            if ($stmt->rowCount() > 0) {
                return ['success' => true, 'message' => 'Email verified successfully! You will now receive project updates.'];
            }
            
            return ['success' => false, 'message' => 'Invalid or expired verification token.'];
            
        } catch (Exception $e) {
            error_log("Email verification error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Verification failed. Please try again.'];
        }
    }
    
    /**
     * Unsubscribe from project updates
     */
    public function unsubscribe($subscription_token) {
        try {
            $stmt = $this->pdo->prepare("
                UPDATE project_subscriptions 
                SET is_active = 0, unsubscribed_at = NOW() 
                WHERE subscription_token = ? AND is_active = 1
            ");
            
            $result = $stmt->execute([$subscription_token]);
            
            if ($stmt->rowCount() > 0) {
                return ['success' => true, 'message' => 'You have been unsubscribed successfully.'];
            }
            
            return ['success' => false, 'message' => 'Invalid unsubscribe link or already unsubscribed.'];
            
        } catch (Exception $e) {
            error_log("Unsubscribe error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Unsubscribe failed. Please try again.'];
        }
    }
    
    /**
     * Get subscriber count for a project
     */
    public function getSubscriberCount($project_id) {
        try {
            $stmt = $this->pdo->prepare("
                SELECT COUNT(*) FROM project_subscriptions 
                WHERE project_id = ? AND is_active = 1 AND email_verified = 1
            ");
            $stmt->execute([$project_id]);
            return $stmt->fetchColumn();
        } catch (Exception $e) {
            error_log("Get subscriber count error: " . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Send verification email
     */
    private function sendVerificationEmail($project_id, $email, $verification_token) {
        // Get project details
        $stmt = $this->pdo->prepare("SELECT project_name FROM projects WHERE id = ?");
        $stmt->execute([$project_id]);
        $project = $stmt->fetch();
        
        if (!$project) return false;
        
        $verification_url = BASE_URL . "api/verifySubscription.php?token=" . urlencode($verification_token);
        
        $subject = "Verify Your Project Subscription - " . $project['project_name'];
        
        $message = $this->getEmailTemplate('verification', [
            'project_name' => $project['project_name'],
            'verification_url' => $verification_url,
            'project_url' => BASE_URL . "projectDetails.php?id=" . $project_id
        ]);
        
        return $this->sendEmail($email, $subject, $message);
    }
    
    /**
     * Send project update notification
     */
    public function sendProjectUpdate($project_id, $update_type, $update_details) {
        try {
            // Get verified subscribers
            $stmt = $this->pdo->prepare("
                SELECT * FROM project_subscriptions 
                WHERE project_id = ? AND is_active = 1 AND email_verified = 1
            ");
            $stmt->execute([$project_id]);
            $subscribers = $stmt->fetchAll();
            
            if (empty($subscribers)) return true;
            
            // Get project details
            $stmt = $this->pdo->prepare("SELECT * FROM projects WHERE id = ?");
            $stmt->execute([$project_id]);
            $project = $stmt->fetch();
            
            if (!$project) return false;
            
            $subject = $this->getUpdateSubject($update_type, $project['project_name']);
            
            $sent_count = 0;
            
            foreach ($subscribers as $subscriber) {
                $unsubscribe_url = BASE_URL . "api/unsubscribe.php?token=" . urlencode($subscriber['subscription_token']);
                
                $message = $this->getEmailTemplate('update', [
                    'project_name' => $project['project_name'],
                    'update_type' => $update_type,
                    'update_details' => $update_details,
                    'project_url' => BASE_URL . "projectDetails.php?id=" . $project_id,
                    'unsubscribe_url' => $unsubscribe_url,
                    'project_progress' => $project['progress_percentage'] ?? 0,
                    'project_status' => ucfirst($project['status'] ?? 'Unknown')
                ]);
                
                if ($this->sendEmail($subscriber['email'], $subject, $message)) {
                    $sent_count++;
                    
                    // Log notification
                    $this->logNotification($subscriber['id'], $project_id, $update_type, $subject, $update_details);
                    
                    // Update last notification sent
                    $stmt = $this->pdo->prepare("UPDATE project_subscriptions SET last_notification_sent = NOW() WHERE id = ?");
                    $stmt->execute([$subscriber['id']]);
                }
            }
            
            log_activity('project_update_notification', "Sent update notifications for project ID: $project_id to $sent_count subscribers");
            
            return true;
            
        } catch (Exception $e) {
            error_log("Send project update error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get email template
     */
    private function getEmailTemplate($type, $data) {
        $logo_url = BASE_URL . "migoriLogo.png";
        
        $header = "
        <div style='background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;'>
            <img src='$logo_url' alt='Migori County' style='height: 60px; margin-bottom: 15px;'>
            <h1 style='color: white; margin: 0; font-size: 24px; font-weight: bold;'>Migori County</h1>
            <p style='color: #e5f3ff; margin: 5px 0 0 0; font-size: 14px;'>Public Project Management</p>
        </div>";
        
        $footer = "
        <div style='background: #f8fafc; padding: 20px; text-align: center; border-radius: 0 0 10px 10px; margin-top: 20px;'>
            <p style='margin: 0; font-size: 12px; color: #64748b;'>
                <strong>Privacy Protection:</strong> Your email is secured with industry-standard encryption.<br>
                We use secure servers and never share your data with third parties.<br>
                You can unsubscribe anytime by clicking the unsubscribe link below.
            </p>
            <div style='margin-top: 15px; padding-top: 15px; border-top: 1px solid #e2e8f0;'>
                <p style='margin: 0; font-size: 11px; color: #94a3b8;'>
                    © " . date('Y') . " Migori County Government. All rights reserved.<br>
                    This email was sent from an automated system. Please do not reply to this email.
                </p>
            </div>
        </div>";
        
        if ($type === 'verification') {
            return "
            <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);'>
                $header
                <div style='padding: 30px;'>
                    <h2 style='color: #1f2937; margin-bottom: 20px;'>Verify Your Subscription</h2>
                    <p style='color: #4b5563; line-height: 1.6; margin-bottom: 20px;'>
                        Thank you for subscribing to updates for <strong>{$data['project_name']}</strong>.
                    </p>
                    <p style='color: #4b5563; line-height: 1.6; margin-bottom: 25px;'>
                        To complete your subscription and start receiving project updates, please verify your email address:
                    </p>
                    <div style='text-align: center; margin: 30px 0;'>
                        <a href='{$data['verification_url']}' style='background: #3b82f6; color: white; padding: 12px 30px; text-decoration: none; border-radius: 25px; font-weight: bold; display: inline-block;'>
                            Verify Email Address
                        </a>
                    </div>
                    <p style='color: #6b7280; font-size: 14px; line-height: 1.5;'>
                        If the button doesn't work, copy and paste this link in your browser:<br>
                        <a href='{$data['verification_url']}' style='color: #3b82f6; word-break: break-all;'>{$data['verification_url']}</a>
                    </p>
                </div>
                $footer
            </div>";
        }
        
        if ($type === 'update') {
            $update_icon = $this->getUpdateIcon($data['update_type']);
            
            return "
            <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);'>
                $header
                <div style='padding: 30px;'>
                    <div style='background: #f0f9ff; padding: 20px; border-radius: 8px; border-left: 4px solid #3b82f6; margin-bottom: 25px;'>
                        <h2 style='color: #1f2937; margin: 0 0 10px 0; display: flex; align-items: center;'>
                            $update_icon
                            Project Update: {$data['project_name']}
                        </h2>
                        <p style='color: #64748b; margin: 0; font-size: 14px;'>
                            Status: {$data['project_status']} | Progress: {$data['project_progress']}%
                        </p>
                    </div>
                    
                    <h3 style='color: #374151; margin-bottom: 15px;'>" . ucfirst(str_replace('_', ' ', $data['update_type'])) . "</h3>
                    
                    <div style='background: #f9fafb; padding: 20px; border-radius: 8px; margin-bottom: 25px;'>
                        <p style='color: #4b5563; line-height: 1.6; margin: 0;'>
                            {$data['update_details']}
                        </p>
                    </div>
                    
                    <div style='text-align: center; margin: 30px 0;'>
                        <a href='{$data['project_url']}' style='background: #10b981; color: white; padding: 12px 30px; text-decoration: none; border-radius: 25px; font-weight: bold; display: inline-block;'>
                            View Project Details
                        </a>
                    </div>
                    
                    <div style='text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb;'>
                        <p style='color: #6b7280; font-size: 13px; margin-bottom: 10px;'>
                            Don't want to receive these updates?
                        </p>
                        <a href='{$data['unsubscribe_url']}' style='color: #dc2626; font-size: 12px; text-decoration: underline;'>
                            Unsubscribe from this project
                        </a>
                    </div>
                </div>
                $footer
            </div>";
        }
        
        return '';
    }
    
    private function getUpdateIcon($update_type) {
        $icons = [
            'project_update' => '📋',
            'status_change' => '🔄',
            'completion' => '✅',
            'milestone' => '🎯'
        ];
        
        return '<span style="margin-right: 10px; font-size: 20px;">' . ($icons[$update_type] ?? '📋') . '</span>';
    }
    
    private function getUpdateSubject($update_type, $project_name) {
        $subjects = [
            'project_update' => "Project Update: $project_name",
            'status_change' => "Status Change: $project_name",
            'completion' => "Project Completed: $project_name",
            'milestone' => "Milestone Reached: $project_name"
        ];
        
        return $subjects[$update_type] ?? "Project Update: $project_name";
    }
    
    /**
     * Send email with proper headers
     */
    private function sendEmail($to_email, $subject, $message) {
        $headers = [
            'From' => 'Migori County PMC <hamisi@lakeside.co.ke>',
            'Reply-To' => 'hamisi@lakeside.co.ke',
            'Content-Type' => 'text/html; charset=UTF-8',
            'X-Mailer' => 'Migori County PMC System',
            'X-Priority' => '3',
            'MIME-Version' => '1.0'
        ];
        
        $header_string = '';
        foreach ($headers as $key => $value) {
            $header_string .= "$key: $value\r\n";
        }
        
        return mail($to_email, $subject, $message, $header_string);
    }
    
    /**
     * Log notification sent
     */
    private function logNotification($subscription_id, $project_id, $type, $subject, $message) {
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO subscription_notifications 
                (subscription_id, project_id, notification_type, subject, message) 
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->execute([$subscription_id, $project_id, $type, $subject, $message]);
        } catch (Exception $e) {
            error_log("Log notification error: " . $e->getMessage());
        }
    }
}
?>
