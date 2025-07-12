<?php
require_once '../../config.php';
require_once '../../includes/auth.php';
require_once '../../includes/functions.php';
require_once '../../includes/passwordRecovery.php';

require_admin();
$current_admin = get_current_admin();

// Only super admin can send activation emails
if ($current_admin['role'] !== 'super_admin') {
    json_response(['success' => false, 'message' => 'Insufficient permissions'], 403);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_response(['success' => false, 'message' => 'Method not allowed'], 405);
}

// CSRF protection
if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
    json_response(['success' => false, 'message' => 'CSRF token validation failed'], 403);
}

$admin_id = sanitize_input($_POST['admin_id'] ?? '', 'int');

if (!$admin_id) {
    json_response(['success' => false, 'message' => 'Invalid admin ID']);
}

try {
    // Get admin details
    $stmt = $pdo->prepare("SELECT name, email, is_active, email_verified FROM admins WHERE id = ?");
    $stmt->execute([$admin_id]);
    $target_admin = $stmt->fetch();
    
    if (!$target_admin) {
        json_response(['success' => false, 'message' => 'Administrator not found']);
    }
    
    if ($target_admin['email_verified']) {
        json_response(['success' => false, 'message' => 'Administrator email is already verified']);
    }
    
    // Rate limiting
    if (!enhanced_rate_limit('send_activation_' . $admin_id, 3, 1800)) {
        json_response(['success' => false, 'message' => 'Too many activation emails sent. Please wait before trying again.']);
    }
    
    // Send activation email
    $result = send_activation_email($admin_id);
    
    if ($result['success']) {
        log_activity('activation_email_resent', "Manually sent activation email to {$target_admin['name']} ({$target_admin['email']})", $current_admin['id'], 'admin', $admin_id);
    }
    
    json_response($result);
    
} catch (Exception $e) {
    error_log("Send activation email error: " . $e->getMessage());
    json_response(['success' => false, 'message' => 'Failed to send activation email']);
}
?>
