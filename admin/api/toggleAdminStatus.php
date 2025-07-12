<?php
require_once '../../config.php';
require_once '../../includes/auth.php';
require_once '../../includes/functions.php';
require_once '../../includes/passwordRecovery.php';

require_admin();
$current_admin = get_current_admin();

// Only super admin can toggle admin status
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
$new_status = sanitize_input($_POST['status'] ?? '', 'int');

if (!$admin_id || !in_array($new_status, [0, 1])) {
    json_response(['success' => false, 'message' => 'Invalid parameters']);
}

// Prevent super admin from deactivating themselves
if ($admin_id == $current_admin['id']) {
    json_response(['success' => false, 'message' => 'You cannot change your own status']);
}

try {
    $pdo->beginTransaction();
    
    // Get current admin details
    $stmt = $pdo->prepare("SELECT name, email, is_active, role FROM admins WHERE id = ?");
    $stmt->execute([$admin_id]);
    $target_admin = $stmt->fetch();
    
    if (!$target_admin) {
        json_response(['success' => false, 'message' => 'Administrator not found']);
    }
    
    // Prevent deactivating super admins (they can only be activated if inactive)
    if ($target_admin['role'] === 'super_admin' && $new_status == 0) {
        json_response(['success' => false, 'message' => 'Super administrators cannot be deactivated']);
    }
    
    // Update admin status
    $stmt = $pdo->prepare("UPDATE admins SET is_active = ?, updated_at = NOW() WHERE id = ?");
    $stmt->execute([$new_status, $admin_id]);
    
    $status_text = $new_status ? 'activated' : 'deactivated';
    $action = $new_status ? 'admin_activated' : 'admin_deactivated';
    
    // Log the action
    log_activity($action, "Admin {$target_admin['name']} ({$target_admin['email']}) was $status_text", $current_admin['id'], 'admin', $admin_id);
    
    // Send reactivation email if admin was reactivated
    $email_sent = false;
    if ($new_status == 1 && $target_admin['is_active'] == 0) {
        $email_result = send_reactivation_email($admin_id);
        $email_sent = $email_result['success'];
    }
    
    $pdo->commit();
    
    $message = "Administrator {$target_admin['name']} has been $status_text successfully";
    if ($new_status == 1 && $email_sent) {
        $message .= ". Reactivation notification sent to {$target_admin['email']}";
    } elseif ($new_status == 1 && !$email_sent) {
        $message .= ". Reactivation notification could not be sent";
    }
    
    json_response([
        'success' => true, 
        'message' => $message,
        'new_status' => $new_status,
        'email_sent' => $email_sent
    ]);
    
} catch (Exception $e) {
    $pdo->rollBack();
    error_log("Toggle admin status error: " . $e->getMessage());
    json_response(['success' => false, 'message' => 'Failed to update administrator status']);
}
?>
