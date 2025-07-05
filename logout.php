<?php
require_once 'config.php';
require_once 'includes/auth.php';

// Initialize session properly
init_secure_session();

// Log the logout activity if user is logged in
if (is_logged_in()) {
    $current_admin = get_current_admin();
    if ($current_admin) {
        security_log('admin_logout', $current_admin['id'], [
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ]);
    }
}

// Use the proper logout function
logout_user();

// Add cache control headers to prevent caching
header("Cache-Control: no-cache, no-store, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

// Redirect to login page with logout confirmation
header("Location: login.php?logged_out=1");
exit();
?>
