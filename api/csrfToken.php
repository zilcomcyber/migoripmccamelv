<?php
require_once '../config.php';
require_once '../includes/functions.php';

header('Content-Type: application/json');

try {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    // Generate a fresh CSRF token
    unset($_SESSION['csrf_token'], $_SESSION['csrf_token_time']);
    $token = generate_csrf_token();

    json_response([
        'success' => true,
        'token' => $token
    ]);

} catch (Exception $e) {
    error_log("CSRF token refresh error: " . $e->getMessage());
    json_response(['success' => false, 'message' => 'Failed to refresh token'], 500);
}
?>
