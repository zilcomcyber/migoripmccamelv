<?php
require_once '../../config.php';
require_once '../../includes/auth.php';
require_once '../../includes/rbac.php';

// Ensure admin is logged in and has permission
require_admin();
if (!has_permission('manage_roles')) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Access denied']);
    exit;
}

header('Content-Type: application/json');

$admin_id = filter_input(INPUT_GET, 'admin_id', FILTER_VALIDATE_INT);

if (!$admin_id) {
    echo json_encode(['success' => false, 'message' => 'Invalid admin ID']);
    exit;
}

try {
    $permissions = getAdminPermissions($admin_id);
    echo json_encode([
        'success' => true, 
        'permissions' => $permissions
    ]);
} catch (Exception $e) {
    error_log("Get admin permissions API error: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Failed to get permissions']);
}
?>
