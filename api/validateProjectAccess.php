<?php
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

// Require authentication
require_admin();

header('Content-Type: application/json');

$project_id = (int)($_GET['project_id'] ?? $_POST['project_id'] ?? 0);
$action = $_GET['action'] ?? $_POST['action'] ?? '';

if (!$project_id) {
    http_response_code(400);
    echo json_encode(['error' => 'Project ID required']);
    exit;
}

$current_admin = get_current_admin();

// Super admin has access to all projects
if ($current_admin['role'] === 'super_admin') {
    echo json_encode(['access' => true, 'reason' => 'super_admin']);
    exit;
}

// Check ownership
$has_access = owns_project($project_id, $current_admin['id']);

if (!$has_access) {
    // Log unauthorized access attempt
    security_log('api_unauthorized_project_access', $current_admin['id'], [
        'project_id' => $project_id,
        'action' => $action,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
}

echo json_encode([
    'access' => $has_access,
    'reason' => $has_access ? 'owner' : 'not_owner'
]);
