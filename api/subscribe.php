<?php
require_once '../config.php';
require_once '../includes/functions.php';
require_once '../includes/projectSubscriptions.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

// Rate limiting
if (!check_rate_limit('subscribe', 3, 300)) { // 3 attempts per 5 minutes
    http_response_code(429);
    echo json_encode(['success' => false, 'message' => 'Too many subscription attempts. Please try again later.']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);

if (!$input) {
    $input = $_POST;
}

$project_id = (int)($input['project_id'] ?? 0);
$email = trim($input['email'] ?? '');

if (!$project_id || !$email) {
    echo json_encode(['success' => false, 'message' => 'Project ID and email are required']);
    exit;
}

// Verify project exists and is published
$project = get_project_by_id($project_id);
if (!$project) {
    echo json_encode(['success' => false, 'message' => 'Project not found']);
    exit;
}

if ($project['visibility'] !== 'published') {
    echo json_encode(['success' => false, 'message' => 'This project is not available for subscriptions']);
    exit;
}

try {
    $subscription_manager = new ProjectSubscriptionManager($pdo);
    $result = $subscription_manager->subscribe(
        $project_id, 
        $email,
        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    );
    
    echo json_encode($result);
    
} catch (Exception $e) {
    error_log("Subscription API error: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Service temporarily unavailable. Please try again later.']);
}
?>
