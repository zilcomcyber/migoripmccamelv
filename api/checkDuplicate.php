
<?php
require_once '../config.php';
require_once '../includes/auth.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);

if (!isset($input['project_name']) || empty(trim($input['project_name']))) {
    echo json_encode(['exists' => false]);
    exit;
}

$project_name = trim($input['project_name']);

try {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects WHERE LOWER(project_name) = LOWER(?)");
    $stmt->execute([$project_name]);
    $count = $stmt->fetchColumn();
    
    echo json_encode(['exists' => $count > 0]);
} catch (Exception $e) {
    error_log("Duplicate check error: " . $e->getMessage());
    echo json_encode(['exists' => false, 'error' => 'Database error']);
}
?>
