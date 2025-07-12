<?php
require_once '../config.php';
require_once '../includes/functions.php';
require_once '../includes/projectStepsTemplates.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_response(['success' => false, 'message' => 'Invalid request method'], 405);
}

try {
    $input = json_decode(file_get_contents('php://input'), true);
    $department_id = intval($input['department_id'] ?? 0);
    
    if ($department_id <= 0) {
        json_response(['success' => false, 'message' => 'Invalid department ID']);
    }
    
    // Get department name
    $stmt = $pdo->prepare("SELECT name FROM departments WHERE id = ?");
    $stmt->execute([$department_id]);
    $department = $stmt->fetch();
    
    if (!$department) {
        json_response(['success' => false, 'message' => 'Department not found']);
    }
    
    $steps = get_default_project_steps($department['name']);
    
    json_response(['success' => true, 'steps' => $steps]);
    
} catch (Exception $e) {
    error_log("Get default steps error: " . $e->getMessage());
    json_response(['success' => false, 'message' => 'An error occurred while fetching default steps']);
}
?>
