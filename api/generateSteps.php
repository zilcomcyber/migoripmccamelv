<?php
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';
require_once '../includes/stepProgress.php';

// Require admin authentication
require_admin();

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_response(['success' => false, 'message' => 'Method not allowed'], 405);
}

if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
    json_response(['success' => false, 'message' => 'Invalid security token'], 403);
}

try {
    $project_id = intval($_POST['project_id'] ?? 0);

    if ($project_id <= 0) {
        json_response(['success' => false, 'message' => 'Invalid project ID']);
    }

    // Check if project exists
    $stmt = $pdo->prepare("SELECT p.id, p.project_name, d.name as department_name 
                          FROM projects p 
                          JOIN departments d ON p.department_id = d.id 
                          WHERE p.id = ?");
    $stmt->execute([$project_id]);
    $project = $stmt->fetch();

    if (!$project) {
        json_response(['success' => false, 'message' => 'Project not found']);
    }

    // Check if steps already exist
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM project_steps WHERE project_id = ?");
    $stmt->execute([$project_id]);
    $existing_steps = $stmt->fetchColumn();

    if ($existing_steps > 0) {
        json_response(['success' => false, 'message' => 'Project already has steps defined']);
    }

    // Create steps based on department
    $result = create_project_steps($project_id, $project['department_name']);

    if ($result['success']) {
        // Update project progress
        update_project_progress($project_id);
        json_response(['success' => true, 'message' => 'Project steps generated successfully']);
    } else {
        json_response(['success' => false, 'message' => $result['message']]);
    }

} catch (Exception $e) {
    error_log("Generate steps error: " . $e->getMessage());
    json_response(['success' => false, 'message' => 'Unable to generate project steps. Please try again.'], 500);
}
?>