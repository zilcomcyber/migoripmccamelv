<?php
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

// Check if user is logged in as admin
if (!is_admin_logged_in()) {
    json_response(['success' => false, 'message' => 'Unauthorized'], 401);
}

header('Content-Type: application/json');

try {
    // Fetch all active templates with prepared statement
    $stmt = $pdo->prepare("SELECT id, name, subject, content, category 
                          FROM feedback_templates 
                          WHERE is_active = 1 
                          ORDER BY category, name");
    $stmt->execute();
    $templates = $stmt->fetchAll(PDO::FETCH_ASSOC);

    json_response([
        'success' => true,
        'templates' => $templates
    ]);

} catch (PDOException $e) {
    error_log("Database error fetching templates: " . $e->getMessage());
    json_response([
        'success' => false,
        'message' => 'Failed to load templates'
    ], 500);
    
} catch (Exception $e) {
    error_log("Unexpected error fetching templates: " . $e->getMessage());
    json_response([
        'success' => false,
        'message' => 'An unexpected error occurred'
    ], 500);
}