<?php
require_once '../config.php';
require_once '../includes/functions.php';

header('Content-Type: application/json');

try {
    $filters = [];
    
    if (isset($_GET['search'])) {
        $filters['search'] = $_GET['search'];
    }
    
    if (isset($_GET['status']) && !empty($_GET['status'])) {
        $filters['status'] = $_GET['status'];
    }
    
    if (isset($_GET['ward']) && !empty($_GET['ward'])) {
        $filters['ward'] = $_GET['ward'];
    }
    
    if (isset($_GET['department']) && !empty($_GET['department'])) {
        $filters['department'] = $_GET['department'];
    }
    
    if (isset($_GET['year']) && !empty($_GET['year'])) {
        $filters['year'] = $_GET['year'];
    }

    $projects = get_projects($filters);

    echo json_encode([
        'success' => true,
        'projects' => $projects,
        'count' => count($projects)
    ]);

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => 'Error loading projects: ' . $e->getMessage()
    ]);
}
?>
