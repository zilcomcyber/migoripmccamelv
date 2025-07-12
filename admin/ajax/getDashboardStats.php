<?php
require_once '../../config.php';
require_once '../../includes/functions.php';
require_once '../../includes/auth.php';

// Set JSON content type
header('Content-Type: application/json');

// Ensure admin is logged in
if (!isset($_SESSION['admin_logged_in']) || !$_SESSION['admin_logged_in']) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized access']);
    exit;
}

try {
    // Get current admin for role-based filtering
    $current_admin = get_current_admin();
    
    // Role-based filtering
    $role_filter = "";
    $role_params = [];
    
    if ($current_admin['role'] !== 'super_admin') {
        $role_filter = " WHERE created_by = ?";
        $role_params = [$current_admin['id']];
    }
    
    // Get project statistics
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $role_filter);
    $stmt->execute($role_params);
    $total_projects = (int)$stmt->fetchColumn();
    
    $ongoing_filter = $role_filter ? $role_filter . " AND status = ?" : " WHERE status = ?";
    $ongoing_params = $role_filter ? array_merge($role_params, ['ongoing']) : ['ongoing'];
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $ongoing_filter);
    $stmt->execute($ongoing_params);
    $ongoing_projects = (int)$stmt->fetchColumn();
    
    $completed_filter = $role_filter ? $role_filter . " AND status = ?" : " WHERE status = ?";
    $completed_params = $role_filter ? array_merge($role_params, ['completed']) : ['completed'];
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $completed_filter);
    $stmt->execute($completed_params);
    $completed_projects = (int)$stmt->fetchColumn();
    
    $planning_filter = $role_filter ? $role_filter . " AND status = ?" : " WHERE status = ?";
    $planning_params = $role_filter ? array_merge($role_params, ['planning']) : ['planning'];
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $planning_filter);
    $stmt->execute($planning_params);
    $planning_projects = (int)$stmt->fetchColumn();
    
    // Get this month's projects
    $this_month_filter = $role_filter ? $role_filter . " AND DATE_FORMAT(created_at, '%Y-%m') = DATE_FORMAT(NOW(), '%Y-%m')" : " WHERE DATE_FORMAT(created_at, '%Y-%m') = DATE_FORMAT(NOW(), '%Y-%m')";
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $this_month_filter);
    $stmt->execute($role_params);
    $this_month_projects = (int)$stmt->fetchColumn();
    
    // Get feedback statistics
    if ($current_admin['role'] === 'super_admin') {
        $total_feedback = $pdo->query("SELECT COUNT(*) FROM feedback")->fetchColumn();
        $pending_feedback = $pdo->query("SELECT COUNT(*) FROM feedback WHERE status = 'pending'")->fetchColumn();
        $responded_feedback = $pdo->query("SELECT COUNT(*) FROM feedback WHERE status = 'responded'")->fetchColumn();
    } else {
        // Filter feedback for projects owned by current admin
        $stmt = $pdo->prepare("
            SELECT COUNT(*) FROM feedback f 
            JOIN projects p ON f.project_id = p.id 
            WHERE p.created_by = ?
        ");
        $stmt->execute([$current_admin['id']]);
        $total_feedback = $stmt->fetchColumn();
        
        $stmt = $pdo->prepare("
            SELECT COUNT(*) FROM feedback f 
            JOIN projects p ON f.project_id = p.id 
            WHERE p.created_by = ? AND f.status = 'pending'
        ");
        $stmt->execute([$current_admin['id']]);
        $pending_feedback = $stmt->fetchColumn();
        
        $stmt = $pdo->prepare("
            SELECT COUNT(*) FROM feedback f 
            JOIN projects p ON f.project_id = p.id 
            WHERE p.created_by = ? AND f.status = 'responded'
        ");
        $stmt->execute([$current_admin['id']]);
        $responded_feedback = $stmt->fetchColumn();
    }
    
    $stats = [
        'total_projects' => (int)$total_projects,
        'ongoing_projects' => (int)$ongoing_projects,
        'completed_projects' => (int)$completed_projects,
        'planning_projects' => (int)$planning_projects,
        'this_month_projects' => (int)$this_month_projects,
        'total_feedback' => (int)$total_feedback,
        'pending_feedback' => (int)$pending_feedback,
        'responded_feedback' => (int)$responded_feedback
    ];
    
    echo json_encode($stats);
    
} catch (Exception $e) {
    error_log("Dashboard stats error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Failed to fetch statistics']);
}
?>
