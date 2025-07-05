
<?php
require_once 'config.php';
require_once 'includes/projectProgressCalculator.php';

try {
    // Get all projects
    $stmt = $pdo->query("SELECT id, project_name FROM projects");
    $projects = $stmt->fetchAll();
    
    echo "Updating progress for " . count($projects) . " projects...\n";
    
    foreach ($projects as $project) {
        echo "Updating project ID {$project['id']}: {$project['project_name']}... ";
        
        // Use direct calculation and update
        $new_progress = calculate_complete_project_progress($project['id']);
        
        // Update the projects table directly
        $stmt = $pdo->prepare("UPDATE projects SET progress_percentage = ?, updated_at = NOW() WHERE id = ?");
        $update_result = $stmt->execute([$new_progress, $project['id']]);
        
        if ($update_result) {
            // Also run the full progress update function for status changes
            $result = update_project_progress_and_status($project['id'], false, false);
            
            if ($result['success']) {
                echo "Progress: {$result['progress']}%, Status: {$result['status']}\n";
            } else {
                echo "Progress: {$new_progress}%, Status update failed: {$result['message']}\n";
            }
        } else {
            echo "Failed to update progress in database\n";
        }
    }
    
    echo "Done!\n";
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
?>
