<?php
require_once 'projectProgressCalculator.php';

//Update project status based on its steps - DEPRECATED, use new progress calculator
function update_project_status_based_on_steps($project_id) {
    // Use new comprehensive progress calculation system
    return update_project_progress_and_status($project_id);
}

/**
 * Update step status and trigger project status update
 */
function update_step_status($step_id, $new_status, $start_date = null, $end_date = null, $notes = null) {
    // Use new comprehensive progress calculation system
    return update_step_status_with_progress_recalc($step_id, $new_status, $start_date, $end_date, $notes);
}

/**
 * Update all project statuses based on their steps
 */
function update_all_project_statuses() {
    global $pdo;

    try {
        $stmt = $pdo->query("SELECT DISTINCT project_id FROM project_steps");
        $project_ids = $stmt->fetchAll(PDO::FETCH_COLUMN);

        foreach ($project_ids as $project_id) {
            update_project_status_based_on_steps($project_id);
        }

        return true;
    } catch (Exception $e) {
        error_log("Error updating all project statuses: " . $e->getMessage());
        return false;
    }
}
?>