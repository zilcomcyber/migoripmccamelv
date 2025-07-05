<?php
//Step-based progress calculation functions
// Calculate project progress based on step states (planning=0%, in_progress=50%, completed=100%)
// This function calculates ONLY the step component (50% of total progress)
function calculate_step_progress($project_id) {
    global $pdo;

    try {
        // Get all steps for this project
        $stmt = $pdo->prepare("SELECT status FROM project_steps WHERE project_id = ?");
        $stmt->execute([$project_id]);
        $steps = $stmt->fetchAll(PDO::FETCH_COLUMN);

        if (empty($steps)) {
            return 0;
        }

        $total_steps = count($steps);
        $step_score = 0;

        foreach ($steps as $status) {
            switch ($status) {
                case 'pending':
                case 'planning':
                    $step_score += 0; // 0% contribution
                    break;
                case 'in_progress':
                    $step_score += 0.5; // 50% contribution
                    break;
                case 'completed':
                    $step_score += 1; // 100% contribution
                    break;
            }
        }

        // Return step progress as percentage (this represents 50% of total project progress)
        return round(($step_score / $total_steps) * 100, 2);

    } catch (Exception $e) {
        error_log("Calculate step progress error: " . $e->getMessage());
        return 0;
    }
}
// Update project progress based on step progress calculation
function complete_step($step_id) {
    require_once 'projectProgressCalculator.php';
    return update_step_status_with_progress_recalc($step_id, 'completed');
}

// Mark step as incomplete
function incomplete_step($step_id) {
    require_once 'projectProgressCalculator.php';
    return update_step_status_with_progress_recalc($step_id, 'pending');
}

/**
 * Mark step as in progress
 */
function mark_step_in_progress($step_id) {
    require_once 'projectProgressCalculator.php';
    return update_step_status_with_progress_recalc($step_id, 'in_progress');
}
?>