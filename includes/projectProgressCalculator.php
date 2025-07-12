<?php
/**
 * Project Progress Calculator
 * Implements step progress (50%) + financial progress (50%) calculation
 * with automatic status updates and proper edit behavior
 */

/**
 * Calculate complete project progress using step progress (50%) + financial progress (50%)
 */
function calculate_complete_project_progress($project_id) {
    global $pdo;

    try {
        // Get step progress (50% of total)
        $step_progress = calculate_step_progress_component($project_id);

        // Get financial progress (50% of total)
        $financial_progress = calculate_financial_progress_component($project_id);

        // Total progress
        $total_progress = $step_progress + $financial_progress;

        return min(100, max(0, round($total_progress, 2)));

    } catch (Exception $e) {
        error_log("Calculate complete project progress error: " . $e->getMessage());
        return 0;
    }
}

/**
 * Calculate step progress component (50% of total project progress)
 */
function calculate_step_progress_component($project_id) {
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
        $step_current_score = 0;

        // Calculate current score based on step statuses
        foreach ($steps as $status) {
            switch ($status) {
                case 'pending':
                    $step_current_score += 0; // 0 points
                    break;
                case 'in_progress':
                    $step_current_score += 1; // 1 point
                    break;
                case 'completed':
                case 'complete':
                    $step_current_score += 2; // 2 points
                    break;
            }
        }

        // Virtual total: each step can have maximum 2 points
        $step_virtual_total = $total_steps * 2;

        // Step progress is 50% of total project progress
        $step_progress = ($step_virtual_total > 0) ? ($step_current_score / $step_virtual_total) * 50 : 0;

        return round($step_progress, 2);

    } catch (Exception $e) {
        error_log("Calculate step progress component error: " . $e->getMessage());
        return 0;
    }
}

/**
 * Calculate financial progress component (50% of total project progress)
 */
function calculate_financial_progress_component($project_id) {
    global $pdo;

    try {
        // Get base budget from projects table
        $stmt = $pdo->prepare("SELECT total_budget FROM projects WHERE id = ?");
        $stmt->execute([$project_id]);
        $project = $stmt->fetch();
        $base_budget = $project['total_budget'] ?? 0;

        // Get total budget increases from active budget_increase transactions
        $stmt = $pdo->prepare("
            SELECT SUM(amount) as total_increases
            FROM project_transactions 
            WHERE project_id = ? 
            AND transaction_type = 'budget_increase' 
            AND transaction_status = 'active'
        ");
        $stmt->execute([$project_id]);
        $result = $stmt->fetch();
        $budget_increases = $result['total_increases'] ?? 0;

        // Calculate total approved budget (base + increases)
        $total_approved_budget = $base_budget + $budget_increases;

        if ($total_approved_budget <= 0) {
            return 0;
        }

        // Get total expenditure from ONLY active expenditure transactions
        $stmt = $pdo->prepare("
            SELECT SUM(amount) as total_expenditure
            FROM project_transactions 
            WHERE project_id = ? 
            AND transaction_type = 'expenditure' 
            AND transaction_status = 'active'
        ");
        $stmt->execute([$project_id]);
        $result = $stmt->fetch();

        $total_expenditure = $result['total_expenditure'] ?? 0;

        // Debug log for troubleshooting
        error_log("Project {$project_id}: Base Budget: {$base_budget}, Budget Increases: {$budget_increases}, Total Approved: {$total_approved_budget}, Active Expenditure: {$total_expenditure}");

        // Financial progress is 50% of total project progress, capped at 50%
        // Only expenditure transactions with active status count towards progress
        $financial_progress = min(($total_expenditure / $total_approved_budget) * 50, 50);

        return round($financial_progress, 2);

    } catch (Exception $e) {
        error_log("Calculate financial progress component error: " . $e->getMessage());
        return 0;
    }
}

/**
 * Determine project status based on progress percentage
 */
function calculate_status_from_progress($progress_percentage) {
    if ($progress_percentage == 0) {
        return 'planning';
    } elseif ($progress_percentage > 0 && $progress_percentage < 100) {
        return 'ongoing';
    } elseif ($progress_percentage >= 100) {
        return 'completed';
    }

    return 'planning'; // Default fallback
}

/**
 * Update project progress and status automatically
 * This is the main function that should be called whenever:
 * - Step status changes
 * - Expenditure is updated
 * - Project is edited
 */
function update_project_progress_and_status($project_id, $force_private_visibility = false, $start_transaction = true) {
    global $pdo;

    try {
        // Check if we should start a new transaction
        $transaction_started = false;
        if ($start_transaction && !$pdo->inTransaction()) {
            $pdo->beginTransaction();
            $transaction_started = true;
        }

        // Get current progress and status for comparison
        $stmt = $pdo->prepare("SELECT progress_percentage, status FROM projects WHERE id = ?");
        $stmt->execute([$project_id]);
        $project_data = $stmt->fetch();
        $old_progress = $project_data['progress_percentage'] ?? 0;
        $old_status = $project_data['status'] ?? 'planning';

        // Calculate new progress
        $new_progress = calculate_complete_project_progress($project_id);

        // Determine new status based on progress
        $new_status = calculate_status_from_progress($new_progress);

        // Get current project data for step counts
        $stmt = $pdo->prepare("
            SELECT 
                COUNT(*) as total_steps,
                COUNT(CASE WHEN status = 'completed' OR status = 'complete' THEN 1 END) as completed_steps
            FROM project_steps 
            WHERE project_id = ?
        ");
        $stmt->execute([$project_id]);
        $step_data = $stmt->fetch();

        // Check if approved_cost column exists
        $stmt = $pdo->prepare("SHOW COLUMNS FROM projects LIKE 'approved_cost'");
        $stmt->execute();
        $approved_cost_exists = $stmt->fetch();

        // Prepare update query
        $update_fields = [
            "progress_percentage = ?",
            "status = ?",
            "completed_steps = ?",
            "total_steps = ?",
            "updated_at = NOW()"
        ];
        $params = [
            $new_progress,
            $new_status,
            $step_data['completed_steps'] ?? 0,
            $step_data['total_steps'] ?? 0
        ];

        // Add approved_cost update if column exists and we have approved budget
        if ($approved_cost_exists) {
            $stmt = $pdo->prepare("SELECT budget_amount FROM total_budget WHERE project_id = ? AND approval_status = 'approved' AND is_active = 1 ORDER BY version DESC LIMIT 1");
            $stmt->execute([$project_id]);
            $approved_budget = $stmt->fetchColumn();
            if ($approved_budget) {
                $update_fields[] = "approved_cost = ?";
                $params[] = $approved_budget;
            }
        }

        // If forcing private visibility (like on edit)
        if ($force_private_visibility) {
            $update_fields[] = "visibility = 'private'";
        }

        $params[] = $project_id;

        $sql = "UPDATE projects SET " . implode(", ", $update_fields) . " WHERE id = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);

        if ($transaction_started) {
            $pdo->commit();
        }

        // Verify the update was successful
        $stmt = $pdo->prepare("SELECT progress_percentage FROM projects WHERE id = ?");
        $stmt->execute([$project_id]);
        $db_progress = $stmt->fetchColumn();

        if ($db_progress != $new_progress) {
            error_log("Progress mismatch for project $project_id: calculated=$new_progress, db=$db_progress");
        }

        // Log progress update
        log_activity('project_progress_updated', "Updated progress for project ID: $project_id to {$new_progress}%", null, 'project', $project_id);

        // Send notifications for major updates
        $should_notify = false;
        $notification_type = 'project_update';
        $notification_details = '';

        // Check for significant progress milestones
        if ($old_progress < 25 && $new_progress >= 25) {
            $should_notify = true;
            $notification_type = 'milestone';
            $notification_details = "Project has reached 25% completion milestone.";
        } elseif ($old_progress < 50 && $new_progress >= 50) {
            $should_notify = true;
            $notification_type = 'milestone';
            $notification_details = "Project has reached 50% completion milestone.";
        } elseif ($old_progress < 75 && $new_progress >= 75) {
            $should_notify = true;
            $notification_type = 'milestone';
            $notification_details = "Project has reached 75% completion milestone.";
        } elseif ($old_progress < 100 && $new_progress >= 100) {
            $should_notify = true;
            $notification_type = 'completion';
            $notification_details = "Project has been completed! All project activities have been finished.";
        }

        // Check for status changes
        if ($old_status !== $new_status) {
            $should_notify = true;
            $notification_type = 'status_change';
            $notification_details = "Project status has changed from '" . ucfirst($old_status) . "' to '" . ucfirst($new_status) . "'.";
        }

        // Send notification if criteria met
        if ($should_notify) {
            try {
                require_once __DIR__ . '/functions.php';
                notify_project_subscribers($project_id, $notification_type, $notification_details);
            } catch (Exception $e) {
                error_log("Failed to send subscriber notifications: " . $e->getMessage());
            }
        }

        return [
            'success' => true,
            'progress' => $new_progress,
            'status' => $new_status,
            'step_progress' => calculate_step_progress_component($project_id),
            'financial_progress' => calculate_financial_progress_component($project_id),
            'db_progress' => $db_progress
        ];

    } catch (Exception $e) {
        if ($transaction_started && $pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log("Update project progress and status error: " . $e->getMessage());
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

/**
 * Update step status and trigger project recalculation
 */
function update_step_status_with_progress_recalc($step_id, $new_status, $start_date = null, $end_date = null, $notes = null) {
    global $pdo;

    try {
        // Get step and project info first
        $stmt = $pdo->prepare("SELECT project_id FROM project_steps WHERE id = ?");
        $stmt->execute([$step_id]);
        $step = $stmt->fetch();

        if (!$step) {
            throw new Exception("Step not found");
        }

        // Validate status
        $valid_statuses = ['pending', 'in_progress', 'completed', 'complete'];
        if (!in_array($new_status, $valid_statuses)) {
            throw new Exception("Invalid step status");
        }

        // Start transaction only if none exists
        $transaction_started = false;
        if (!$pdo->inTransaction()) {
            $pdo->beginTransaction();
            $transaction_started = true;
        }

        // Update step
        $update_fields = ["status = ?"];
        $params = [$new_status];

        if ($start_date !== null) {
            $update_fields[] = "start_date = ?";
            $params[] = $start_date;
        }

        if ($end_date !== null) {
            $update_fields[] = "actual_end_date = ?";
            $params[] = $end_date;
        } elseif ($new_status === 'completed' || $new_status === 'complete') {
            $update_fields[] = "actual_end_date = NOW()";
        } elseif ($new_status !== 'completed' && $new_status !== 'complete') {
            $update_fields[] = "actual_end_date = NULL";
        }

        if ($new_status === 'in_progress' && $start_date === null) {
            $update_fields[] = "start_date = COALESCE(start_date, NOW())";
        }

        if ($notes !== null) {
            $update_fields[] = "notes = ?";
            $params[] = $notes;
        }

        $update_fields[] = "updated_at = NOW()";
        $params[] = $step_id;

        $sql = "UPDATE project_steps SET " . implode(", ", $update_fields) . " WHERE id = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);

        // Update project progress and status (don't start new transaction)
        $result = update_project_progress_and_status($step['project_id'], false, false);

        // Commit transaction if we started it
        if ($transaction_started) {
            $pdo->commit();
        }

        return $result;

    } catch (Exception $e) {
        if ($transaction_started && $pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log("Error updating step status with progress recalc: " . $e->getMessage());
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

/**
 * Get total approved budget including budget increases
 */
function get_total_approved_budget($project_id) {
    global $pdo;

    try {
        // Get base budget from projects table
        $stmt = $pdo->prepare("SELECT total_budget FROM projects WHERE id = ?");
        $stmt->execute([$project_id]);
        $project = $stmt->fetch();
        $base_budget = $project['total_budget'] ?? 0;

        // Get total budget increases from active budget_increase transactions
        $stmt = $pdo->prepare("
            SELECT SUM(amount) as total_increases
            FROM project_transactions 
            WHERE project_id = ? 
            AND transaction_type = 'budget_increase' 
            AND transaction_status = 'active'
        ");
        $stmt->execute([$project_id]);
        $result = $stmt->fetch();
        $budget_increases = $result['total_increases'] ?? 0;

        return $base_budget + $budget_increases;

    } catch (Exception $e) {
        error_log("Get total approved budget error: " . $e->getMessage());
        return 0;
    }
}

/**
 * Handle project edit with proper progress recalculation and visibility update
 */
function handle_project_edit_with_progress_update($project_id) {
    // Force visibility to private and recalculate progress/status
    return update_project_progress_and_status($project_id, true);
}
?>