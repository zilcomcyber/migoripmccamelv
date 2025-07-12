<?php
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

header('Content-Type: application/json');

// Require admin authentication
if (!isset($_SESSION['admin_id'])) {
    http_response_code(401);
    json_response(['success' => false, 'message' => 'Authentication required']);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    json_response(['success' => false, 'message' => 'Method not allowed']);
}

try {
    $project_id = (int)$_POST['project_id'];
    $transaction_type = sanitize_input($_POST['transaction_type']);
    $amount = (float)$_POST['amount'];
    $description = sanitize_input($_POST['description']);
    $reference_number = sanitize_input($_POST['reference_number']);
    $transaction_date = $_POST['transaction_date'] ?? date('Y-m-d');
    $fund_source = sanitize_input($_POST['fund_source'] ?? 'County Development Fund');
    $funding_category = sanitize_input($_POST['funding_category'] ?? 'development');
    $voucher_number = sanitize_input($_POST['voucher_number'] ?? '');
    $disbursement_method = sanitize_input($_POST['disbursement_method'] ?? 'bank_transfer');

    // Validate inputs
    if ($project_id <= 0) {
        json_response(['success' => false, 'message' => 'Invalid project ID']);
    }

    // Validate transaction type against database
    $stmt = $pdo->prepare("SELECT type_code, affects_budget, affects_expenditure FROM transaction_types WHERE type_code = ? AND is_active = 1");
    $stmt->execute([$transaction_type]);
    $transaction_type_data = $stmt->fetch();

    if (!$transaction_type_data) {
        json_response(['success' => false, 'message' => 'Invalid or inactive transaction type']);
    }

    if ($amount <= 0) {
        json_response(['success' => false, 'message' => 'Amount must be greater than 0']);
    }

    if (empty($description)) {
        json_response(['success' => false, 'message' => 'Description is required']);
    }

    if (empty($reference_number)) {
        json_response(['success' => false, 'message' => 'Reference number is required']);
    }

    // Check if project exists
    $stmt = $pdo->prepare("SELECT id FROM projects WHERE id = ?");
    $stmt->execute([$project_id]);
    if (!$stmt->fetch()) {
        json_response(['success' => false, 'message' => 'Project not found']);
    }

    // Begin transaction
    $pdo->beginTransaction();

    // Insert transaction
    $stmt = $pdo->prepare("
        INSERT INTO project_transactions 
        (project_id, transaction_type, amount, description, reference_number, transaction_date, 
         fund_source, funding_category, voucher_number, disbursement_method, created_by, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    ");

    $result = $stmt->execute([
        $project_id, 
        $transaction_type, 
        $amount, 
        $description, 
        $reference_number, 
        $transaction_date,
        $fund_source,
        $funding_category,
        $voucher_number,
        $disbursement_method,
        $_SESSION['admin_id']
    ]);

    if (!$result) {
        throw new Exception('Failed to insert transaction');
    }

    $transaction_id = $pdo->lastInsertId();

    // Handle document upload if provided
    if (isset($_FILES['document']) && $_FILES['document']['error'] === UPLOAD_ERR_OK) {
        $upload_result = secure_file_upload($_FILES['document'], ['pdf', 'jpg', 'jpeg', 'png'], 10485760); // 10MB

        if ($upload_result['success']) {
            // Insert transaction document
            $stmt = $pdo->prepare("
                INSERT INTO project_transaction_documents 
                (transaction_id, file_path, original_filename, file_size, created_at) 
                VALUES (?, ?, ?, ?, NOW())
            ");

            $stmt->execute([
                $transaction_id,
                $upload_result['filename'],
                $upload_result['original_name'],
                $_FILES['document']['size']
            ]);
        }
    }

    // Update project progress based on new transaction using the enhanced calculator
    require_once '../includes/projectProgressCalculator.php';

    // Calculate the new progress immediately after transaction is inserted
    $new_progress = calculate_complete_project_progress($project_id);

    // Update the projects table directly with the calculated progress
    $stmt = $pdo->prepare("UPDATE projects SET progress_percentage = ?, updated_at = NOW() WHERE id = ?");
    $update_result = $stmt->execute([$new_progress, $project_id]);

    if (!$update_result) {
        throw new Exception('Failed to update project progress');
    }

    // Also run the full progress update function for status changes (without starting new transaction)
    $progress_result = update_project_progress_and_status($project_id, false, false);
    $enhanced_progress = $progress_result['progress'] ?? $new_progress;

    // Verify the progress was actually updated
    $stmt = $pdo->prepare("SELECT progress_percentage FROM projects WHERE id = ?");
    $stmt->execute([$project_id]);
    $current_progress = $stmt->fetchColumn();

    error_log("Transaction added - Project ID: $project_id, New Progress: $new_progress, DB Progress: $current_progress");

    // Log activity
    log_activity(
        'transaction_added',
        "Added {$transaction_type} of KES " . number_format($amount) . " for project ID {$project_id}",
        $_SESSION['admin_id'],
        'project',
        $project_id,
        ['transaction_id' => $transaction_id, 'amount' => $amount, 'type' => $transaction_type]
    );

    $pdo->commit();

    json_response([
        'success' => true, 
        'message' => ucfirst($transaction_type) . ' added successfully',
        'transaction_id' => $transaction_id,
        'new_progress' => $enhanced_progress
    ]);

} catch (Exception $e) {
    $pdo->rollBack();
    error_log("Add transaction error: " . $e->getMessage());
    json_response(['success' => false, 'message' => 'Failed to add transaction: ' . $e->getMessage()]);
}

// Enhanced progress calculation function
function calculate_project_progress($project_id, $conn) {
    // Step progress (50% of total)
    $stmt = $conn->prepare("SELECT * FROM project_steps WHERE project_id = ? ORDER BY step_number");
    $stmt->execute([$project_id]);
    $steps = $stmt->fetchAll();

    $total_steps = count($steps);
    $step_score = 0;
    foreach ($steps as $step) {
        if ($step['status'] === 'completed') $step_score += 1;
        elseif ($step['status'] === 'in_progress') $step_score += 0.5;
    }
    $step_progress = ($total_steps > 0) ? ($step_score / $total_steps) * 50 : 0;

    // Budget progress (50% of total)
    $stmt = $conn->prepare("
        SELECT 
            SUM(CASE WHEN transaction_type = 'allocation' THEN amount ELSE 0 END) as allocated,
            SUM(CASE WHEN transaction_type = 'expenditure' THEN amount ELSE 0 END) as spent
        FROM project_transactions 
        WHERE project_id = ?
    ");
    $stmt->execute([$project_id]);
    $transactions = $stmt->fetch();

    $allocated = $transactions['allocated'] ?? 0;
    $spent = $transactions['spent'] ?? 0;
    $budget_progress = ($allocated > 0) ? min($spent / $allocated, 1) * 50 : 0;

    return round($step_progress + $budget_progress, 1);
}
?>