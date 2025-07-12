<?php
function add_project_transaction($project_id, $transaction_type, $amount, $description, $reference_number = '', $document_path = '', $admin_id = null) {
    global $pdo;
    
    try {
        if (!$admin_id && isset($_SESSION['admin_id'])) {
            $admin_id = $_SESSION['admin_id'];
        }
        
        $valid_types = ['allocation', 'expenditure'];
        if (!in_array($transaction_type, $valid_types)) {
            return ['success' => false, 'message' => 'Invalid transaction type'];
        }
        
        $stmt = $pdo->prepare("INSERT INTO project_transactions 
                              (project_id, transaction_type, amount, description, reference_number, document_path, created_by, created_at) 
                              VALUES (?, ?, ?, ?, ?, ?, ?, NOW())");
        
        $result = $stmt->execute([
            $project_id,
            $transaction_type,
            $amount,
            $description,
            $reference_number,
            $document_path,
            $admin_id
        ]);
        
        if ($result) {
            // Update project progress after adding transaction
            require_once 'projectProgressCalculator.php';
            $progress_result = update_project_progress_and_status($project_id, false, true);
            
            log_activity('transaction_added', "Added $transaction_type of " . format_currency($amount) . " to project ID $project_id", $admin_id);
            return [
                'success' => true, 
                'message' => 'Transaction added successfully',
                'progress_update' => $progress_result,
                'new_progress' => $progress_result['progress'] ?? 0
            ];
        }
        
        return ['success' => false, 'message' => 'Failed to add transaction'];
        
    } catch (Exception $e) {
        error_log("Add transaction error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Database error occurred'];
    }
}

/**
 * Get all transactions for a project
 */
function get_project_transactions($project_id, $transaction_type = null) {
    global $pdo;
    
    try {
        $sql = "SELECT pt.*, a.name as admin_name 
                FROM project_transactions pt 
                LEFT JOIN admins a ON pt.created_by = a.id 
                WHERE pt.project_id = ?";
        $params = [$project_id];
        
        if ($transaction_type) {
            $sql .= " AND pt.transaction_type = ?";
            $params[] = $transaction_type;
        }
        
        $sql .= " ORDER BY pt.created_at DESC";
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
        
    } catch (Exception $e) {
        error_log("Get transactions error: " . $e->getMessage());
        return [];
    }
}

/**
 * Update a transaction
 */
function update_project_transaction($transaction_id, $amount, $description, $reference_number = '', $document_path = '', $admin_id = null) {
    global $pdo;
    
    try {
        if (!$admin_id && isset($_SESSION['admin_id'])) {
            $admin_id = $_SESSION['admin_id'];
        }
        
        // Get project_id for progress update
        $stmt = $pdo->prepare("SELECT project_id FROM project_transactions WHERE id = ?");
        $stmt->execute([$transaction_id]);
        $project_id = $stmt->fetchColumn();
        
        if (!$project_id) {
            return ['success' => false, 'message' => 'Transaction not found'];
        }
        
        $stmt = $pdo->prepare("UPDATE project_transactions 
                              SET amount = ?, description = ?, reference_number = ?, document_path = ?, updated_at = NOW() 
                              WHERE id = ?");
        
        $result = $stmt->execute([$amount, $description, $reference_number, $document_path, $transaction_id]);
        
        if ($result) {
            // Update project progress after modifying transaction
            require_once 'projectProgressCalculator.php';
            $progress_result = update_project_progress_and_status($project_id, false, true);
            
            log_activity('transaction_updated', "Updated transaction ID $transaction_id", $admin_id);
            return [
                'success' => true, 
                'message' => 'Transaction updated successfully',
                'progress_update' => $progress_result,
                'new_progress' => $progress_result['progress'] ?? 0
            ];
        }
        
        return ['success' => false, 'message' => 'Failed to update transaction'];
        
    } catch (Exception $e) {
        error_log("Update transaction error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Database error occurred'];
    }
}

/**
 * Delete a transaction
 */
function delete_project_transaction($transaction_id, $admin_id = null) {
    global $pdo;
    
    try {
        if (!$admin_id && isset($_SESSION['admin_id'])) {
            $admin_id = $_SESSION['admin_id'];
        }
        
        // Get project_id for progress update
        $stmt = $pdo->prepare("SELECT project_id FROM project_transactions WHERE id = ?");
        $stmt->execute([$transaction_id]);
        $project_id = $stmt->fetchColumn();
        
        if (!$project_id) {
            return ['success' => false, 'message' => 'Transaction not found'];
        }
        
        // Soft delete instead of hard delete
        $stmt = $pdo->prepare("UPDATE project_transactions SET transaction_status = 'deleted', modified_by = ?, modified_at = NOW() WHERE id = ?");
        $result = $stmt->execute([$admin_id, $transaction_id]);
        
        if ($result) {
            // Update project progress after deleting transaction
            require_once 'projectProgressCalculator.php';
            $progress_result = update_project_progress_and_status($project_id, false, true);
            
            log_activity('transaction_deleted', "Deleted transaction ID $transaction_id", $admin_id);
            return [
                'success' => true, 
                'message' => 'Transaction deleted successfully',
                'progress_update' => $progress_result,
                'new_progress' => $progress_result['progress'] ?? 0
            ];
        }
        
        return ['success' => false, 'message' => 'Failed to delete transaction'];
        
    } catch (Exception $e) {
        error_log("Delete transaction error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Database error occurred'];
    }
}

/**
 * Handle transaction document upload
 */
function handle_transaction_document_upload($file) {
    $allowed_types = ['pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx'];
    $max_size = 5242880; // 5MB
    
    if (!isset($file) || $file['error'] !== UPLOAD_ERR_OK) {
        return ['success' => false, 'message' => 'File upload error'];
    }
    
    $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($extension, $allowed_types)) {
        return ['success' => false, 'message' => 'Invalid file type. Allowed: PDF, DOC, DOCX, JPG, PNG'];
    }
    
    if ($file['size'] > $max_size) {
        return ['success' => false, 'message' => 'File too large. Maximum size: 5MB'];
    }
    
    $filename = 'transaction_' . uniqid() . '_' . time() . '.' . $extension;
    $filepath = UPLOAD_PATH . $filename;
    
    if (!is_dir(UPLOAD_PATH)) {
        mkdir(UPLOAD_PATH, 0755, true);
    }
    
    if (move_uploaded_file($file['tmp_name'], $filepath)) {
        chmod($filepath, 0644);
        return [
            'success' => true,
            'filename' => $filename,
            'filepath' => $filepath,
            'original_name' => basename($file['name'])
        ];
    }
    
    return ['success' => false, 'message' => 'Failed to save file'];
}
?>
