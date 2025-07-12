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
    $document_type = sanitize_input($_POST['document_type']);
    $document_title = sanitize_input($_POST['document_title']);
    $description = sanitize_input($_POST['description'] ?? '');

    // Validate inputs
    if ($project_id <= 0) {
        json_response(['success' => false, 'message' => 'Invalid project ID']);
    }

    $allowed_types = ['tender', 'contract', 'budget', 'report', 'agreement', 'approval'];
    if (!in_array($document_type, $allowed_types)) {
        json_response(['success' => false, 'message' => 'Invalid document type']);
    }

    if (empty($document_title)) {
        json_response(['success' => false, 'message' => 'Document title is required']);
    }

    // Check if project exists
    $stmt = $pdo->prepare("SELECT id FROM projects WHERE id = ?");
    $stmt->execute([$project_id]);
    if (!$stmt->fetch()) {
        json_response(['success' => false, 'message' => 'Project not found']);
    }

    // Handle file upload
    if (!isset($_FILES['document_file']) || $_FILES['document_file']['error'] !== UPLOAD_ERR_OK) {
        json_response(['success' => false, 'message' => 'Document file is required']);
    }

    // Upload file
    $upload_result = secure_file_upload($_FILES['document_file'], ['pdf', 'jpg', 'jpeg', 'png'], 10485760); // 10MB

    if (!$upload_result['success']) {
        json_response(['success' => false, 'message' => 'File upload failed: ' . $upload_result['message']]);
    }

    // Begin transaction
    $pdo->beginTransaction();

    // Insert document record
    $stmt = $pdo->prepare("
        INSERT INTO project_documents 
        (project_id, document_type, document_title, description, file_path, original_filename, file_size, uploaded_by, created_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
    ");

    $result = $stmt->execute([
        $project_id,
        $document_type,
        $document_title,
        $description,
        $upload_result['filename'],
        $upload_result['original_name'],
        $_FILES['document_file']['size'],
        $_SESSION['admin_id']
    ]);

    if (!$result) {
        throw new Exception('Failed to insert document record');
    }

    $document_id = $pdo->lastInsertId();

    // Log activity
    log_activity(
        'document_uploaded',
        "Uploaded {$document_type} document '{$document_title}' for project ID {$project_id}",
        $_SESSION['admin_id'],
        'project',
        $project_id,
        ['document_id' => $document_id, 'document_type' => $document_type]
    );

    $pdo->commit();

    json_response([
        'success' => true,
        'message' => 'Document uploaded successfully',
        'document_id' => $document_id
    ]);

} catch (Exception $e) {
    error_log("Document upload error: " . $e->getMessage());
    json_response(['success' => false, 'message' => 'Failed to save document information. Please try again.'], 500);
}
?>