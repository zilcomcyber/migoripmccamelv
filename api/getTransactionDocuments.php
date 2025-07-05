<?php
require_once '../config.php';
require_once '../includes/functions.php';

header('Content-Type: application/json');

if (!isset($_GET['transaction_id'])) {
    json_response(['success' => false, 'message' => 'Transaction ID required']);
}

$transaction_id = (int)$_GET['transaction_id'];

try {
    $stmt = $pdo->prepare("
        SELECT ptd.*, pt.project_id, pt.transaction_type, pt.amount, pt.description
        FROM project_transaction_documents ptd
        JOIN project_transactions pt ON ptd.transaction_id = pt.id
        WHERE ptd.transaction_id = ?
        ORDER BY ptd.created_at DESC
    ");
    
    $stmt->execute([$transaction_id]);
    $documents = $stmt->fetchAll();
    
    json_response([
        'success' => true,
        'documents' => $documents
    ]);
    
} catch (Exception $e) {
    error_log("Get transaction documents error: " . $e->getMessage());
    json_response(['success' => false, 'message' => 'Failed to fetch documents']);
}
?>
