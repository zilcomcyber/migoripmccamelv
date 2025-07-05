<?php
require_once '../config.php';
require_once '../includes/functions.php';

// Force JSON response and enable error debugging
header('Content-Type: application/json');
error_reporting(E_ALL);
ini_set('display_errors', 0); // Disable HTML errors (prevent broken JSON)

try {
    // Only accept POST requests
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception("Only POST requests are allowed", 405);
    }

    // Start session for cookies
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    // Generate or retrieve visitor ID (cookie-based)
    $visitor_id = $_COOKIE['visitor_id'] ?? null;
    if (!$visitor_id) {
        $visitor_id = uniqid('visitor_', true);
        setcookie('visitor_id', $visitor_id, time() + (86400 * 30), "/"); // 30-day expiry
    }

    // Get real IP (works behind proxies like Cloudflare)
    function get_real_ip() {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return $_SERVER['HTTP_CF_CONNECTING_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
        }
        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }
    $user_ip = get_real_ip();
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

    // Validate required comment fields
    $project_id = (int)($_POST['project_id'] ?? 0);
    $citizen_name = sanitize_input($_POST['citizen_name'] ?? '');
    $citizen_email = sanitize_input($_POST['citizen_email'] ?? '');
    $message = sanitize_input($_POST['message'] ?? '');
    $parent_id = (int)($_POST['parent_comment_id'] ?? 0); // For replies

    // Validate input
    if (empty($project_id) || empty($citizen_name) || empty($message)) {
        throw new Exception("Name and comment are required", 400);
    }
    if (strlen($citizen_name) < 2) {
        throw new Exception("Name must be at least 2 characters", 400);
    }
    if (strlen($message) < 10) {
        throw new Exception("Comment must be at least 10 characters", 400);
    }
    if (!empty($citizen_email) && !filter_var($citizen_email, FILTER_VALIDATE_EMAIL)) {
        throw new Exception("Invalid email format", 400);
    }

    // Verify project exists
    $project = get_project_by_id($project_id);
    if (!$project) {
        throw new Exception("Project not found", 404);
    }

    // Insert into `feedback` table (your only table)
    $stmt = $pdo->prepare("
        INSERT INTO feedback 
        (project_id, citizen_name, citizen_email, message, parent_comment_id, status, user_ip, user_agent, visitor_id, created_at) 
        VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, NOW())
    ");
    $stmt->execute([
        $project_id, 
        $citizen_name, 
        $citizen_email, 
        $message, 
        $parent_id, 
        $user_ip, 
        $user_agent, 
        $visitor_id
    ]);

    // Success response
    echo json_encode([
        'success' => true,
        'message' => 'Comment submitted for approval!'
    ]);

} catch (Exception $e) {
    // Error response (ensure valid JSON)
    http_response_code($e->getCode() ?: 500);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
    exit;
}