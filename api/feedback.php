<?php
// Disable error display to prevent HTML in JSON response
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// Start output buffering to catch any unwanted output
ob_start();

require_once '../config.php';
require_once '../includes/functions.php';

// Check if comment filter exists, if not, create a fallback
if (file_exists('../includes/commentFilter.php')) {
    require_once '../includes/commentFilter.php';
} else {
    error_log("Warning: commentFilter.php not found, creating fallback function");
    if (!function_exists('filter_comment')) {
        function filter_comment($message, $citizen_name) {
            return ['status' => 'approved', 'reason' => 'clean_content'];
        }
    }
}

// Set proper headers
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-cache, must-revalidate');

// Function to ensure JSON response even on fatal errors
function sendJsonResponse($data) {
    // Clear any output that might have been generated
    if (ob_get_level()) {
        ob_clean();
    }
    echo json_encode($data);
    exit;
}

// Set error handler to catch any PHP errors and return JSON
set_error_handler(function($severity, $message, $file, $line) {
    error_log("PHP Error: $message in $file on line $line");
    sendJsonResponse(['success' => false, 'message' => 'A server error occurred. Please try again.']);
});

// Set exception handler
set_exception_handler(function($exception) {
    error_log("API Exception: " . $exception->getMessage());
    sendJsonResponse(['success' => false, 'message' => 'A server error occurred. Please try again.']);
});

// Handle CORS if needed
if (isset($_SERVER['HTTP_ORIGIN'])) {
    header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Max-Age: 86400');
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header("Access-Control-Allow-Methods: POST, OPTIONS");
    header("Access-Control-Allow-Headers: Content-Type");
    exit(0);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

try {
    // Log incoming data for debugging
    error_log("Feedback API called with data: " . json_encode($_POST));
    
    $project_id = isset($_POST['project_id']) ? (int)$_POST['project_id'] : 0;
    $citizen_name = isset($_POST['citizen_name']) ? trim($_POST['citizen_name']) : '';
    $citizen_email = isset($_POST['citizen_email']) ? trim($_POST['citizen_email']) : '';
    $message = isset($_POST['message']) ? trim($_POST['message']) : '';
    $parent_comment_id = isset($_POST['parent_comment_id']) ? (int)$_POST['parent_comment_id'] : 0;

    // Check for duplicate submissions (within last 30 seconds)
    try {
        $duplicate_check = $pdo->prepare("
            SELECT COUNT(*) FROM feedback 
            WHERE project_id = ? AND citizen_name = ? AND message = ? 
            AND created_at > DATE_SUB(NOW(), INTERVAL 30 SECOND)
        ");
        $duplicate_check->execute([$project_id, $citizen_name, $message]);
        if ($duplicate_check->fetchColumn() > 0) {
            sendJsonResponse(['success' => false, 'message' => 'Duplicate comment detected. Please wait before submitting again.']);
        }
    } catch (Exception $e) {
        error_log("Duplicate check error: " . $e->getMessage());
    }

    // Log processed data
    error_log("Processed data - Project ID: $project_id, Name: '$citizen_name', Message length: " . strlen($message));

    // Basic validation
    if (empty($project_id) || empty($citizen_name) || empty($message)) {
        error_log("Validation failed - Project ID: $project_id, Name: '$citizen_name', Message length: " . strlen($message));
        sendJsonResponse(['success' => false, 'message' => 'All required fields must be filled']);
    }

    if (strlen($citizen_name) < 2) {
        sendJsonResponse(['success' => false, 'message' => 'Name must be at least 2 characters long']);
    }

    if (!empty($citizen_email) && !filter_var($citizen_email, FILTER_VALIDATE_EMAIL)) {
        sendJsonResponse(['success' => false, 'message' => 'Please enter a valid email address']);
    }

    // Check if project exists
    try {
        $stmt = $pdo->prepare("SELECT id FROM projects WHERE id = ?");
        $stmt->execute([$project_id]);
        if (!$stmt->fetch()) {
            error_log("Project not found with ID: $project_id");
            sendJsonResponse(['success' => false, 'message' => 'Project not found']);
        }
        error_log("Project exists with ID: $project_id");
    } catch (Exception $e) {
        error_log("Database error checking project: " . $e->getMessage());
        sendJsonResponse(['success' => false, 'message' => 'Database error occurred while validating project']);
    }

    // Filter comment using the comment filter system
    $filter_result = ['status' => 'pending', 'reason' => 'Submitted for review']; // Default to pending
    try {
        // Initialize CommentFilter class
        if (class_exists('CommentFilter')) {
            $commentFilter = new CommentFilter();
            $filter_result = $commentFilter->filterComment($message);
            error_log("Comment filter result: " . json_encode($filter_result));
        } else {
            error_log("Warning: CommentFilter class not found, using default pending status");
        }
        
        // Handle rejected comments
        if ($filter_result['status'] === 'rejected') {
            sendJsonResponse(['success' => false, 'message' => $filter_result['message']]);
        }
    } catch (Exception $e) {
        error_log("Comment filtering error: " . $e->getMessage());
        // Default to pending for manual review
        $filter_result = ['status' => 'pending', 'reason' => 'Submitted for review due to filtering error'];
    }

    // Determine status based on filter result
    $status = match($filter_result['status']) {
        'approved' => 'approved',
        'pending_review' => 'pending',
        'rejected' => 'rejected',
        default => 'pending'
    };

    // Insert feedback
    try {
        error_log("Attempting to insert feedback with status: $status");
        
        // Check if the table exists and get structure
        $table_check = $pdo->query("SHOW TABLES LIKE 'project_feedback'");
        if ($table_check->rowCount() == 0) {
            // Try the feedback table instead
            $table_check = $pdo->query("SHOW TABLES LIKE 'feedback'");
            if ($table_check->rowCount() > 0) {
                error_log("Using 'feedback' table instead of 'project_feedback'");
                $stmt = $pdo->prepare("
                    INSERT INTO feedback (project_id, citizen_name, citizen_email, message, parent_comment_id, status, created_at) 
                    VALUES (?, ?, ?, ?, ?, ?, NOW())
                ");
            } else {
                error_log("Neither 'project_feedback' nor 'feedback' table exists");
                sendJsonResponse(['success' => false, 'message' => 'Database table not found']);
            }
        } else {
            $stmt = $pdo->prepare("
                INSERT INTO project_feedback (project_id, citizen_name, citizen_email, message, parent_comment_id, status, created_at) 
                VALUES (?, ?, ?, ?, ?, ?, NOW())
            ");
        }

        $result = $stmt->execute([$project_id, $citizen_name, $citizen_email, $message, $parent_comment_id, $status]);

        if ($result) {
            $comment_id = $pdo->lastInsertId();
            error_log("Comment inserted successfully with ID: $comment_id, Status: $status");
            
            if ($status === 'approved') {
                sendJsonResponse(['success' => true, 'message' => 'Comment posted successfully!']);
            } else {
                sendJsonResponse(['success' => true, 'message' => $filter_result['message'] ?? 'Comment submitted for review. It will be published after approval.']);
            }
        } else {
            $error_info = $stmt->errorInfo();
            error_log("Failed to insert comment - SQL Error: " . implode(', ', $error_info));
            sendJsonResponse(['success' => false, 'message' => 'Failed to submit comment: Database error']);
        }
    } catch (PDOException $e) {
        error_log("PDO Exception during comment insertion: " . $e->getMessage());
        sendJsonResponse(['success' => false, 'message' => 'Database error occurred: ' . $e->getMessage()]);
    }

} catch (Exception $e) {
    error_log("Feedback submission error: " . $e->getMessage());
    error_log("Stack trace: " . $e->getTraceAsString());
    
    // In development, show more details
    $is_development = (strpos($_SERVER['HTTP_HOST'] ?? '', 'localhost') !== false || 
                      strpos($_SERVER['HTTP_HOST'] ?? '', '127.0.0.1') !== false);
    
    if ($is_development) {
        sendJsonResponse(['success' => false, 'message' => 'Error: ' . $e->getMessage(), 'debug' => $e->getTraceAsString()]);
    } else {
        sendJsonResponse(['success' => false, 'message' => 'An error occurred while processing your request']);
    }
}
?>