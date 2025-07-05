<?php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/projectStepsTemplates.php';

/**
 * Security Functions
 */
if (!function_exists('generate_csrf_token')) {
function generate_csrf_token() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }

    return $_SESSION['csrf_token'];
}

}
if (!function_exists('verify_csrf_token')) {
function verify_csrf_token($token) {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    // Check if token is provided
    if (empty($token)) {
        error_log("CSRF: No token provided");
        return false;
    }

    // Check if session token exists
    if (!isset($_SESSION['csrf_token']) || !isset($_SESSION['csrf_token_time'])) {
        error_log("CSRF: No session token found");
        return false;
    }

    // Check token age
    $token_age = time() - $_SESSION['csrf_token_time'];
    if ($token_age > CSRF_TOKEN_LIFETIME) {
        error_log("CSRF: Token expired (age: {$token_age}s)");
        unset($_SESSION['csrf_token'], $_SESSION['csrf_token_time']);
        return false;
    }

    // Verify token match
    $is_valid = hash_equals($_SESSION['csrf_token'], $token);
    if (!$is_valid) {
        error_log("CSRF: Token mismatch");
    }

    return $is_valid;
}

function csrf_protect() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!isset($_POST['csrf_token']) || !verify_csrf_token($_POST['csrf_token'])) {
            http_response_code(403);
            die('CSRF token validation failed');
        }
    }
}

function sanitize_input($data, $type = 'string') {
    if (is_array($data)) {
        return array_map('sanitize_input', $data);
    }

    $data = trim($data);

    switch ($type) {
        case 'email':
            $data = filter_var($data, FILTER_SANITIZE_EMAIL);
            break;
        case 'int':
            $data = filter_var($data, FILTER_SANITIZE_NUMBER_INT);
            break;
        case 'float':
            $data = filter_var($data, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
            break;
        case 'url':
            $data = filter_var($data, FILTER_SANITIZE_URL);
            break;
        default:
            $data = htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8', false);
    }

    return $data;
}

/**
 * Data Formatting Functions
 */
function format_date($date) {
    return date('M d, Y', strtotime($date));
}

/**
 * Check if current admin owns a specific project
 */
function owns_project($project_id, $admin_id = null) {
    global $pdo;

    if ($admin_id === null) {
        $admin_id = $_SESSION['admin_id'] ?? null;
    }

    if (!$admin_id) {
        return false;
    }

    // Super admins can access all projects
    if (isset($_SESSION['admin_role']) && $_SESSION['admin_role'] === 'super_admin') {
        return true;
    }

    $stmt = $pdo->prepare("SELECT 1 FROM projects WHERE id = ? AND created_by = ?");
    $stmt->execute([$project_id, $admin_id]);
    return $stmt->fetch() ? true : false;
}

/**
 * Require project ownership or exit with access denied
 */
function require_project_ownership($project_id, $permission_key = null) {
    $current_admin = get_current_admin();
    if (!$current_admin) {
        header('Location: ../404.php');
        exit;
    }

    // Super admin bypasses ownership checks
    if ($current_admin['role'] === 'super_admin') {
        return true;
    }

    // Check permission if specified
    if ($permission_key && !has_permission($permission_key)) {
        header('Location: ../404.php');
        exit;
    }

    // Check ownership
    global $pdo;
    if (!owns_project($project_id, $current_admin['id'], $pdo)) {
        // Log unauthorized access attempt
        security_log('unauthorized_project_access', $current_admin['id'], [
            'project_id' => $project_id,
            'attempted_action' => basename($_SERVER['PHP_SELF']),
            'url' => $_SERVER['REQUEST_URI'] ?? null
        ]);

        header('Location: ../404.php');
        exit;
    }

    return true;
}

}
if (!function_exists('format_currency')) {
function format_currency($amount) {
    return 'KES ' . number_format($amount, 2);
}

function get_status_badge_class($status) {
    $classes = [
        'planning' => 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300',
        'ongoing' => 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300',
        'completed' => 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300',
        'suspended' => 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300',
        'cancelled' => 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'
    ];
    return $classes[$status] ?? 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300';
}

function get_progress_color_class($percentage) {
    if ($percentage >= 80) return 'bg-green-500';
    if ($percentage >= 60) return 'bg-blue-500';
    if ($percentage >= 40) return 'bg-yellow-500';
    if ($percentage >= 20) return 'bg-orange-500';
    return 'bg-red-500';
}

function get_status_text_class($status) {
    switch ($status) {
        case 'completed': return 'text-green-600 dark:text-green-400';
        case 'ongoing': return 'text-blue-600 dark:text-blue-400';
        case 'planning': return 'text-yellow-600 dark:text-yellow-400';
        case 'suspended': return 'text-red-600 dark:text-red-400';
        case 'cancelled': return 'text-gray-600 dark:text-gray-400';
        default: return 'text-gray-600 dark:text-gray-400';
    }
}

function get_feedback_status_badge_class($status) {
    $classes = [
        'pending' => 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300',
        'approved' => 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300',
        'rejected' => 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300',
        'reviewed' => 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300',
        'responded' => 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
    ];
    return $classes[$status] ?? 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300';
}

/**
 * Budget Functions
 */
function get_project_budget($project_id) {
    global $pdo;
    
    try {
        $stmt = $pdo->prepare("SELECT * FROM total_budget WHERE project_id = ? AND is_active = 1 ORDER BY version DESC LIMIT 1");
        $stmt->execute([$project_id]);
        return $stmt->fetch();
    } catch (Exception $e) {
        error_log("Get project budget error: " . $e->getMessage());
        return null;
    }
}

function get_project_budget_summary($project_id) {
    global $pdo;
    
    try {
        // Get approved budget
        $budget_stmt = $pdo->prepare("SELECT budget_amount FROM total_budget WHERE project_id = ? AND approval_status = 'approved' AND is_active = 1 ORDER BY version DESC LIMIT 1");
        $budget_stmt->execute([$project_id]);
        $approved_budget = $budget_stmt->fetchColumn() ?: 0;

        // Get allocations, disbursements, and expenditures (only active transactions)
        $trans_stmt = $pdo->prepare("
            SELECT 
                COALESCE(SUM(CASE WHEN transaction_type = 'allocation' AND transaction_status = 'active' THEN amount ELSE 0 END), 0) as allocated,
                COALESCE(SUM(CASE WHEN transaction_type = 'disbursement' AND transaction_status = 'active' THEN amount ELSE 0 END), 0) as disbursed,
                COALESCE(SUM(CASE WHEN transaction_type = 'expenditure' AND transaction_status = 'active' THEN amount ELSE 0 END), 0) as spent
            FROM project_transactions 
            WHERE project_id = ?
        ");
        $trans_stmt->execute([$project_id]);
        $transactions = $trans_stmt->fetch();

        $allocated = $transactions['allocated'] ?: 0;
        $disbursed = $transactions['disbursed'] ?: 0;
        $spent = $transactions['spent'] ?: 0;

        return [
            'approved_budget' => $approved_budget,
            'allocated' => $allocated,
            'disbursed' => $disbursed,
            'spent' => $spent,
            'remaining' => $allocated - $disbursed - $spent,
            'available_for_disbursement' => $allocated - $disbursed,
            'utilization_percentage' => $allocated > 0 ? (($disbursed + $spent) / $allocated) * 100 : 0
        ];
    } catch (Exception $e) {
        error_log("Get project budget summary error: " . $e->getMessage());
        return [
            'approved_budget' => 0,
            'allocated' => 0,
            'disbursed' => 0,
            'spent' => 0,
            'remaining' => 0,
            'available_for_disbursement' => 0,
            'utilization_percentage' => 0
        ];
    }
}

/**
 * Get transaction history with all status changes
 */
function get_transaction_history($project_id, $include_deleted = true) {
    global $pdo;
    
    try {
        $sql = "SELECT pt.*, 
                       creator.name as created_by_name,
                       modifier.name as modified_by_name,
                       ptd.original_filename as document_filename
                FROM project_transactions pt
                LEFT JOIN admins creator ON pt.created_by = creator.id
                LEFT JOIN admins modifier ON pt.modified_by = modifier.id
                LEFT JOIN project_transaction_documents ptd ON pt.id = ptd.transaction_id
                WHERE pt.project_id = ?";
        
        $params = [$project_id];
        
        if (!$include_deleted) {
            $sql .= " AND pt.transaction_status != 'deleted'";
        }
        
        $sql .= " ORDER BY pt.created_at DESC";
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
        
    } catch (Exception $e) {
        error_log("Get transaction history error: " . $e->getMessage());
        return [];
    }
}

/**
 * Create transaction with history tracking
 */
function create_transaction_with_history($project_id, $transaction_data, $admin_id) {
    global $pdo;
    
    try {
        $pdo->beginTransaction();
        
        // Insert the transaction
        $stmt = $pdo->prepare("INSERT INTO project_transactions 
            (project_id, transaction_type, amount, description, transaction_date, reference_number, 
             fund_source, funding_category, voucher_number, disbursement_method, receipt_number, 
             bank_receipt_reference, created_by, transaction_status, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', NOW())");
        
        $result = $stmt->execute([
            $project_id,
            $transaction_data['transaction_type'],
            $transaction_data['amount'],
            $transaction_data['description'],
            $transaction_data['transaction_date'],
            $transaction_data['reference_number'],
            $transaction_data['fund_source'],
            $transaction_data['funding_category'],
            $transaction_data['voucher_number'] ?? null,
            $transaction_data['disbursement_method'] ?? null,
            $transaction_data['receipt_number'] ?? null,
            $transaction_data['bank_receipt_reference'] ?? null,
            $admin_id
        ]);
        
        if (!$result) {
            throw new Exception('Failed to create transaction');
        }
        
        $transaction_id = $pdo->lastInsertId();
        
        // Log the activity
        log_activity('transaction_created', 
                    "Created {$transaction_data['transaction_type']} transaction of KES " . number_format($transaction_data['amount']), 
                    $admin_id, 'transaction', $transaction_id);
        
        $pdo->commit();
        return ['success' => true, 'transaction_id' => $transaction_id];
        
    } catch (Exception $e) {
        $pdo->rollBack();
        error_log("Create transaction with history error: " . $e->getMessage());
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

/**
 * Edit transaction with history preservation
 */
function edit_transaction_with_history($transaction_id, $new_data, $edit_reason, $admin_id) {
    global $pdo;
    
    try {
        $pdo->beginTransaction();
        
        // Get the original transaction
        $stmt = $pdo->prepare("SELECT * FROM project_transactions WHERE id = ?");
        $stmt->execute([$transaction_id]);
        $original = $stmt->fetch();
        
        if (!$original) {
            throw new Exception('Transaction not found');
        }
        
        // Create a history entry of the original
        $stmt = $pdo->prepare("INSERT INTO project_transactions 
            (project_id, transaction_type, amount, description, transaction_date, reference_number, 
             fund_source, funding_category, voucher_number, disbursement_method, receipt_number, 
             bank_receipt_reference, created_by, created_at, transaction_status, original_transaction_id, 
             edit_reason, modified_by, modified_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'edited', ?, ?, ?, NOW())");
        
        $stmt->execute([
            $original['project_id'], $original['transaction_type'], $original['amount'],
            $original['description'], $original['transaction_date'], $original['reference_number'],
            $original['fund_source'], $original['funding_category'], $original['voucher_number'],
            $original['disbursement_method'], $original['receipt_number'], $original['bank_receipt_reference'],
            $original['created_by'], $original['created_at'], $transaction_id, $edit_reason, $admin_id
        ]);
        
        // Update the original transaction
        $stmt = $pdo->prepare("UPDATE project_transactions SET 
            transaction_type = ?, amount = ?, description = ?, transaction_date = ?, reference_number = ?,
            fund_source = ?, funding_category = ?, voucher_number = ?, disbursement_method = ?,
            receipt_number = ?, bank_receipt_reference = ?, modified_by = ?, modified_at = NOW()
            WHERE id = ?");
        
        $result = $stmt->execute([
            $new_data['transaction_type'], $new_data['amount'], $new_data['description'],
            $new_data['transaction_date'], $new_data['reference_number'], $new_data['fund_source'],
            $new_data['funding_category'], $new_data['voucher_number'] ?? null, 
            $new_data['disbursement_method'] ?? null, $new_data['receipt_number'] ?? null,
            $new_data['bank_receipt_reference'] ?? null, $admin_id, $transaction_id
        ]);
        
        if (!$result) {
            throw new Exception('Failed to update transaction');
        }
        
        // Log the activity
        log_activity('transaction_edited', 
                    "Edited transaction ID $transaction_id. Reason: $edit_reason", 
                    $admin_id, 'transaction', $transaction_id);
        
        $pdo->commit();
        return ['success' => true];
        
    } catch (Exception $e) {
        $pdo->rollBack();
        error_log("Edit transaction with history error: " . $e->getMessage());
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

/**
 * Soft delete transaction with history preservation
 */
function delete_transaction_with_history($transaction_id, $deletion_reason, $admin_id) {
    global $pdo;
    
    try {
        $stmt = $pdo->prepare("UPDATE project_transactions SET 
            transaction_status = 'deleted', deletion_reason = ?, modified_by = ?, modified_at = NOW() 
            WHERE id = ?");
        
        $result = $stmt->execute([$deletion_reason, $admin_id, $transaction_id]);
        
        if (!$result) {
            throw new Exception('Failed to delete transaction');
        }
        
        // Log the activity
        log_activity('transaction_deleted', 
                    "Deleted transaction ID $transaction_id. Reason: $deletion_reason", 
                    $admin_id, 'transaction', $transaction_id);
        
        return ['success' => true];
        
    } catch (Exception $e) {
        error_log("Delete transaction with history error: " . $e->getMessage());
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

/**
 * Project Functions
 */
function get_projects($filters = []) {
    global $pdo;

    $sql = "SELECT p.*, d.name as department_name, w.name as ward_name, 
                   sc.name as sub_county_name, c.name as county_name
            FROM projects p
            JOIN departments d ON p.department_id = d.id
            JOIN wards w ON p.ward_id = w.id
            JOIN sub_counties sc ON p.sub_county_id = sc.id
            JOIN counties c ON p.county_id = c.id
            WHERE p.visibility = 'published'";

    $params = [];

    if (!empty($filters['search'])) {
        $sql .= " AND (p.project_name LIKE ? OR p.description LIKE ?)";
        $params[] = '%' . $filters['search'] . '%';
        $params[] = '%' . $filters['search'] . '%';
    }

    // Add other filters...

    $sql .= " ORDER BY p.created_at DESC";

    if (!empty($filters['limit'])) {
        $sql .= " LIMIT ?";
        $params[] = $filters['limit'];
    }

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

function get_all_projects($filters = [], $paginate = false, $per_page = 10) {
    global $pdo;

    $sql = "SELECT p.*, d.name as department_name, w.name as ward_name, 
                   sc.name as sub_county_name, c.name as county_name
            FROM projects p
            JOIN departments d ON p.department_id = d.id
            JOIN wards w ON p.ward_id = w.id
            JOIN sub_counties sc ON p.sub_county_id = sc.id
            JOIN counties c ON p.county_id = c.id
            WHERE 1=1";

    $count_sql = "SELECT COUNT(*) as total FROM projects p WHERE 1=1";
    $params = $count_params = [];

    // Add role-based filtering if created_by is specified
    if (!empty($filters['created_by'])) {
        $sql .= " AND p.created_by = ?";
        $count_sql .= " AND p.created_by = ?";
        $params[] = $filters['created_by'];
        $count_params[] = $filters['created_by'];
    }

    // Search filter
    if (!empty($filters['search'])) {
        $search_term = '%' . $filters['search'] . '%';
        $sql .= " AND (p.project_name LIKE ? OR p.description LIKE ?)";
        $count_sql .= " AND (p.project_name LIKE ? OR p.description LIKE ?)";
        $params[] = $search_term;
        $params[] = $search_term;
        $count_params[] = $search_term;
        $count_params[] = $search_term;
    }

    // Status filter
    if (!empty($filters['status'])) {
        $sql .= " AND p.status = ?";
        $count_sql .= " AND p.status = ?";
        $params[] = $filters['status'];
        $count_params[] = $filters['status'];
    }

    // Department filter
    if (!empty($filters['department'])) {
        $sql .= " AND p.department_id = ?";
        $count_sql .= " AND p.department_id = ?";
        $params[] = $filters['department'];
        $count_params[] = $filters['department'];
    }

    // Year filter
    if (!empty($filters['year'])) {
        $sql .= " AND p.project_year = ?";
        $count_sql .= " AND p.project_year = ?";
        $params[] = $filters['year'];
        $count_params[] = $filters['year'];
    }

    // Visibility filter
    if (!empty($filters['visibility'])) {
        $sql .= " AND p.visibility = ?";
        $count_sql .= " AND p.visibility = ?";
        $params[] = $filters['visibility'];
        $count_params[] = $filters['visibility'];
    }

    $sql .= " ORDER BY p.created_at DESC";

    if ($paginate) {
        $page = $filters['page'] ?? 1;
        $offset = ($page - 1) * $per_page;
        $sql .= " LIMIT ?, ?";
        $params[] = $offset;
        $params[] = $per_page;
    }

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $projects = $stmt->fetchAll();

    if ($paginate) {
        $count_stmt = $pdo->prepare($count_sql);
        $count_stmt->execute($count_params);
        $total = $count_stmt->fetchColumn();

        return [
            'projects' => $projects,
            'total' => $total,
            'per_page' => $per_page,
            'current_page' => $page ?? 1,
            'total_pages' => ceil($total / $per_page)
        ];
    }

    return $projects;
}



function get_project_by_id($id) {
    global $pdo;
    $sql = "SELECT p.*, d.name as department_name, w.name as ward_name, 
                   sc.name as sub_county_name, c.name as county_name
            FROM projects p
            JOIN departments d ON p.department_id = d.id
            JOIN wards w ON p.ward_id = w.id
            JOIN sub_counties sc ON p.sub_county_id = sc.id
            JOIN counties c ON p.county_id = c.id
            WHERE p.id = ?";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$id]);
    return $stmt->fetch();
}

function get_project_years() {
    global $pdo;
    $stmt = $pdo->query("SELECT DISTINCT project_year FROM projects ORDER BY project_year DESC");
    return $stmt->fetchAll(PDO::FETCH_COLUMN);
}

/**
 * Get Migori sub-counties only
 */
function get_migori_sub_counties() {
    global $pdo;
    $stmt = $pdo->prepare("SELECT sc.* FROM sub_counties sc 
                          JOIN counties c ON sc.county_id = c.id 
                          WHERE c.name = 'Migori' ORDER BY sc.name");
    $stmt->execute();
    return $stmt->fetchAll();
}

/**
 * Location Functions
 */
function get_counties() {
    global $pdo;
    $stmt = $pdo->query("SELECT * FROM counties ORDER BY name");
    return $stmt->fetchAll();
}

function get_sub_counties($county_id = null) {
    global $pdo;
    if ($county_id) {
        $stmt = $pdo->prepare("SELECT * FROM sub_counties WHERE county_id = ? ORDER BY name");
        $stmt->execute([$county_id]);
    } else {
        $stmt = $pdo->query("SELECT sc.*, c.name as county_name FROM sub_counties sc JOIN counties c ON sc.county_id = c.id ORDER BY c.name, sc.name");
    }
    return $stmt->fetchAll();
}

function get_wards($sub_county_id = null) {
    global $pdo;
    if ($sub_county_id) {
        $stmt = $pdo->prepare("SELECT * FROM wards WHERE sub_county_id = ? ORDER BY name");
        $stmt->execute([$sub_county_id]);
    } else {
        $stmt = $pdo->query("SELECT w.*, sc.name as sub_county_name FROM wards w JOIN sub_counties sc ON w.sub_county_id = sc.id ORDER BY sc.name, w.name");
    }
    return $stmt->fetchAll();
}

function get_departments() {
    $cache_key = 'departments_list';
    $cached = CacheManager::get($cache_key);

    if ($cached !== null) {
        return $cached;
    }

    global $pdo;
    $stmt = $pdo->query("SELECT * FROM departments ORDER BY name");
    $result = $stmt->fetchAll();

    CacheManager::set($cache_key, $result, 86400);
    return $result;
}

/**
 * Project Steps Functions
 */
function create_project_steps($project_id, $department_name) {
    global $pdo;

    try {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM project_steps WHERE project_id = ?");
        $stmt->execute([$project_id]);
        $existing_steps = $stmt->fetchColumn();

        if ($existing_steps > 0) {
            return ['success' => false, 'message' => 'Project already has steps defined'];
        }

        $steps_template = get_default_project_steps($department_name);

        if (empty($steps_template)) {
            return ['success' => false, 'message' => 'No step template found for this department'];
        }

        $pdo->beginTransaction();
        $stmt = $pdo->prepare("INSERT INTO project_steps (project_id, step_name, step_description, step_order, status, expected_duration_days) VALUES (?, ?, ?, ?, 'pending', ?)");

        foreach ($steps_template as $index => $step) {
            $stmt->execute([
                $project_id,
                $step['name'],
                $step['description'],
                $index + 1,
                $step['duration'] ?? 30
            ]);
        }

        $pdo->commit();
        return ['success' => true, 'message' => 'Project steps created successfully'];

    } catch (Exception $e) {
        $pdo->rollback();
        error_log("Create project steps error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to create project steps'];
    }
}

function get_project_steps($project_id) {
    global $pdo;
    $stmt = $pdo->prepare("SELECT * FROM project_steps WHERE project_id = ? ORDER BY order_number");
    $stmt->execute([$project_id]);
    return $stmt->fetchAll();
}

function calculate_project_progress($project_id) {
    global $pdo;

    try {
        // Step progress (50% of total)
        $stmt = $pdo->prepare("SELECT * FROM project_steps WHERE project_id = ? ORDER BY step_number");
        $stmt->execute([$project_id]);
        $steps = $stmt->fetchAll();

        $total_steps = count($steps);
        $step_score = 0;
        foreach ($steps as $step) {
            if ($step['status'] === 'completed') $step_score += 1;
            elseif ($step['status'] === 'in_progress') $step_score += 0.5;
        }
        $step_progress = ($total_steps > 0) ? ($step_score / $total_steps) * 50 : 0;

        // Budget progress (50% of total) - handle missing table gracefully
        $budget_progress = 0;
        try {
            // Get project total budget and transactions
            $stmt = $pdo->prepare("SELECT total_budget FROM projects WHERE id = ?");
            $stmt->execute([$project_id]);
            $project = $stmt->fetch();
            $total_budget = $project['total_budget'] ?? 0;

            $stmt = $pdo->prepare("
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

            // Calculate budget utilization as percentage of allocated vs spent
            if ($allocated > 0) {
                $budget_utilization = min($spent / $allocated, 1);
                $budget_progress = $budget_utilization * 50;
            } elseif ($total_budget > 0 && $spent > 0) {
                // Fallback: use spent vs total budget
                $budget_utilization = min($spent / $total_budget, 1);
                $budget_progress = $budget_utilization * 50;
            }
        } catch (PDOException $e) {
            // If project_transactions table doesn't exist, budget progress is 0
            $budget_progress = 0;
        }

        return round($step_progress + $budget_progress, 1);

    } catch (Exception $e) {
        error_log("Calculate project progress error: " . $e->getMessage());
        return 0;
    }
}

function update_step_status($step_id, $status, $completion_date = null) {
    global $pdo;

    try {
        if ($completion_date === null && $status === 'completed') {
            $completion_date = date('Y-m-d');
        }

        $sql = "UPDATE project_steps SET status = ?, completion_date = ? WHERE id = ?";
        $stmt = $pdo->prepare($sql);
        $result = $stmt->execute([$status, $completion_date, $step_id]);

        if ($result) {
            $stmt = $pdo->prepare("SELECT project_id FROM project_steps WHERE id = ?");
            $stmt->execute([$step_id]);
            $project_id = $stmt->fetchColumn();

            $progress = calculate_project_progress($project_id);
            $stmt = $pdo->prepare("UPDATE projects SET progress_percentage = ? WHERE id = ?");
            $stmt->execute([$progress, $project_id]);
        }

        return $result;
    } catch (Exception $e) {
        error_log("Update step status error: " . $e->getMessage());
        return false;
    }
}

function update_project_progress($project_id) {
    require_once 'projectProgressCalculator.php';
    return update_project_progress_and_status($project_id);
}

/**
 * Comments and Feedback Functions
 */
function add_project_comment($project_id, $comment_text, $user_name, $user_email = null, $parent_id = 0) {
    global $pdo;

    try {
        if (empty($project_id) || empty($comment_text) || empty($user_name)) {
            error_log("Comment validation failed - Project ID: $project_id, User: '$user_name', Comment length: " . strlen($comment_text));
            return ['success' => false, 'message' => 'Missing required fields'];
        }

        $user_ip = $_SERVER['REMOTE_ADDR'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '127.0.0.1';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $subject = $parent_id > 0 ? "Reply to comment" : "Project Comment";

        $sql = "INSERT INTO feedback (project_id, citizen_name, citizen_email, subject, message, status, parent_comment_id, user_ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, NOW())";
        $stmt = $pdo->prepare($sql);

        $result = $stmt->execute([$project_id, $user_name, $user_email, $subject, $comment_text, $parent_id, $user_ip, $user_agent]);

        if ($result) {
            $comment_id = $pdo->lastInsertId();
            error_log("Comment successfully inserted with ID: $comment_id for project: $project_id by user: $user_name");
            log_activity("New comment submitted for project ID: $project_id by $user_name from IP: $user_ip");
            return ['success' => true, 'message' => 'Comment submitted successfully and is pending approval'];
        } else {
            error_log("Failed to insert comment - SQL error: " . implode(', ', $stmt->errorInfo()));
            return ['success' => false, 'message' => 'Database error: Failed to save comment'];
        }
    } catch (Exception $e) {
        error_log("Add comment error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to submit comment. Please try again.'];
    }
}

function get_project_comments($project_id) {
    global $pdo;

    try {
        $user_ip = $_SERVER['REMOTE_ADDR'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '127.0.0.1';

        $sql = "SELECT f.*, 
                       a.name as admin_name,
                       a.email as admin_email,
                       CASE WHEN f.user_ip = ? AND f.status = 'pending' THEN 1 ELSE 0 END as is_user_pending,
                       CASE WHEN f.subject = 'Admin Response' OR f.citizen_name = '' OR f.citizen_name IS NULL THEN 1 ELSE 0 END as is_admin_comment
                FROM feedback f
                LEFT JOIN admins a ON f.responded_by = a.id 
                WHERE f.project_id = ? 
                AND (f.status IN ('approved', 'reviewed', 'responded') OR (f.status = 'pending' AND f.user_ip = ?))
                AND (f.parent_comment_id IS NULL OR f.parent_comment_id = 0)
                ORDER BY f.created_at DESC";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([$user_ip, $project_id, $user_ip]);
        $main_comments = $stmt->fetchAll();

        $comments_with_responses = [];

        foreach ($main_comments as $comment) {
            $comment_array = $comment;

            if (!empty($comment['admin_response']) && !empty($comment['responded_by']) && $comment['status'] === 'responded') {
                $admin_comment = [
                    'id' => 'admin_' . $comment['id'],
                    'project_id' => $comment['project_id'],
                    'citizen_name' => '',
                    'citizen_email' => '',
                    'subject' => 'Admin Response',
                    'message' => $comment['admin_response'],
                    'status' => 'approved',
                    'parent_comment_id' => $comment['id'],
                    'user_ip' => '',
                    'user_agent' => '',
                    'created_at' => $comment['updated_at'],
                    'admin_name' => $comment['admin_name'] ?? 'Admin',
                    'admin_email' => $comment['admin_email'],
                    'is_user_pending' => 0,
                    'is_admin_comment' => 1,
                    'responded_by' => $comment['responded_by']
                ];

                $comment_array['admin_response_comment'] = $admin_comment;
            }

            $comment_array['replies'] = get_comment_replies_limited($comment['id'], 3);
            $comment_array['total_replies'] = get_comment_replies_count($comment['id']);

            $comments_with_responses[] = $comment_array;
        }

        return $comments_with_responses;

    } catch (Exception $e) {
        error_log("Get project comments error: " . $e->getMessage());
        return [];
    }
}

function get_comment_replies_limited($parent_id, $limit = 3, $user_ip = null) {
    global $pdo;

    try {
        if (!$user_ip) {
            $user_ip = $_SERVER['REMOTE_ADDR'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '127.0.0.1';
        }

        $sql = "SELECT f.*, 
                       a.name as admin_name,
                       a.email as admin_email,
                       CASE WHEN f.user_ip = ? AND f.status = 'pending' THEN 1 ELSE 0 END as is_user_pending,
                       CASE WHEN f.subject = 'Admin Response' OR f.citizen_name = '' OR f.citizen_name IS NULL THEN 1 ELSE 0 END as is_admin_comment
                FROM feedback f
                LEFT JOIN admins a ON f.responded_by = a.id 
                WHERE f.parent_comment_id = ? 
                AND (f.status IN ('approved', 'reviewed', 'responded') OR (f.status = 'pending' AND f.user_ip = ?))
                ORDER BY f.created_at ASC
                LIMIT ?";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([$user_ip, $parent_id, $user_ip, $limit]);
        return $stmt->fetchAll();

    } catch (Exception $e) {
        error_log("Get comment replies limited error: " . $e->getMessage());
        return [];
    }
}

function get_comment_replies_count($parent_id) {
    global $pdo;

    try {
        $sql = "SELECT COUNT(*) FROM feedback 
                WHERE parent_comment_id = ? 
                AND status IN ('approved', 'reviewed', 'responded')";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([$parent_id]);
        return $stmt->fetchColumn();

    } catch (Exception $e) {
        error_log("Get comment replies count error: " . $e->getMessage());
        return 0;
    }
}

function get_approved_comments_count($project_id) {
    global $pdo;

    try {
        $sql = "SELECT COUNT(*) FROM feedback 
                WHERE project_id = ? 
                AND status IN ('approved', 'reviewed', 'responded')";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([$project_id]);
        return $stmt->fetchColumn();

    } catch (Exception $e) {
        error_log("Get approved comments count error: " . $e->getMessage());
        return 0;
    }
}

function get_feedback_for_admin($filters = [], $page = 1, $per_page = 20) {
    global $pdo;
    $offset = ($page - 1) * $per_page;

    try {
        $sql = "SELECT f.*, 
                       p.project_name,
                       a.name as admin_name,
                       a.email as admin_email
                FROM feedback f
                LEFT JOIN projects p ON f.project_id = p.id
                LEFT JOIN admins a ON f.responded_by = a.id
                WHERE 1=1";

        $params = [];

        if (!empty($filters['status'])) {
            $sql .= " AND f.status = ?";
            $params[] = $filters['status'];
        }

        if (!empty($filters['project_id'])) {
            $sql .= " AND f.project_id = ?";
            $params[] = $filters['project_id'];
        }

        if (!empty($filters['search'])) {
            $sql .= " AND (f.message LIKE ? OR f.citizen_name LIKE ? OR p.project_name LIKE ?)";
            $search_param = '%' . $filters['search'] . '%';
            $params[] = $search_param;
            $params[] = $search_param;
            $params[] = $search_param;
        }

        $sql .= " ORDER BY f.created_at DESC LIMIT ? OFFSET ?";
        $params[] = $per_page;
        $params[] = $offset;

        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();

     } catch (Exception $e) {
        error_log("Get feedback for admin error: " . $e->getMessage());
        return [];
    }
}

function get_feedback_count($filters = []) {
    global $pdo;

    try {
        $sql = "SELECT COUNT(*) FROM feedback f
                LEFT JOIN projects p ON f.project_id = p.id
                WHERE 1=1";

        $params = [];

        if (!empty($filters['status'])) {
            $sql .= " AND f.status = ?";
            $params[] = $filters['status'];
        }

        if (!empty($filters['project_id'])) {
            $sql .= " AND f.project_id = ?";
            $params[] = $filters['project_id'];
        }

        if (!empty($filters['search'])) {
            $sql .= " AND (f.message LIKE ? OR f.citizen_name LIKE ? OR p.project_name LIKE ?)";
            $search_param = '%' . $filters['search'] . '%';
            $params[] = $search_param;
            $params[] = $search_param;
            $params[] = $search_param;
        }

        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchColumn();

    } catch (Exception $e) {
        error_log("Get feedback count error: " . $e->getMessage());
        return 0;
    }
}

function get_paginated_activities($page = 1, $per_page = 25) {
    global $pdo;
    $offset = ($page - 1) * $per_page;

    try {
        $sql = "SELECT al.*, a.name as admin_name, a.email as admin_email 
                FROM admin_activity_log al 
                LEFT JOIN admins a ON al.admin_id = a.id 
                ORDER BY al.created_at DESC 
                LIMIT ? OFFSET ?";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([$per_page, $offset]);
        return $stmt->fetchAll();
    } catch (Exception $e) {
        // Fallback to activity_logs table
        try {
            $sql = "SELECT al.*, a.name as admin_name, a.email as admin_email 
                    FROM activity_logs al 
                    LEFT JOIN admins a ON al.admin_id = a.id 
                    ORDER BY al.created_at DESC 
                    LIMIT ? OFFSET ?";

            $stmt = $pdo->prepare($sql);
            $stmt->execute([$per_page, $offset]);
            return $stmt->fetchAll();
        } catch (Exception $e2) {
            error_log("Get paginated activities error: " . $e2->getMessage());
            return [];
        }
    }
}

function get_total_activities_count() {
    global $pdo;

    try {
        $stmt = $pdo->query("SELECT COUNT(*) FROM admin_activity_log");
        return $stmt->fetchColumn();
    } catch (Exception $e) {
        try {
            $stmt = $pdo->query("SELECT COUNT(*) FROM activity_logs");
            return $stmt->fetchColumn();
        } catch (Exception $e2) {
            error_log("Get total activities count error: " . $e2->getMessage());
            return 0;
        }
    }
}

function get_comments_for_admin($filters = []) {
    global $pdo;

    try {
        $sql = "SELECT f.*, 
                       p.project_name,
                       a.name as admin_name,
                       a.email as admin_email,
                       f.responded_by IS NOT NULL as is_admin_comment,
                       parent.citizen_name as parent_user_name
                FROM feedback f
                LEFT JOIN projects p ON f.project_id = p.id
                LEFT JOIN admins a ON f.responded_by = a.id
                LEFT JOIN feedback parent ON f.parent_comment_id = parent.id
                WHERE (f.subject LIKE '%comment%' OR f.subject LIKE '%Comment%')";

        $params = [];

        if (!empty($filters['status'])) {
            $sql .= " AND f.status = ?";
            $params[] = $filters['status'];
        }

        if (!empty($filters['project_id'])) {
            $sql .= " AND f.project_id = ?";
            $params[] = $filters['project_id'];
        }

        if (!empty($filters['search'])) {
            $sql .= " AND (f.message LIKE ? OR f.citizen_name LIKE ? OR p.project_name LIKE ?)";
            $search_param = '%' . $filters['search'] . '%';
            $params[] = $search_param;
            $params[] = $search_param;
            $params[] = $search_param;
        }

        $sql .= " ORDER BY f.created_at DESC";

        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();

    } catch (Exception $e) {
        error_log("Get comments for admin error: " . $e->getMessage());
        return [];
    }
}

function moderate_comment($comment_id, $status, $admin_id = null) {
    global $pdo;

    try {
        if (!in_array($status, ['approved', 'rejected'])) {
            return ['success' => false, 'message' => 'Invalid status'];
        }

        $stmt = $pdo->prepare("UPDATE feedback SET status = ?, responded_by = ?, responded_at = NOW() WHERE id = ?");
        $stmt->execute([$status, $admin_id, $comment_id]);

        return ['success' => true, 'message' => 'Comment ' . $status . ' successfully'];

    } catch (Exception $e) {
        error_log("Moderate comment error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to moderate comment'];
    }
}

/**
 * Prepared Responses Functions
 */
function add_prepared_response($response_text) {
    global $pdo;

    try {
        $sql = "INSERT INTO feedback_templates (response_text, created_at) VALUES (?, NOW())";
        $stmt = $pdo->prepare($sql);
        $result = $stmt->execute([$response_text]);

        if ($result) {
            return ['success' => true, 'message' => 'Prepared response added successfully'];
        } else {
            error_log("Failed to insert prepared response - SQL error: " . implode(', ', $stmt->errorInfo()));
            return ['success' => false, 'message' => 'Database error: Failed to save prepared response'];
        }
    } catch (Exception $e) {
        error_log("Add prepared response error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to add prepared response. Please try again.'];
    }
}

function delete_prepared_response($response_id) {
    global $pdo;

    try {
        $sql = "DELETE FROM feedback_templates WHERE id = ?";
        $stmt = $pdo->prepare($sql);
        $result = $stmt->execute([$response_id]);

        if ($result) {
            return ['success' => true, 'message' => 'Prepared response deleted successfully'];
        } else {
            error_log("Failed to delete prepared response - SQL error: " . implode(', ', $stmt->errorInfo()));
            return ['success' => false, 'message' => 'Database error: Failed to delete prepared response'];
        }
    } catch (Exception $e) {
        error_log("Delete prepared response error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to delete prepared response. Please try again.'];
    }
}

function update_prepared_response($response_id, $response_text) {
    global $pdo;

    try {
        $sql = "UPDATE feedback_templates SET response_text = ? WHERE id = ?";
        $stmt = $pdo->prepare($sql);
        $result = $stmt->execute([$response_text, $response_id]);

        if ($result) {
            return ['success' => true, 'message' => 'Prepared response updated successfully'];
        } else {
            error_log("Failed to update prepared response - SQL error: " . implode(', ', $stmt->errorInfo()));
            return ['success' => false, 'message' => 'Database error: Failed to update prepared response'];
        }
    } catch (Exception $e) {
        error_log("Update prepared response error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to update prepared response. Please try again.'];
    }
}

function secure_file_upload($file, $allowed_extensions = ['pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx'], $max_size = 20971520) {
    // Initialize result array
    $result = [
        'success' => false,
        'message' => '',
        'filename' => '',
        'original_name' => $file['name'] ?? '',
        'file_size' => $file['size'] ?? 0,
        'mime_type' => '',
        'file_path' => ''
    ];

    // Check if file was uploaded
    if (!isset($file) || !isset($file['error'])) {
        $result['message'] = 'No file was uploaded';
        return $result;
    }

    // Check for upload errors
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $error_messages = [
            UPLOAD_ERR_INI_SIZE => 'File exceeds server upload limit',
            UPLOAD_ERR_FORM_SIZE => 'File exceeds form upload limit',
            UPLOAD_ERR_PARTIAL => 'File was only partially uploaded',
            UPLOAD_ERR_NO_FILE => 'No file was uploaded',
            UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',
            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',
            UPLOAD_ERR_EXTENSION => 'File upload stopped by extension'
        ];
        $result['message'] = $error_messages[$file['error']] ?? 'Unknown upload error';
        return $result;
    }

    // Validate file extension
    $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($extension, $allowed_extensions)) {
        $result['message'] = 'Invalid file type. Allowed types: ' . implode(', ', $allowed_extensions);
        return $result;
    }

    // Validate file size
    if ($file['size'] > $max_size) {
        $result['message'] = 'File too large. Maximum size: ' . format_bytes($max_size);
        return $result;
    }

    // Get MIME type
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime_type = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);

    // Create upload directory if it doesn't exist
    if (!is_dir(UPLOAD_PATH)) {
        if (!mkdir(UPLOAD_PATH, 0755, true)) {
            $result['message'] = 'Failed to create upload directory';
            return $result;
        }
    }

    // Generate secure filename
    $filename = uniqid('doc_', true) . '.' . $extension;
    $file_path = UPLOAD_PATH . $filename;

    // Move the file
    if (move_uploaded_file($file['tmp_name'], $file_path)) {
        // Set secure permissions
        chmod($file_path, 0644);

        // Return success with file information
        return [
            'success' => true,
            'message' => 'File uploaded successfully',
            'filename' => $filename,
            'original_name' => basename($file['name']),
            'file_size' => $file['size'],
            'mime_type' => $mime_type,
            'file_path' => $file_path
        ];
    }

    $result['message'] = 'Failed to save uploaded file';
    return $result;
}

// Helper function to format bytes
function format_bytes($bytes, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    return round($bytes, $precision) . ' ' . $units[$pow];
}

function handle_file_upload($file, $allowed_types = ['csv', 'xlsx']) {
    if (!isset($file) || $file['error'] !== UPLOAD_ERR_OK) {
        return ['success' => false, 'message' => 'File upload error'];
    }
    $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($extension, $allowed_types)) {
        return ['success' => false, 'message' => 'Invalid file type'];
    }
    if ($file['size'] > MAX_FILE_SIZE) {
        return ['success' => false, 'message' => 'File too large'];
    }
    $filename = uniqid() . '_' . time() . '.' . $extension;
    $filepath = UPLOAD_PATH . $filename;
    if (!is_dir(UPLOAD_PATH)) {
        mkdir(UPLOAD_PATH, 0755, true);
    }
    if (move_uploaded_file($file['tmp_name'], $filepath)) {
        return ['success' => true, 'filename' => $filename, 'filepath' => $filepath];
    }
    return ['success' => false, 'message' => 'Failed to save file'];
}

/**
 * Check if current admin has specific permission
 * This function wraps the RBAC system for backward compatibility
 */
function verify_admin_permission($permission) {
    if (!isset($_SESSION['admin_id'])) {
        return false;
    }

    // Super admin has all permissions
    if ($_SESSION['admin_role'] === 'super_admin') {
        return true;
    }

    global $pdo;
    try {
        $stmt = $pdo->prepare("
            SELECT COUNT(*) 
            FROM admin_permissions ap
            JOIN permissions p ON ap.permission_id = p.id
            WHERE ap.admin_id = ? AND p.name = ? AND ap.is_active = 1
        ");
        $stmt->execute([$_SESSION['admin_id'], $permission]);
        return $stmt->fetchColumn() > 0;
    } catch (Exception $e) {
        error_log("Permission check error: " . $e->getMessage());
        return false;
    }
}

function verify_permission($permission_key, $admin_id = null) {
    return has_permission($permission_key, $admin_id);
}

function can_view_project($project_id, $admin_id = null) {
    global $pdo;

    try {
        if (!$admin_id && isset($_SESSION['admin_id'])) {
            $admin_id = $_SESSION['admin_id'];
        }

        if (!$admin_id) return false;

        $stmt = $pdo->prepare("SELECT role FROM admins WHERE id = ?");
        $stmt->execute([$admin_id]);
        $role = $stmt->fetchColumn();

        if ($role === 'super_admin') return true;

        if (has_permission('view_all_projects', $admin_id)) {
            return true;
        }

        $stmt = $pdo->prepare("SELECT created_by FROM projects WHERE id = ?");
        $stmt->execute([$project_id]);
        $created_by = $stmt->fetchColumn();

        return $created_by == $admin_id;
    } catch (Exception $e) {
        error_log("Can view project error: " . $e->getMessage());
        return false;
    }
}

function grant_permission($admin_id, $permission_key, $granted_by = null) {
    global $pdo;

    try {
        if (!$granted_by && isset($_SESSION['admin_id'])) {
            $granted_by = $_SESSION['admin_id'];
        }

        $sql = "INSERT INTO admin_permissions (admin_id, permission_key, can_access, granted_by) 
                VALUES (?, ?, TRUE, ?) 
                ON DUPLICATE KEY UPDATE can_access = TRUE, granted_by = ?, granted_at = NOW()";
        $stmt = $pdo->prepare($sql);
        $result = $stmt->execute([$admin_id, $permission_key, $granted_by, $granted_by]);

        if ($result) {
            log_activity('permission_granted', "Permission '$permission_key' granted to admin ID $admin_id", $granted_by, 'admin', $admin_id);
        }

        return $result;
    } catch (Exception $e) {
        error_log("Grant permission error: " . $e->getMessage());
        return false;
    }
}
function revoke_permission($admin_id, $permission_key, $revoked_by = null) {
    global $pdo;

    try {
        if (!$revoked_by && isset($_SESSION['admin_id'])) {
            $revoked_by = $_SESSION['admin_id'];
        }

        $sql = "UPDATE admin_permissions SET can_access = FALSE WHERE admin_id = ? AND permission_key = ?";
        $stmt = $pdo->prepare($sql);
        $result = $stmt->execute([$admin_id, $permission_key]);

        if ($result) {
            log_activity('permission_revoked', "Permission '$permission_key' revoked from admin ID $admin_id", $revoked_by, 'admin', $admin_id);
        }

        return $result;
    } catch (Exception $e) {
        error_log("Revoke permission error: " . $e->getMessage());
        return false;
    }
}

/**
 * Logging and Activity Functions
 */
function log_activity($activity_type, $description, $admin_id = null, $target_type = null, $target_id = null, $additional_data = null) {
    global $pdo;

    try {
        if (!$admin_id && isset($_SESSION['admin_id'])) {
            $admin_id = $_SESSION['admin_id'];
        }

        $ip_address = $_SERVER['REMOTE_ADDR'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '127.0.0.1';
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        $additional_json = $additional_data ? json_encode($additional_data) : null;

        $sql = "INSERT INTO admin_activity_log (admin_id, activity_type, activity_description, target_type, target_id, ip_address, user_agent, additional_data) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        $stmt = $pdo->prepare($sql);
        $result = $stmt->execute([$admin_id, $activity_type, $description, $target_type, $target_id, $ip_address, $user_agent, $additional_json]);

        Logger::info("Activity: [$activity_type] $description", [
            'admin_id' => $admin_id,
            'target' => $target_type ? "$target_type:$target_id" : null,
            'ip' => $ip_address
        ]);

        return $result;
    } catch (Exception $e) {
        Logger::error("Activity logging failed", [
            'error' => $e->getMessage(),
            'activity_type' => $activity_type,
            'description' => $description
        ]);
        return false;
    }
}

function get_recent_activities($limit = 10, $admin_id = null) {
    global $pdo;

    try {
        // Try admin_activity_log first, fallback to activity_logs
        $tables_to_try = ['admin_activity_log', 'activity_logs'];

        foreach ($tables_to_try as $table) {
            $sql = "SELECT al.*, a.name as admin_name, a.email as admin_email 
                    FROM $table al 
                    LEFT JOIN admins a ON al.admin_id = a.id ";
            $params = [];

            if ($admin_id) {
                $sql .= "WHERE al.admin_id = ? ";
                $params[] = $admin_id;
            }

            $sql .= "ORDER BY al.created_at DESC LIMIT ?";
            $params[] = $limit;

            try {
                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);
                return $stmt->fetchAll();
            } catch (Exception $e) {
                // Continue to next table if this one doesn't exist
                continue;
            }
        }

        return [];
    } catch (Exception $e) {
        error_log("Get activities error: " . $e->getMessage());
        return [];
    }
}

/**
 * Check if admin has grievances to handle
 */
function has_admin_grievances($admin_id) {
    global $pdo;

    try {
        $stmt = $pdo->prepare("
            SELECT COUNT(*) 
            FROM feedback f
            JOIN projects p ON f.project_id = p.id
            WHERE p.created_by = ? AND f.status = 'grievance'
        ");
        $stmt->execute([$admin_id]);
        return $stmt->fetchColumn() > 0;
    } catch (Exception $e) {
        error_log("Check admin grievances error: " . $e->getMessage());
        return false;
    }
}

/**
 * Get count of admin's grievances
 */
function get_admin_grievance_count($admin_id) {
    global $pdo;

    try {
        $stmt = $pdo->prepare("
            SELECT COUNT(*) 
            FROM feedback f
            JOIN projects p ON f.project_id = p.id
            WHERE p.created_by = ? AND f.status = 'grievance'
        ");
        $stmt->execute([$admin_id]);
        return $stmt->fetchColumn();
    } catch (Exception $e) {
        error_log("Get admin grievance count error: " . $e->getMessage());
        return 0;
    }
}

/**
 * Send email notification
 */
function send_email_notification($to_email, $subject, $message, $from_admin_id = null) {
    global $pdo;

    try {
        // Get sender information
        $from_email = 'noreply@migoricounty.go.ke';
        $from_name = 'Migori County PMC';

        if ($from_admin_id) {
            $stmt = $pdo->prepare("SELECT name, email FROM admins WHERE id = ?");
            $stmt->execute([$from_admin_id]);
            $admin = $stmt->fetch();
            if ($admin) {
                $from_name = $admin['name'];
                $from_email = $admin['email'];
            }
        }

        // Email headers
        $headers = [
            'From' => "$from_name <$from_email>",
            'Reply-To' => $from_email,
            'Content-Type' => 'text/html; charset=UTF-8',
            'X-Mailer' => 'Migori County PMC System'
        ];

        $header_string = '';
        foreach ($headers as $key => $value) {
            $header_string .= "$key: $value\r\n";
        }

        // HTML email template
        $html_message = "
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .header { background-color: #1e40af; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; }
                .footer { background-color: #f3f4f6; padding: 10px; text-align: center; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class='header'>
                <h2>Migori County Project Management</h2>
            </div>
            <div class='content'>
                <p>Dear Citizen,</p>
                <p>$message</p>
                <p>Best regards,<br>$from_name<br>Migori County Administration</p>
            </div>
            <div class='footer'>
                <p>This is an automated message from Migori County PMC System. Please do not reply to this email.</p>
            </div>
        </body>
        </html>
        ";

        // Send email
        $result = mail($to_email, $subject, $html_message, $header_string);

        // Log email attempt
        log_activity('email_sent', "Email sent to $to_email with subject: $subject", $from_admin_id);

        return $result;

    } catch (Exception $e) {
        error_log("Email sending error: " . $e->getMessage());
        return false;
    }
}

/**
 * Cache Management Class
 */
class CacheManager {
    private static $cache_dir = __DIR__ . '/../cache/';
    private static $default_ttl = 3600; // 1 hour

    public static function get($key) {
        $cache_file = self::$cache_dir . md5($key) . '.cache';

        if (file_exists($cache_file)) {
            $data = unserialize(file_get_contents($cache_file));

            if ($data['expires'] > time()) {
                return $data['value'];
            }

            unlink($cache_file);
        }

        return null;
    }

    public static function set($key, $value, $ttl = null) {
        if (!is_dir(self::$cache_dir)) {
            mkdir(self::$cache_dir, 0755, true);
        }

        $cache_file = self::$cache_dir . md5($key) . '.cache';
        $ttl = $ttl ?? self::$default_ttl;

        $data = [
            'value' => $value,
            'expires' => time() + $ttl
        ];

        return file_put_contents($cache_file, serialize($data));
    }

    public static function delete($key) {
        $cache_file = self::$cache_dir . md5($key) . '.cache';
        if (file_exists($cache_file)) {
            return unlink($cache_file);
        }
        return false;
    }
}

/**
 * Logger Class
 */
class Logger {
    const LEVEL_DEBUG = 0;
    const LEVEL_INFO = 1;
    const LEVEL_WARNING = 2;
    const LEVEL_ERROR = 3;
    const LEVEL_CRITICAL = 4;

    private static $log_level = self::LEVEL_INFO;
    private static $log_file = __DIR__ . '/../logs/app.log';

    public static function setLevel($level) {
        self::$log_level = $level;
    }

    public static function debug($message, $context = []) {
        self::log(self::LEVEL_DEBUG, 'DEBUG', $message, $context);
    }

    public static function info($message, $context = []) {
        self::log(self::LEVEL_INFO, 'INFO', $message, $context);
    }

    public static function warning($message, $context = []) {
        self::log(self::LEVEL_WARNING, $message, $context);
    }

    public static function error($message, $context = []) {
        self::log(self::LEVEL_ERROR, 'ERROR', $message, $context);
    }

    public static function critical($message, $context = []) {
        self::log(self::LEVEL_CRITICAL, 'CRITICAL', $message, $context);
    }

    private static function log($level, $level_name, $message, $context) {
        if ($level < self::$log_level) {
            return;
        }

        if (!is_dir(dirname(self::$log_file))) {
            mkdir(dirname(self::$log_file), 0755, true);
        }

        $log_entry = sprintf(
            "[%s] %s: %s %s\n",
            date('Y-m-d H:i:s'),
            $level_name,
            $message,
            !empty($context) ? json_encode($context) : ''
        );

        file_put_contents(self::$log_file, $log_entry, FILE_APPEND);

        if (defined('ENVIRONMENT') && ENVIRONMENT === 'production') {
            syslog($level, $message . (!empty($context) ? ' ' . json_encode($context) : ''));
        }
    }
}

/**
 * Session and Security Functions
 */
function secure_session_start() {
    $session_name = 'migori_pmc_session';
    $secure = true;
    $httponly = true;

    ini_set('session.use_only_cookies', 1);

    $cookieParams = session_get_cookie_params();
    session_set_cookie_params([
        'lifetime' => $cookieParams["lifetime"],
        'path' => '/',
        'domain' => $_SERVER['HTTP_HOST'],
        'secure' => $secure,
        'httponly' => $httponly,
        'samesite' => 'Strict'
    ]);

    session_name($session_name);

    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    if (!isset($_SESSION['last_regeneration'])) {
        session_regenerate_id(true);
        $_SESSION['last_regeneration'] = time();
    } elseif (time() - $_SESSION['last_regeneration'] > 1800) {
        session_regenerate_id(true);
        $_SESSION['last_regeneration'] = time();
    }
}

/**
 * Error Handling Functions
 */
set_error_handler(function($errno, $errstr, $errfile, $errline) {
    if (!(error_reporting() & $errno)) {
        return false;
    }

    $error_types = [
        E_ERROR => 'Error',
        E_WARNING => 'Warning',
        E_PARSE => 'Parse Error',
        E_NOTICE => 'Notice',
        E_CORE_ERROR => 'Core Error',
        E_CORE_WARNING => 'Core Warning',
        E_COMPILE_ERROR => 'Compile Error',
        E_COMPILE_WARNING => 'Compile Warning',
        E_USER_ERROR => 'User Error',
        E_USER_WARNING => 'User Warning',
        E_USER_NOTICE => 'User Notice',
        E_STRICT => 'Strict Notice',
        E_RECOVERABLE_ERROR => 'Recoverable Error',
        E_DEPRECATED => 'Deprecated',
        E_USER_DEPRECATED => 'User Deprecated'
    ];

    $errtype = $error_types[$errno] ?? 'Unknown Error';

    $error_msg = sprintf(
        "[%s] %s in %s on line %d",
        $errtype,
        $errstr,
        $errfile,
        $errline
    );

    error_log($error_msg);

    if (defined('ENVIRONMENT') && ENVIRONMENT === 'development') {
        echo "<div class='error'><strong>$errtype:</strong> $errstr in <em>$errfile</em> on line <strong>$errline</strong></div>";
    }

    return true;
});

/**
 * Database Helper Function
 */
function db_query(string $sql, array $params = [], bool $return_stmt = false) {
    global $pdo;

    try {
        $stmt = $pdo->prepare($sql);

        foreach ($params as $key => $value) {
            $param_type = PDO::PARAM_STR;

            if (is_int($value)) $param_type = PDO::PARAM_INT;
            if (is_bool($value)) $param_type = PDO::PARAM_BOOL;
            if (is_null($value)) $param_type = PDO::PARAM_NULL;

            $stmt->bindValue(
                is_int($key) ? $key + 1 : $key, 
                $value, 
                $param_type
            );
        }

        $stmt->execute();

        return $return_stmt ? $stmt : $stmt->fetchAll();

    } catch (PDOException $e) {
        error_log("Database error: " . $e->getMessage());
        throw new Exception("Database operation failed");
    }
}

/**
 * API Response Function
 */
function api_response($data = null, $status = 'success', $code = 200, $meta = []) {
    $response = [
        'status' => $status,
        'code' => $code,
        'data' => $data,
        'timestamp' => time(),
        'version' => '1.0'
    ];

    if (!empty($meta)) {
        $response['meta'] = $meta;
    }

    if ($status === 'error' && !isset($response['meta']['message'])) {
        $response['meta']['message'] = 'An error occurred';
    }

    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

/**
 * Rate Limiting Function
 */
function check_rate_limit($action, $limit = 5, $time_window = 60) {
    $key = "rate_limit_{$action}_" .($_SERVER['REMOTE_ADDR'] ?? 'cli');

    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = [
            'attempts' => 1,
            'first_attempt' => time()
        ];
        return true;
    }

    $current = $_SESSION[$key];

    if (time() - $current['first_attempt'] > $time_window) {
        $_SESSION[$key] = [
            'attempts' => 1,
            'first_attempt' => time()
        ];
        return true;
    }

    if ($current['attempts'] >= $limit) {
        log_activity('rate_limit_exceeded', "Rate limit exceeded for action: $action", null, 'system', null, [
            'ip' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT']
        ]);
        return false;
    }

    $_SESSION[$key]['attempts']++;
    return true;
}

/**
 * JSON Response Helper
 */
function json_response($data, $status_code = 200) {
    http_response_code($status_code);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

/**
 * Show access denied notification
 */
function show_access_notification() {
    if (isset($_SESSION['access_denied'])) {
        $message = $_SESSION['access_denied'];
        unset($_SESSION['access_denied']);
        return $message;
    }
    return null;
}

/**
 * Require specific permission or redirect with notification
 */
function require_permission($permission_key, $redirect_url = 'index.php') {
    if (!has_permission($permission_key)) {
        $_SESSION['access_denied'] = "You don't have permission to access this feature.";
        header("Location: $redirect_url");
        exit;
    }
}

/**
 * Check if user has required role (alternative function name)
 */
function check_admin_role($required_role) {
    if (!is_logged_in()) {
        return false;
    }

    $role_hierarchy = ['viewer' => 1, 'admin' => 2, 'super_admin' => 3];
    $current_role = $_SESSION['admin_role'];

    return isset($role_hierarchy[$current_role]) && 
           isset($role_hierarchy[$required_role]) && 
           $role_hierarchy[$current_role] >= $role_hierarchy[$required_role];
}

/**
 * Check if current admin has a specific permission
 * Wrapper function for RBAC system
 */
function check_page_permission($permission_key) {
    if (!function_exists('hasPagePermission')) {
        require_once __DIR__ . '/rbac.php';
    }
    return hasPagePermission($permission_key);
}

function get_projects_owned_by($user_id) {
    global $pdo;
    $stmt = $pdo->prepare("SELECT p.* FROM projects p 
                          JOIN project_owners po ON p.id = po.project_id 
                          WHERE po.user_id = ?");
    $stmt->execute([$user_id]);
    return $stmt->fetchAll();
}

function get_admin_grievances($filters = []) {
    global $pdo, $current_admin;

    $page = $filters['page'] ?? 1;
    $per_page = $filters['per_page'] ?? 20;
    $offset = ($page - 1) * $per_page;

    $sql = "SELECT 
            f.id, f.project_id, f.citizen_name, f.citizen_email, 
            f.citizen_phone, f.subject, f.message, f.status,
            f.grievance_status, f.resolution_notes, f.resolved_at,
            f.admin_response, f.responded_at, f.created_at,
            p.project_name, p.department_id, 
            d.name as department_name,
            responder.name as responded_by_name,
            creator.name as project_creator_name
        FROM feedback f
        JOIN projects p ON f.project_id = p.id
        JOIN departments d ON p.department_id = d.id
        LEFT JOIN admins responder ON f.responded_by = responder.id
        LEFT JOIN admins creator ON p.created_by = creator.id
        WHERE f.status = 'grievance'";

    $params = [];

    if (!empty($filters['search'])) {
        $sql .= " AND (f.message LIKE ? OR f.citizen_name LIKE ? OR p.project_name LIKE ?)";
        $search_param = '%' . $filters['search'] . '%';
        $params[] = $search_param;
        $params[] = $search_param;
        $params[] = $search_param;
    }

    if (!empty($filters['project_id'])) {
        $sql .= " AND f.project_id = ?";
        $params[] = $filters['project_id'];
    }

    $sql .= " ORDER BY f.created_at DESC LIMIT ? OFFSET ?";
    $params[] = $per_page;
    $params[] = $offset;

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

    return $stmt->fetchAll();
}

function get_admin_grievance_details($grievance_id) {
    global $pdo;

    $sql = "SELECT 
            f.id, f.project_id, f.citizen_name, f.citizen_email, 
            f.citizen_phone, f.subject, f.message, f.status,
            f.grievance_status, f.resolution_notes, f.resolved_at,
            f.admin_response, f.responded_at, f.created_at,
            p.project_name, p.department_id, 
            d.name as department_name,
            responder.name as responded_by_name
        FROM feedback f
        JOIN projects p ON f.project_id = p.id
        JOIN departments d ON p.department_id = d.id
        LEFT JOIN admins responder ON f.responded_by = responder.id
        WHERE f.id = ?";

    $stmt = $pdo->prepare($sql);
    $stmt->execute([$grievance_id]);

    return $stmt->fetch();
}

function update_grievance_status($grievance_id, $status, $resolution_notes = null) {
    global $pdo;

    $sql = "UPDATE feedback SET grievance_status = ?, resolution_notes = ?, resolved_at = NOW() WHERE id = ?";
    $stmt = $pdo->prepare($sql);
    return $stmt->execute([$status, $resolution_notes, $grievance_id]);
}

function get_all_admins($filters = [], $page = 1, $per_page = 10) {
    global $pdo;
    $offset = ($page - 1) * $per_page;

    $sql = "SELECT a.* FROM admins a WHERE 1=1";
    $params = [];

    if (!empty($filters['search'])) {
        $sql .= " AND (a.name LIKE ? OR a.username LIKE ? OR a.email LIKE ?)";
        $search_term = '%' . $filters['search'] . '%';
        $params[] = $search_term;
        $params[] = $search_term;
        $params[] = $search_term;
    }

    if (!empty($filters['role'])) {
        $sql .= " AND a.role = ?";
        $params[] = $filters['role'];
    }

    $sql .= " ORDER BY a.created_at DESC LIMIT ? OFFSET ?";
    $params[] = $per_page;
    $params[] = $offset;

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

function get_total_admins_count($filters = []) {
    global $pdo;

    $sql = "SELECT COUNT(*) FROM admins WHERE 1=1";
    $params = [];

    if (!empty($filters['search'])) {
        $sql .= " AND (name LIKE ? OR username LIKE ? OR email LIKE ?)";
        $search_term = '%' . $filters['search'] . '%';
        $params[] = $search_term;
        $params[] = $search_term;
        $params[] = $search_term;
    }

    if (!empty($filters['role'])) {
        $sql .= " AND role = ?";
        $params[] = $filters['role'];
    }

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchColumn();
}

} // End of function_exists check

?>
