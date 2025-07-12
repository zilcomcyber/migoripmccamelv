<?php
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/rbac.php';

// Start secure session if not already started
if (session_status() === PHP_SESSION_NONE) {
    init_secure_session();
}

// Ensure admin is authenticated
require_admin();

// Get current page filename
$current_page = basename($_SERVER['PHP_SELF']);

// Perform comprehensive security checks
performSecurityChecks($current_page);

// Perform permission check for current page
try {
    requirePagePermission($current_page);
    // Log successful page access
    logPageAccess($current_page);
} catch (Exception $e) {
    // If permission check fails, log and redirect
    $current_admin = get_current_admin();
    if ($current_admin) {
        logSecurityIncident('permission_denied', "Access denied to {$current_page}");
    }
    header('Location: ./index.php');
    exit;
}

/**
 * Perform comprehensive security checks
 */
function performSecurityChecks($page) {
    $current_admin = get_current_admin();

    // Check for suspicious activity patterns
    checkSuspiciousActivity($current_admin['id'], $page);

    // Validate session integrity
    validateSessionIntegrity();

    // Check for privilege escalation attempts
    checkPrivilegeEscalation($current_admin, $page);
}

/**
 * Check for suspicious activity patterns
 */
function checkSuspiciousActivity($admin_id, $page) {
    global $pdo;

    try {
        // Check for rapid page access (potential automation)
        $stmt = $pdo->prepare("
            SELECT COUNT(*) as access_count 
            FROM security_logs 
            WHERE admin_id = ? 
            AND event_type = 'page_access' 
            AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)
        ");
        $stmt->execute([$admin_id]);
        $recent_access = $stmt->fetchColumn();

        if ($recent_access > 30) { // More than 30 page accesses per minute
            $stmt = $pdo->prepare("
                INSERT INTO security_logs (event_type, admin_id, ip_address, user_agent, details, created_at)
                VALUES ('suspicious_activity', ?, ?, ?, ?, NOW())
            ");
            $stmt->execute([
                $admin_id,
                $_SERVER['REMOTE_ADDR'] ?? null,
                $_SERVER['HTTP_USER_AGENT'] ?? null,
                json_encode([
                    'reason' => 'rapid_page_access',
                    'access_count' => $recent_access,
                    'page' => $page,
                    'time_window' => '1_minute'
                ])
            ]);
        }

        // Check for access to multiple high-risk pages
        $stmt = $pdo->prepare("
            SELECT COUNT(DISTINCT JSON_EXTRACT(details, '$.page')) as unique_pages
            FROM security_logs 
            WHERE admin_id = ? 
            AND event_type = 'page_access' 
            AND created_at > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
            AND JSON_EXTRACT(details, '$.page') IN ('manageAdmins.php', 'rolesPermissions.php', 'systemSettings.php')
        ");
        $stmt->execute([$admin_id]);
        $high_risk_access = $stmt->fetchColumn();

        if ($high_risk_access > 5) {
            $stmt = $pdo->prepare("
                INSERT INTO security_logs (event_type, admin_id, ip_address, user_agent, details, created_at)
                VALUES ('suspicious_activity', ?, ?, ?, ?, NOW())
            ");
            $stmt->execute([
                $admin_id,
                $_SERVER['REMOTE_ADDR'] ?? null,
                $_SERVER['HTTP_USER_AGENT'] ?? null,
                json_encode([
                    'reason' => 'multiple_high_risk_access',
                    'unique_pages' => $high_risk_access,
                    'current_page' => $page,
                    'time_window' => '5_minutes'
                ])
            ]);
        }
    } catch (PDOException $e) {
        error_log("Suspicious activity check error: Database connection issue");
    }
}

/**
 * Validate session integrity
 */
function validateSessionIntegrity() {
    // Check if session data is tampered with
    if (!isset($_SESSION['admin_id']) || !isset($_SESSION['admin_role'])) {
        logSecurityIncident('session_tampering', 'Missing critical session data');
        force_logout_with_incident('session_integrity');
    }

    // Verify admin exists in database
    global $pdo;
    try {
        $stmt = $pdo->prepare("SELECT role, is_active FROM admins WHERE id = ?");
        $stmt->execute([$_SESSION['admin_id']]);
        $admin = $stmt->fetch();

        if (!$admin) {
            logSecurityIncident('invalid_admin_session', 'Admin not found in database');
            force_logout_with_incident('invalid_admin');
        }

        if (!$admin['is_active']) {
            logSecurityIncident('inactive_admin_access', 'Inactive admin attempting access');
            force_logout_with_incident('account_disabled');
        }

        if ($admin['role'] !== $_SESSION['admin_role']) {
            logSecurityIncident('role_mismatch', 'Session role does not match database');
            force_logout_with_incident('role_mismatch');
        }
    } catch (PDOException $e) {
        error_log("Session integrity check error: " . $e->getMessage());
        force_logout_with_incident('system_error');
    }
}

/**
 * Check for privilege escalation attempts
 */
function checkPrivilegeEscalation($admin, $page) {
    // Define high-privilege pages
    $high_privilege_pages = [
        'manageAdmins.php',
        'rolesPermissions.php',
        'systemSettings.php',
        'manageAdminPermissions.php'
    ];

    if (in_array($page, $high_privilege_pages) && $admin['role'] !== 'super_admin') {
        // This should be caught by permission system, but double-check
        if (!hasPagePermission('manage_roles') && !hasPagePermission('manage_users')) {
            logSecurityIncident('privilege_escalation_attempt', 
                "Non-super admin attempting to access {$page}");
            force_logout_with_incident('unauthorized_access');
        }
    }
}

/**
 * Log successful page access
 */
function logPageAccess($page) {
    $current_admin = get_current_admin();
    if (!$current_admin) return;

    global $pdo;
    try {
        $stmt = $pdo->prepare("
            INSERT INTO security_logs (event_type, admin_id, ip_address, user_agent, details, created_at)
            VALUES ('page_access', ?, ?, ?, ?, NOW())
        ");
        $stmt->execute([
            $current_admin['id'],
            $_SERVER['REMOTE_ADDR'] ?? null,
            $_SERVER['HTTP_USER_AGENT'] ?? null,
            json_encode([
                'page' => $page,
                'url' => $_SERVER['REQUEST_URI'] ?? null,
                'referrer' => $_SERVER['HTTP_REFERER'] ?? null,
                'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
                'timestamp' => time()
            ])
        ]);
    } catch (PDOException $e) {
        error_log("Page access logging error: Database connection issue");
    }
}

/**
 * Log security incidents
 */
function logSecurityIncident($incident_type, $description) {
    global $pdo;
    try {
        $stmt = $pdo->prepare("
            INSERT INTO security_logs (event_type, admin_id, ip_address, user_agent, details, created_at)
            VALUES ('security_incident', ?, ?, ?, ?, NOW())
        ");
        $stmt->execute([
            $_SESSION['admin_id'] ?? null,
            $_SERVER['REMOTE_ADDR'] ?? null,
            $_SERVER['HTTP_USER_AGENT'] ?? null,
            json_encode([
                'incident_type' => $incident_type,
                'description' => $description,
                'session_data' => [
                    'admin_id' => $_SESSION['admin_id'] ?? null,
                    'admin_role' => $_SESSION['admin_role'] ?? null,
                    'last_activity' => $_SESSION['last_activity'] ?? null
                ]
            ])
        ]);
    } catch (PDOException $e) {
        error_log("Security incident logging error: " . $e->getMessage());
    }
}

//Force logout with security incident logging
 
function force_logout_with_incident($reason) {
    logSecurityIncident('forced_logout', "Forced logout due to: {$reason}");
    force_logout($reason);
}

// Enhanced page security with proper permission checking
$current_page = basename($_SERVER['PHP_SELF']);

// Map pages to required permissions (must match RBAC system)
$page_permissions = [
    'projects.php' => 'view_projects',
    'createCroject.php' => 'create_projects',
    'editProject.php' => 'edit_projects',
    'manageProject.php' => 'manage_projects',
    'updateProject.php' => 'edit_projects',
    'submitProject.php' => 'create_projects',
    'budgetManagement.php' => 'manage_budgets',
    'documentManager.php' => 'manage_documents',
    'feedback.php' => 'manage_feedback',
    'grievances.php' => 'manage_feedback',
    'pmcReports.php' => 'view_reports',
    'activityLogs.php' => 'view_activity_logs',
    'rolesPermissions.php' => 'manage_roles',
    'manageAdminPermissions.php' => 'manage_roles',
    'systemSettings.php' => 'system_settings',
    'importCsv.php' => 'import_data',
    'manageSteps.php' => 'manage_project_steps'
];

// Always allow dashboard and profile access for authenticated users
$always_allowed = ['index.php', 'dashboard.php', 'profile.php'];

// Check if page requires specific permission
if (!in_array($current_page, $always_allowed) && isset($page_permissions[$current_page])) {
    $required_permission = $page_permissions[$current_page];

    // Super admin bypasses all checks
    if ($_SESSION['admin_role'] !== 'super_admin') {
        if (!has_permission($required_permission)) {
            // Log unauthorized access attempt
            log_activity('unauthorized_access_attempt', 
                "Attempted to access {$current_page} without {$required_permission} permission", 
                $_SESSION['admin_id'] ?? null
            );

            header('Location: ../404.php');
            exit;
        }
    }
}
?>