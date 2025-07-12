<?php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/rbac.php';

/**
 * Check if user is logged in
 */
function is_logged_in() {
    init_secure_session();
    return isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;
}

/**
 * Require authenticated admin
 */
function require_admin() {
    init_secure_session();

    if (!is_logged_in()) {
        header('Location: ' . determine_redirect_url('login.php'));
        exit;
    }

    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > SESSION_TIMEOUT)) {
        logout_user();
        header('Location: ' . determine_redirect_url('login.php?timeout=1'));
        exit;
    }

    if (!isset($_SESSION['last_regenerate']) || (time() - $_SESSION['last_regenerate'] > 300)) {
        session_regenerate_id(true);
        $_SESSION['last_regenerate'] = time();
    }

    $_SESSION['last_activity'] = time();
    validate_session_consistency();
}

/**
 * Validate session consistency
 */
function validate_session_consistency() {
    // More lenient user agent checking for production
    if (isset($_SESSION['user_agent'])) {
        $current_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $session_agent = $_SESSION['user_agent'];
        
        // Only check if both exist and are significantly different
        if (!empty($current_agent) && !empty($session_agent)) {
            // Allow minor variations in user agent
            $similarity = similar_text($current_agent, $session_agent, $percent);
            if ($percent < 80) { // Only flag if less than 80% similar
                security_log('user_agent_mismatch', $_SESSION['admin_id'] ?? null);
                // Don't force logout, just log for now
                // force_logout('security');
            }
        }
    } else {
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
    }

    // Handle various IP address scenarios for production
    if (isset($_SESSION['ip_address'])) {
        $current_ip = get_real_ip_address();
        $session_ip = $_SESSION['ip_address'];

        if (!is_local_ip($current_ip) && !is_local_ip($session_ip)) {
            $current_subnet = get_ip_subnet($current_ip);
            $session_subnet = get_ip_subnet($session_ip);

            if ($current_subnet !== $session_subnet) {
                security_log('ip_mismatch', $_SESSION['admin_id'] ?? null, [
                    'current_ip' => $current_ip,
                    'session_ip' => $session_ip
                ]);
                // Don't force logout for IP changes in production
            }
        }
    } else {
        $_SESSION['ip_address'] = get_real_ip_address();
    }
}

function get_real_ip_address() {
    // Check for various proxy headers
    $ip_headers = [
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'REMOTE_ADDR'
    ];
    
    foreach ($ip_headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ip = $_SERVER[$header];
            // Handle comma-separated IPs (common with proxies)
            if (strpos($ip, ',') !== false) {
                $ip = trim(explode(',', $ip)[0]);
            }
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
}

/**
 * Login user with credentials
 */
function login_user($email, $password) {
    global $pdo;

    if (!check_login_attempts($email)) {
        return ['success' => false, 'message' => 'Too many login attempts. Please try again later.'];
    }

    $stmt = $pdo->prepare("SELECT id, name, email, password_hash, role, email_verified FROM admins WHERE email = ? AND is_active = 1");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    if (!$user) {
        record_login_attempt($email);
        return ['success' => false, 'message' => 'Invalid credentials'];
    }

    if (!$user['email_verified']) {
        record_login_attempt($email);
        return ['success' => false, 'message' => 'Please verify your email address before logging in. Check your email for the activation link.'];
    }

    if ($user && password_verify($password, $user['password_hash'])) {
        // Use PASSWORD_DEFAULT for better compatibility
        $preferred_algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
        
        if (password_needs_rehash($user['password_hash'], $preferred_algo)) {
            $new_hash = password_hash($password, $preferred_algo);
            $pdo->prepare("UPDATE admins SET password_hash = ? WHERE id = ?")
               ->execute([$new_hash, $user['id']]);
        }

        clear_login_attempts($email);

        session_regenerate_id(true);

        $_SESSION['admin_logged_in'] = true;
        $_SESSION['admin_id'] = $user['id'];
        $_SESSION['admin_email'] = $user['email'];
        $_SESSION['admin_name'] = $user['name'];
        $_SESSION['admin_role'] = $user['role'];
        $_SESSION['last_activity'] = time();
        $_SESSION['last_regenerate'] = time();
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'] ?? '';

        if ($user['role'] === 'super_admin') {
            $all_permissions = [];
            foreach (SecureRBAC::getPermissionCategories() as $category => $perms) {
                $all_permissions = array_merge($all_permissions, array_keys($perms));
            }
            $_SESSION['permissions'] = $all_permissions;
        } else {
            $_SESSION['permissions'] = SecureRBAC::getAdminPermissions($user['id']);
        }

        error_log("User {$user['id']} logged in with permissions: " . implode(', ', $_SESSION['permissions']));

        $pdo->prepare("UPDATE admins SET last_login = NOW(), last_ip = ? WHERE id = ?")
           ->execute([$_SERVER['REMOTE_ADDR'] ?? '', $user['id']]);

        return ['success' => true];
    }

    record_login_attempt($email);
    return ['success' => false, 'message' => 'Invalid credentials'];
}

/**
 * Logout user and clear session
 */
function logout_user() {
    init_secure_session();

    $_SESSION = [];

    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(), 
            '', 
            time() - 42000,
            $params["path"],
            $params["domain"],
            $params["secure"],
            $params["httponly"]
        );
    }

    session_destroy();
}

/**
 * Get current admin user data
 */
function get_current_admin() {
    if (!is_logged_in()) {
        return null;
    }

    return [
        'id' => $_SESSION['admin_id'],
        'email' => $_SESSION['admin_email'],
        'name' => $_SESSION['admin_name'],
        'role' => $_SESSION['admin_role']
    ];
}

/**
 * Check if user has required role
 */
function has_role($required_role) {
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
 * Require specific role
 */
function require_role($required_role) {
    require_admin();

    if (!has_role($required_role)) {
        security_log('insufficient_permissions', $_SESSION['admin_id'], [
            'required_role' => $required_role,
            'current_role' => $_SESSION['admin_role']
        ]);
        force_logout('insufficient_permissions');
    }

    verify_role_consistency();
}

/**
 * Check if user can manage specific project
 */
function can_manage_project($project_id) {
    $admin = get_current_admin();
    if (!$admin) return false;

    if ($admin['role'] === 'super_admin') return true;

    if ($admin['role'] === 'admin') {
        global $pdo;
        $stmt = $pdo->prepare("SELECT created_by FROM projects WHERE id = ?");
        $stmt->execute([$project_id]);
        $project = $stmt->fetch();

        return $project && $project['created_by'] == $admin['id'];
    }

    return false;
}

/**
 * Security utility functions
 */
function force_logout($reason = 'security') {
    security_log('forced_logout', $_SESSION['admin_id'] ?? null, ['reason' => $reason]);
    logout_user();
    header('Location: ' . determine_redirect_url("login.php?error=$reason"));
    exit;
}

function verify_role_consistency() {
    global $pdo;
    try {
        $stmt = $pdo->prepare("SELECT role FROM admins WHERE id = ? AND is_active = 1");
        $stmt->execute([$_SESSION['admin_id']]);
        $db_role = $stmt->fetchColumn();

        if ($db_role !== $_SESSION['admin_role']) {
            security_log('role_tampering', $_SESSION['admin_id'], [
                'session_role' => $_SESSION['admin_role'],
                'db_role' => $db_role
            ]);
            force_logout('security');
        }

        if (!isset($_SESSION['permissions']) || empty($_SESSION['permissions'])) {
            if ($db_role === 'super_admin') {
                $all_permissions = [];
                foreach (SecureRBAC::getPermissionCategories() as $category => $perms) {
                    $all_permissions = array_merge($all_permissions, array_keys($perms));
                }
                $_SESSION['permissions'] = $all_permissions;
            } else {
                $_SESSION['permissions'] = SecureRBAC::getAdminPermissions($_SESSION['admin_id']);
            }
        }
    } catch (PDOException $e) {
        security_log('database_error', null, ['error' => 'Database connection issue']);
        force_logout('system');
    }
}

function check_login_attempts($email) {
    global $pdo;
    $stmt = $pdo->prepare("SELECT attempts, last_attempt FROM login_attempts WHERE email = ?");
    $stmt->execute([$email]);
    $attempt = $stmt->fetch();

    return !($attempt && $attempt['attempts'] >= 5 && time() - strtotime($attempt['last_attempt']) < 3600);
}

function record_login_attempt($email) {
    global $pdo;
    $pdo->prepare("INSERT INTO login_attempts (email, attempts, last_attempt) 
                  VALUES (?, 1, NOW()) 
                  ON DUPLICATE KEY UPDATE 
                  attempts = attempts + 1, last_attempt = NOW()")
       ->execute([$email]);
}

function clear_login_attempts($email) {
    global $pdo;
    $pdo->prepare("DELETE FROM login_attempts WHERE email = ?")
       ->execute([$email]);
}

function determine_redirect_url($path) {
    $base_path = '';
    
    // Check if we're in admin directory
    if (strpos($_SERVER['REQUEST_URI'], '/admin/') !== false) {
        $base_path = '../';
    }
    
    // Handle different server configurations
    if (isset($_SERVER['HTTP_HOST'])) {
        return $base_path . $path;
    }
    
    return $path;
}

function is_local_ip($ip) {
    return $ip === '127.0.0.1' || $ip === '::1';
}

function get_ip_subnet($ip) {
    return substr($ip, 0, strrpos($ip, '.'));
}

function security_log($event, $user_id = null, $details = []) {
    $log_message = sprintf(
        "[%s] %s - UserID: %s, IP: %s, Details: %s\n",
        date('Y-m-d H:i:s'),
        $event,
        $user_id ?? 'guest',
        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        json_encode($details)
    );

    error_log($log_message);

    try {
        global $pdo;
        $pdo->prepare("INSERT INTO security_logs (event_type, user_id, ip_address, details) 
                      VALUES (?, ?, ?, ?)")
           ->execute([$event, $user_id, $_SERVER['REMOTE_ADDR'] ?? null, json_encode($details)]);
    } catch (PDOException $e) {
        error_log("Failed to log security event: Database connection error");
    }
}

/**
 * Permission checking functions
 */
function has_session_permission($permission_key) {
    if (!is_logged_in()) {
        return false;
    }

    if ($_SESSION['admin_role'] === 'super_admin') {
        return true;
    }

    return isset($_SESSION['permissions']) && in_array($permission_key, $_SESSION['permissions']);
}

?>