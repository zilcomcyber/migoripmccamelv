<?php
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: Sat, 23 Nov 1997 05:00:00 GMT"); //my date of birth
/**
 * Initialize secure session
 */
function init_secure_session() {
    if (session_status() === PHP_SESSION_NONE) {
        // Configure session settings before starting
        ini_set('session.use_only_cookies', 1);
        ini_set('session.cookie_httponly', 1);
        
        // Check if HTTPS is available - be more flexible for production
        $is_secure = (
            (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
            (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') ||
            (!empty($_SERVER['HTTP_X_FORWARDED_SSL']) && $_SERVER['HTTP_X_FORWARDED_SSL'] === 'on') ||
            (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443)
        );
        
        ini_set('session.cookie_secure', $is_secure ? 1 : 0);
        
        // Set session cookie parameters
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'domain' => '',
            'secure' => $is_secure,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);

        session_name('secure_auth');
        session_start();

        if (!isset($_SESSION['canary'])) {
            session_regenerate_id(true);
            $_SESSION['canary'] = time();
        }
    }
}

// Database configuration
$host = 'localhost';
$dbname = 'project_manager';
$username = 'root';
$password = '';

// App configuration
define('APP_NAME', 'Public Projects Portal');
define('SESSION_TIMEOUT', 3600); // 1 hour
define('MAX_FILE_SIZE', 5 * 1024 * 1024); // 5MB
define('BASE_DIR', __DIR__);

// Application constants - DEFINE BASE_URL FIRST
define('BASE_URL', '/migoripmccamelv2/'); 
define('UPLOADS_DIR', BASE_DIR . '/uploads');
define('UPLOAD_PATH', UPLOADS_DIR . '/');
define('UPLOADS_URL', BASE_URL . 'uploads/');
define('DB_CHARSET', 'utf8mb4');

// Security settings
define('CSRF_TOKEN_LIFETIME', 3600); // 1 hour
define('PASSWORD_MIN_LENGTH', 8);

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);

    // Test the connection
    $pdo->query('SELECT 1');

} catch (PDOException $e) {
    // Log the actual error for debugging
    error_log('Database connection failed: ' . $e->getMessage());

    // Show user-friendly message
    if (defined('ENVIRONMENT') && ENVIRONMENT === 'development') {
        die('Database connection failed: ' . $e->getMessage());
    } else {
        die('Database connection failed. Please check your configuration.');
    }
}

// Set timezone
date_default_timezone_set('Africa/Nairobi');

// Error reporting for development
error_reporting(E_ALL);
ini_set('display_errors', 1);