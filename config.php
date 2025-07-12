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

// Database configuration with fallback options
$db_configs = [
    // Primary configuration
    [
        'host' => 'localhost',
        'dbname' => 'project_manager',
        'username' => 'root',
        'password' => '',
        'port' => 3306

    ],
    // Fallback configuration for different environments
    [
        'host' => '127.0.0.1',
        'dbname' => 'project_manager',
        'username' => 'root',
        'password' => '',
        'port' => 3306
    ]
];

// App configuration
define('APP_NAME', 'Public Projects Portal');
define('SESSION_TIMEOUT', 3600); // 1 hour
define('MAX_FILE_SIZE', 5 * 1024 * 1024); // 5MB
define('BASE_DIR', __DIR__);

// Application constants - DEFINE BASE_URL FIRST
define('BASE_URL', 'http://localhost/migoripmccamelv2/'); 
define('UPLOADS_DIR', BASE_DIR . '/uploads');
define('UPLOAD_PATH', UPLOADS_DIR . '/');
define('UPLOADS_URL', BASE_URL . 'uploads/');
define('DB_CHARSET', 'utf8mb4');

// Security Constants
define('CSRF_TOKEN_LIFETIME', 3600); // 1 hour
define('SESSION_REGENERATE_INTERVAL', 1800); // 30 minutes
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_LOCKOUT_TIME', 900); // 15 minutes

// Production Error Handling
define('ENVIRONMENT', 'production'); // Change to 'development' for debugging
define('SHOW_ERRORS', false); // Never show detailed errors in production

// Configure error reporting for production
if (ENVIRONMENT === 'production') {
    error_reporting(0);
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    ini_set('error_log', __DIR__ . '/logs/error.log');
} else {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
}

// Performance settings for high traffic
define('MAX_CONNECTIONS', 100);
define('QUERY_TIMEOUT', 30);

// Try multiple database configurations
$pdo = null;
$connection_errors = [];

foreach ($db_configs as $config) {
    try {
        $dsn = "mysql:host={$config['host']};port={$config['port']};dbname={$config['dbname']};charset=utf8mb4";

        $pdo = new PDO($dsn, $config['username'], $config['password'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_PERSISTENT => false,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
            PDO::ATTR_TIMEOUT => 10,
        ]);

        // Optimize MySQL settings for high concurrency (only session-level settings)
        $pdo->exec("SET SESSION sql_mode = 'STRICT_TRANS_TABLES'");
        $pdo->exec("SET SESSION wait_timeout = 300");
        $pdo->exec("SET SESSION interactive_timeout = 300");

        // Test the connection
        $pdo->query('SELECT 1');

        // If we get here, connection was successful
        break;

    } catch (PDOException $e) {
        $connection_errors[] = "Host {$config['host']}: " . $e->getMessage();
        $pdo = null;
        continue;
    }
}

// If no connection was successful
if ($pdo === null) {
    // Log all connection attempts
    error_log('All database connection attempts failed:');
    foreach ($connection_errors as $error) {
        error_log($error);
    }

    // Check if this is a development environment
    $is_development = (
        isset($_SERVER['HTTP_HOST']) && 
        (strpos($_SERVER['HTTP_HOST'], 'localhost') !== false || 
         strpos($_SERVER['HTTP_HOST'], '127.0.0.1') !== false)
    );

    // Show appropriate error message
    if ($is_development) {
        echo '<div style="background: #fee; border: 1px solid #fcc; padding: 20px; margin: 20px; border-radius: 5px;">';
        echo '<h3>Database Connection Failed</h3>';
        echo '<p>Connection attempts:</p><ul>';
        foreach ($connection_errors as $error) {
            echo '<li>' . htmlspecialchars($error) . '</li>';
        }
        echo '</ul>';
        echo '<p><strong>Troubleshooting:</strong></p>';
        echo '<ul>';
        echo '<li>Check if MySQL/MariaDB service is running</li>';
        echo '<li>Verify database name exists: project_manager</li>';
        echo '<li>Check database credentials</li>';
        echo '<li>Ensure database server accepts connections</li>';
        echo '</ul>';
        echo '</div>';
        exit;
    } else {
        die('Database connection failed. Please check your configuration.');
    }
}

// Set timezone
date_default_timezone_set('Africa/Nairobi');

// Error reporting for development
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once __DIR__ . '/includes/projectStepsTemplates.php';
require_once __DIR__ . '/includes/security.php';