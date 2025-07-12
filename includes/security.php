<?php
/**
 * Enhanced Security Module
 * Provides comprehensive protection against common web vulnerabilities
 */

class SecurityManager {
    private static $failed_attempts = [];
    private static $blocked_ips = [];
    
    /**
     * Initialize security measures
     */
    public static function initialize() {
        // Set security headers
        self::setSecurityHeaders();
        
        // Start secure session
        self::initSecureSession();
        
        // Check for blocked IPs
        self::checkIPBlocking();
        
        // Monitor for suspicious activity
        self::monitorSuspiciousActivity();
    }
    
    /**
     * Set comprehensive security headers
     */
    private static function setSecurityHeaders() {
        // Only set HTTPS headers in production
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
            header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
        }
        
        header("X-Frame-Options: DENY");
        header("X-Content-Type-Options: nosniff");
        header("X-XSS-Protection: 1; mode=block");
        header("Referrer-Policy: strict-origin-when-cross-origin");
        
        // Content Security Policy
        $csp = "default-src 'self'; " .
               "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://cdn.tailwindcss.com; " .
               "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdnjs.cloudflare.com https://unpkg.com https://cdn.tailwindcss.com; " .
               "img-src 'self' data: https:; " .
               "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; " .
               "connect-src 'self';";
        
        header("Content-Security-Policy: $csp");
        header("Permissions-Policy: camera=(), microphone=(), geolocation=()");
    }
    
    /**
     * Initialize secure session with enhanced settings
     */
    private static function initSecureSession() {
        if (session_status() === PHP_SESSION_NONE) {
            ini_set('session.use_only_cookies', 1);
            ini_set('session.cookie_httponly', 1);
            ini_set('session.use_strict_mode', 1);
            ini_set('session.cookie_samesite', 'Strict');
            
            // Use secure cookies in production
            $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
            ini_set('session.cookie_secure', $secure ? 1 : 0);
            
            session_set_cookie_params([
                'lifetime' => 0,
                'path' => '/',
                'domain' => '',
                'secure' => $secure,
                'httponly' => true,
                'samesite' => 'Strict'
            ]);
            
            session_name('MIGORIPMC_SESSION');
            session_start();
            
            // Regenerate session ID periodically
            if (!isset($_SESSION['last_regeneration'])) {
                session_regenerate_id(true);
                $_SESSION['last_regeneration'] = time();
            } elseif (time() - $_SESSION['last_regeneration'] > SESSION_REGENERATE_INTERVAL) {
                session_regenerate_id(true);
                $_SESSION['last_regeneration'] = time();
            }
        }
    }
    
    /**
     * Check if IP is blocked
     */
    private static function checkIPBlocking() {
        $ip = self::getRealIpAddr();
        
        if (isset(self::$blocked_ips[$ip]) && self::$blocked_ips[$ip] > time()) {
            http_response_code(429);
            die('Access temporarily blocked due to suspicious activity.');
        }
    }
    
    /**
     * Monitor for suspicious activity patterns
     */
    private static function monitorSuspiciousActivity() {
        $ip = self::getRealIpAddr();
        $current_time = time();
        
        // Clean old entries
        foreach (self::$failed_attempts as $key => $data) {
            if ($current_time - $data['time'] > 3600) {
                unset(self::$failed_attempts[$key]);
            }
        }
        
        // Check for rapid requests
        $recent_requests = 0;
        foreach (self::$failed_attempts as $attempt) {
            if ($attempt['ip'] === $ip && $current_time - $attempt['time'] < 60) {
                $recent_requests++;
            }
        }
        
        if ($recent_requests > 30) {
            self::blockIP($ip, 1800); // Block for 30 minutes
            error_log("IP $ip blocked for excessive requests");
        }
    }
    
    /**
     * Record failed login attempt
     */
    public static function recordFailedAttempt($identifier, $type = 'login') {
        $ip = self::getRealIpAddr();
        $key = $type . '_' . $identifier . '_' . $ip;
        
        self::$failed_attempts[$key] = [
            'ip' => $ip,
            'identifier' => $identifier,
            'type' => $type,
            'time' => time(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ];
        
        // Check if should block
        $recent_failures = 0;
        foreach (self::$failed_attempts as $attempt) {
            if ($attempt['ip'] === $ip && 
                $attempt['type'] === $type && 
                time() - $attempt['time'] < 900) {
                $recent_failures++;
            }
        }
        
        if ($recent_failures >= MAX_LOGIN_ATTEMPTS) {
            self::blockIP($ip, LOGIN_LOCKOUT_TIME);
            error_log("IP $ip blocked after $recent_failures failed $type attempts");
        }
    }
    
    /**
     * Block IP address
     */
    private static function blockIP($ip, $duration) {
        self::$blocked_ips[$ip] = time() + $duration;
        
        // Log to database if possible
        global $pdo;
        try {
            $stmt = $pdo->prepare("INSERT INTO security_logs (event_type, ip_address, details, created_at) VALUES (?, ?, ?, NOW())");
            $stmt->execute(['ip_blocked', $ip, json_encode(['duration' => $duration, 'reason' => 'suspicious_activity'])]);
        } catch (Exception $e) {
            error_log("Failed to log IP block: Database logging error");
        }
    }
    
    /**
     * Validate file upload security
     */
    public static function validateFileUpload($file, $allowed_types = [], $max_size = 5242880) {
        if (!isset($file) || $file['error'] !== UPLOAD_ERR_OK) {
            return ['valid' => false, 'message' => 'File upload error'];
        }
        
        // Check file size
        if ($file['size'] > $max_size) {
            return ['valid' => false, 'message' => 'File too large'];
        }
        
        // Check file extension
        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!empty($allowed_types) && !in_array($extension, $allowed_types)) {
            return ['valid' => false, 'message' => 'Invalid file type'];
        }
        
        // Check MIME type
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_type = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        $dangerous_types = [
            'application/x-executable',
            'application/x-msdownload',
            'application/x-php',
            'text/x-php'
        ];
        
        if (in_array($mime_type, $dangerous_types)) {
            return ['valid' => false, 'message' => 'Dangerous file type detected'];
        }
        
        // Check for embedded scripts (basic)
        $content = file_get_contents($file['tmp_name']);
        if (preg_match('/<\?php|<script|javascript:/i', $content)) {
            return ['valid' => false, 'message' => 'Potentially malicious content detected'];
        }
        
        return ['valid' => true, 'message' => 'File is safe'];
    }
    
    /**
     * Get real IP address
     */
    public static function getRealIpAddr() {
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
     * Enhanced CSRF protection
     */
    public static function generateCSRFToken() {
        if (!isset($_SESSION['csrf_tokens'])) {
            $_SESSION['csrf_tokens'] = [];
        }
        
        $token = bin2hex(random_bytes(32));
        $_SESSION['csrf_tokens'][$token] = time();
        
        // Clean old tokens
        foreach ($_SESSION['csrf_tokens'] as $key => $timestamp) {
            if (time() - $timestamp > CSRF_TOKEN_LIFETIME) {
                unset($_SESSION['csrf_tokens'][$key]);
            }
        }
        
        return $token;
    }
    
    /**
     * Verify CSRF token
     */
    public static function verifyCSRFToken($token) {
        if (!isset($_SESSION['csrf_tokens'][$token])) {
            return false;
        }
        
        $timestamp = $_SESSION['csrf_tokens'][$token];
        if (time() - $timestamp > CSRF_TOKEN_LIFETIME) {
            unset($_SESSION['csrf_tokens'][$token]);
            return false;
        }
        
        // Remove token after use (one-time use)
        unset($_SESSION['csrf_tokens'][$token]);
        return true;
    }
}

// Initialize security on every request
SecurityManager::initialize();
?>