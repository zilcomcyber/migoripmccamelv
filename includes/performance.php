<?php
/**
 * Performance Optimization Module
 * Implements caching, connection pooling, and performance monitoring
 */

class PerformanceManager {
    private static $query_cache = [];
    private static $start_time;
    private static $memory_start;
    
    public static function init() {
        self::$start_time = microtime(true);
        self::$memory_start = memory_get_usage(true);
        
        // Enable output compression
        if (!ob_get_level() && extension_loaded('zlib')) {
            ob_start('ob_gzhandler');
        }
        
        // Set performance headers
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        
        // Enable browser caching for static assets
        if (preg_match('/\.(css|js|png|jpg|jpeg|gif|ico|svg)$/i', $_SERVER['REQUEST_URI'])) {
            header('Cache-Control: public, max-age=31536000');
            header('Expires: ' . gmdate('D, d M Y H:i:s', time() + 31536000) . ' GMT');
        }
    }
    
    /**
     * Cache database queries to reduce load
     */
    public static function cacheQuery($key, $callback, $ttl = 300) {
        $cache_file = __DIR__ . '/../cache/query_' . md5($key) . '.cache';
        
        // Check if cache exists and is valid
        if (file_exists($cache_file)) {
            $cache_data = unserialize(file_get_contents($cache_file));
            if ($cache_data['expires'] > time()) {
                return $cache_data['data'];
            }
            unlink($cache_file);
        }
        
        // Execute query and cache result
        $result = $callback();
        
        if (!is_dir(dirname($cache_file))) {
            mkdir(dirname($cache_file), 0755, true);
        }
        
        $cache_data = [
            'data' => $result,
            'expires' => time() + $ttl,
            'created' => time()
        ];
        
        file_put_contents($cache_file, serialize($cache_data));
        return $result;
    }
    
    /**
     * Optimize database queries
     */
    public static function optimizeQuery($sql, $params = []) {
        global $pdo;
        
        $query_key = md5($sql . serialize($params));
        
        // Cache prepared statements
        if (!isset(self::$query_cache[$query_key])) {
            self::$query_cache[$query_key] = $pdo->prepare($sql);
        }
        
        $stmt = self::$query_cache[$query_key];
        $stmt->execute($params);
        return $stmt;
    }
    
    /**
     * Monitor performance metrics
     */
    public static function getMetrics() {
        return [
            'execution_time' => round((microtime(true) - self::$start_time) * 1000, 2),
            'memory_usage' => round((memory_get_usage(true) - self::$memory_start) / 1024 / 1024, 2),
            'peak_memory' => round(memory_get_peak_usage(true) / 1024 / 1024, 2),
            'queries_cached' => count(self::$query_cache)
        ];
    }
    
    /**
     * Clear expired cache files
     */
    public static function clearExpiredCache() {
        $cache_dir = __DIR__ . '/../cache/';
        if (!is_dir($cache_dir)) return;
        
        $files = glob($cache_dir . '*.cache');
        $cleared = 0;
        
        foreach ($files as $file) {
            if (file_exists($file)) {
                $cache_data = @unserialize(file_get_contents($file));
                if (!$cache_data || $cache_data['expires'] < time()) {
                    unlink($file);
                    $cleared++;
                }
            }
        }
        
        return $cleared;
    }
}

// Auto-initialize performance optimizations
PerformanceManager::init();
