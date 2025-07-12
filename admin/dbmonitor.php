<?php
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/functions.php';
require_once __DIR__ . '/../includes/performance.php';

// Require super admin access
require_admin();
if ($_SESSION['admin_role'] !== 'super_admin') {
    header('Location: ./index.php');
    exit;
}

$page_title = "Database Monitor";
include __DIR__ . '/includes/adminHeader.php';

// Get database health and stats
$db_health = check_database_health();
$db_stats = get_database_stats();

// Get recent slow queries (if available)
$slow_queries = [];
try {
    $stmt = $pdo->query("
        SELECT query_time, sql_text, start_time 
        FROM mysql.slow_log 
        WHERE start_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        ORDER BY start_time DESC 
        LIMIT 10
    ");
    $slow_queries = $stmt->fetchAll();
} catch (Exception $e) {
    error_log("Slow query log access error: " . $e->getMessage());
    // Slow query log might not be enabled or accessible
}

// Get connection status
$connection_status = [];
try {
    $stmt = $pdo->query("SHOW PROCESSLIST");
    $connection_status = $stmt->fetchAll();
} catch (Exception $e) {
    error_log("Process list access error: " . $e->getMessage());
    // Process list might not be accessible
}
?>

<div class="bg-white rounded-xl p-6 mb-6 shadow-sm border border-gray-200">
    <div class="mb-6">
        <h1 class="text-3xl font-bold text-gray-900">Database Monitor</h1>
        <p class="text-gray-600">Monitor database health and performance</p>
    </div>

    <!-- Database Health Status -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-lg font-semibold mb-4">Connection Health</h3>
            <div class="flex items-center">
                <?php if ($db_health['status'] === 'healthy'): ?>
                    <div class="w-3 h-3 bg-green-500 rounded-full mr-3"></div>
                    <span class="text-green-600 font-medium">Healthy</span>
                <?php else: ?>
                    <div class="w-3 h-3 bg-red-500 rounded-full mr-3"></div>
                    <span class="text-red-600 font-medium">Unhealthy</span>
                <?php endif; ?>
            </div>
            <?php if ($db_health['response_time_ms']): ?>
                <p class="text-sm text-gray-600 mt-2">
                    Response Time: <?php echo $db_health['response_time_ms']; ?>ms
                </p>
            <?php endif; ?>
            <?php if (isset($db_health['error'])): ?>
                <p class="text-sm text-red-600 mt-2">
                    Error: <?php echo htmlspecialchars($db_health['error']); ?>
                </p>
            <?php endif; ?>
        </div>

        <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-lg font-semibold mb-4">Connections</h3>
            <?php if (!empty($db_stats)): ?>
                <p class="text-2xl font-bold text-blue-600">
                    <?php echo $db_stats['active_connections']; ?>/<?php echo $db_stats['max_connections']; ?>
                </p>
                <p class="text-sm text-gray-600">Active/Max Connections</p>
            <?php else: ?>
                <p class="text-gray-500">Stats unavailable</p>
            <?php endif; ?>
        </div>

        <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-lg font-semibold mb-4">Server Uptime</h3>
            <?php if (!empty($db_stats) && isset($db_stats['uptime_seconds'])): ?>
                <?php 
                $uptime_hours = floor($db_stats['uptime_seconds'] / 3600);
                $uptime_days = floor($uptime_hours / 24);
                ?>
                <p class="text-2xl font-bold text-green-600"><?php echo $uptime_days; ?> days</p>
                <p class="text-sm text-gray-600"><?php echo $uptime_hours; ?> hours total</p>
            <?php else: ?>
                <p class="text-gray-500">Uptime unavailable</p>
            <?php endif; ?>
        </div>
    </div>

    <!-- Connection Status -->
    <?php if (!empty($connection_status)): ?>
    <div class="bg-white rounded-lg shadow p-6 mb-8">
        <h3 class="text-lg font-semibold mb-4">Active Connections</h3>
        <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">ID</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">User</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Host</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Database</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Command</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
                    <?php foreach (array_slice($connection_status, 0, 10) as $process): ?>
                    <tr>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            <?php echo $process['Id']; ?>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            <?php echo htmlspecialchars($process['User']); ?>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            <?php echo htmlspecialchars($process['Host']); ?>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            <?php echo htmlspecialchars($process['db'] ?? 'N/A'); ?>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            <?php echo htmlspecialchars($process['Command']); ?>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            <?php echo $process['Time']; ?>s
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    <?php endif; ?>
</div>

<?php include __DIR__ . '/includes/adminFooter.php'; ?>