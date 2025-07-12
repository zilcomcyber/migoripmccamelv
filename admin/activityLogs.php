<?php
require_once 'includes/pageSecurity.php';
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';
require_once '../includes/rbac.php';

// Require authentication and proper permissions
require_admin();
if (!has_permission('view_activity_logs')) {
    header('Location: index.php?error=access_denied');
    exit;
}

$current_admin = get_current_admin();

// Log access to activity logs
log_activity('activity_logs_access', 'Viewed activity logs page', $current_admin['id']);

// Pagination settings
$limit = 20; // Number of logs per page
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$start = ($page - 1) * $limit;

// Handle filtering
$filters = [
    'admin_id' => $_GET['admin_id'] ?? '',
    'activity_type' => $_GET['activity_type'] ?? '',
    'target_type' => $_GET['target_type'] ?? '',
    'date_from' => $_GET['date_from'] ?? '',
    'date_to' => $_GET['date_to'] ?? '',
    'search' => $_GET['search'] ?? ''
];

// Build query with filters
$query = "SELECT al.*, a.name as admin_name, a.email as admin_email 
          FROM admin_activity_log al 
          LEFT JOIN admins a ON al.admin_id = a.id 
          WHERE 1=1";
$params = [];

if (!empty($filters['admin_id'])) {
    $query .= " AND al.admin_id = ?";
    $params[] = $filters['admin_id'];
}

if (!empty($filters['activity_type'])) {
    $query .= " AND al.activity_type = ?";
    $params[] = $filters['activity_type'];
}

if (!empty($filters['target_type'])) {
    $query .= " AND al.target_type = ?";
    $params[] = $filters['target_type'];
}

if (!empty($filters['date_from'])) {
    $query .= " AND DATE(al.created_at) >= ?";
    $params[] = $filters['date_from'];
}

if (!empty($filters['date_to'])) {
    $query .= " AND DATE(al.created_at) <= ?";
    $params[] = $filters['date_to'];
}

if (!empty($filters['search'])) {
    $query .= " AND (al.activity_description LIKE ? OR a.name LIKE ?)";
    $search_param = '%' . $filters['search'] . '%';
    $params[] = $search_param;
    $params[] = $search_param;
}

// Count total activities for pagination
$count_query = $query;
$count_stmt = $pdo->prepare($count_query);
$count_stmt->execute($params);
$total = $count_stmt->rowCount();
$pages = ceil($total / $limit);

$query .= " ORDER BY al.created_at DESC LIMIT ?, ?";
$params[] = $start;
$params[] = $limit;

try {
    $stmt = $pdo->prepare($query);
    $stmt->execute($params);
    $activities = $stmt->fetchAll();

    // Get filter options
    $admins = $pdo->query("SELECT id, name FROM admins ORDER BY name")->fetchAll();
    $activity_types = $pdo->query("SELECT DISTINCT activity_type FROM admin_activity_log ORDER BY activity_type")->fetchAll(PDO::FETCH_COLUMN);
    $target_types = $pdo->query("SELECT DISTINCT target_type FROM admin_activity_log WHERE target_type IS NOT NULL ORDER BY target_type")->fetchAll(PDO::FETCH_COLUMN);

} catch (Exception $e) {
    error_log("Activity logs error: " . $e->getMessage());
    $activities = [];
    $admins = [];
    $activity_types = [];
    $target_types = [];
}

$page_title = "Activity Logs";

include 'includes/adminHeader.php';
?>

<!-- Breadcrumb -->
<div class="mb-6">
    <nav class="flex" aria-label="Breadcrumb">
        <ol class="flex items-center space-x-2 text-sm">
            <li class="text-gray-600 font-medium">
                <i class="fas fa-home mr-1"></i> Dashboard
            </li>
            <li class="text-gray-400">/</li>
            <li class="text-gray-600 font-medium">Activity Logs</li>
        </ol>
    </nav>
</div>

<!-- Page Header -->
<div class="mb-8">
    <div class="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
        <div class="flex flex-col md:flex-row items-start justify-between">
            <div class="mb-4 md:mb-0">
                <h1 class="text-2xl font-bold text-gray-900 mb-2">Activity Logs</h1>
                <p class="text-gray-600">Monitor system activity and user actions</p>
                <p class="text-sm text-gray-500 mt-2">Track all system operations and user interactions</p>
            </div>
            <div class="text-center md:text-right">
                <div class="text-3xl font-bold text-blue-600 mb-1"><?php echo number_format($total); ?></div>
                <div class="text-sm text-gray-600 mb-3">Total Activities</div>
                <!-- <div class="text-xs text-gray-500"><?php echo $today_activities; ?> today</div> -->
            </div>
        </div>
    </div>
</div>
<div class="bg-white rounded-xl p-6 mb-6 shadow-sm border border-gray-200">

<!-- Filter Section -->
<div class="pmc-card mb-6">
    <div class="pmc-card-header">
        <h3 class="text-lg font-semibold text-gray-900">Filter Activities</h3>
    </div>
    <div class="pmc-card-content">
        <form method="GET" class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4">
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">Admin</label>
                <select name="admin_id" class="w-full rounded-md border-gray-300 shadow-sm focus:border-pmc-navy focus:ring-pmc-navy">
                    <option value="">All Admins</option>
                    <?php foreach ($admins as $admin): ?>
                        <option value="<?php echo $admin['id']; ?>" <?php echo $filters['admin_id'] == $admin['id'] ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($admin['name']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">Activity Type</label>
                <select name="activity_type" class="w-full rounded-md border-gray-300 shadow-sm focus:border-pmc-navy focus:ring-pmc-navy">
                    <option value="">All Types</option>
                    <?php foreach ($activity_types as $type): ?>
                        <option value="<?php echo $type; ?>" <?php echo $filters['activity_type'] == $type ? 'selected' : ''; ?>>
                            <?php echo ucfirst(str_replace('_', ' ', $type)); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">Target Type</label>
                <select name="target_type" class="w-full rounded-md border-gray-300 shadow-sm focus:border-pmc-navy focus:ring-pmc-navy">
                    <option value="">All Targets</option>
                    <?php foreach ($target_types as $type): ?>
                        <option value="<?php echo $type; ?>" <?php echo $filters['target_type'] == $type ? 'selected' : ''; ?>>
                            <?php echo ucfirst($type); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">From Date</label>
                <input type="date" name="date_from" value="<?php echo htmlspecialchars($filters['date_from']); ?>" 
                       class="w-full rounded-md border-gray-300 shadow-sm focus:border-pmc-navy focus:ring-pmc-navy">
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">To Date</label>
                <input type="date" name="date_to" value="<?php echo htmlspecialchars($filters['date_to']); ?>" 
                       class="w-full rounded-md border-gray-300 shadow-sm focus:border-pmc-navy focus:ring-pmc-navy">
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">Search</label>
                <div class="flex space-x-2">
                    <input type="text" name="search" value="<?php echo htmlspecialchars($filters['search']); ?>" 
                           placeholder="Search activities..." 
                           class="w-full rounded-md border-gray-300 shadow-sm focus:border-pmc-navy focus:ring-pmc-navy">
                    <button type="submit" class="bg-pmc-navy text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors">
                        <i class="fas fa-search"></i>
                    </button>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Activity Log Table -->
<div class="pmc-card">
    <div class="pmc-card-header">
        <div class="flex items-center justify-between">
            <h3 class="text-lg font-semibold text-gray-900">Recent Activities</h3>
            <span class="text-sm text-gray-500"><?php echo count($activities); ?> activities found</span>
        </div>
    </div>
    <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Admin</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Activity</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Target</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP Address</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
                <?php foreach ($activities as $activity): ?>
                    <tr class="hover:bg-gray-50">
                        <td class="px-6 py-4 whitespace-nowrap">
                            <div class="flex items-center">
                                <div class="w-8 h-8 bg-pmc-gold rounded-full flex items-center justify-center mr-3">
                                    <span class="text-pmc-navy font-bold text-sm">
                                        <?php echo strtoupper(substr($activity['admin_name'] ?? 'S', 0, 1)); ?>
                                    </span>
                                </div>
                                <div>
                                    <div class="text-sm font-medium text-gray-900">
                                        <?php echo htmlspecialchars($activity['admin_name'] ?? 'System'); ?>
                                    </div>
                                    <div class="text-sm text-gray-500">
                                        <?php echo htmlspecialchars($activity['admin_email'] ?? ''); ?>
                                    </div>
                                </div>
                            </div>
                        </td>
                        <td class="px-6 py-4">
                            <div class="text-sm font-medium text-gray-900">
                                <?php echo ucfirst(str_replace('_', ' ', $activity['activity_type'])); ?>
                            </div>
                            <div class="text-sm text-gray-500">
                                <?php echo htmlspecialchars($activity['activity_description']); ?>
                            </div>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            <?php if ($activity['target_type']): ?>
                                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                    <?php echo ucfirst($activity['target_type']); ?> #<?php echo $activity['target_id']; ?>
                                </span>
                            <?php endif; ?>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">
                            <?php echo htmlspecialchars($activity['ip_address']); ?>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            <div title="<?php echo $activity['created_at']; ?>">
                                <?php echo format_date($activity['created_at']); ?>
                            </div>
                            <div class="text-xs text-gray-400">
                                <?php echo date('H:i:s', strtotime($activity['created_at'])); ?>
                            </div>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            <?php if ($activity['additional_data']): ?>
                                <button onclick="showActivityDetails(<?php echo htmlspecialchars($activity['additional_data']); ?>)" 
                                        class="text-blue-600 hover:text-blue-900">
                                    <i class="fas fa-info-circle"></i>
                                </button>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>

                <?php if (empty($activities)): ?>
                    <tr>
                        <td colspan="6" class="px-6 py-12 text-center text-gray-500">
                            <i class="fas fa-history text-4xl text-gray-300 mb-4"></i>
                            <p>No activities found matching your criteria.</p>
                        </td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- Pagination -->
    <div class="pmc-card-footer flex justify-center items-center p-4">
        <?php if ($pages > 1): ?>
            <nav class="relative z-0 inline-flex rounded-md shadow-sm -space-x-px" aria-label="Pagination">
                <?php if ($page > 1): ?>
                    <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => $page - 1])); ?>"
                       class="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50">
                        <span class="sr-only">Previous</span>
                        <i class="fas fa-chevron-left"></i>
                    </a>
                <?php endif; ?>

                <?php for ($i = 1; $i <= $pages; $i++): ?>
                    <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => $i])); ?>"
                       class="<?php echo ($page == $i) ? 'bg-pmc-navy text-white' : 'bg-white text-gray-700 hover:bg-gray-50'; ?> relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium">
                        <?php echo $i; ?>
                    </a>
                <?php endfor; ?>

                <?php if ($page < $pages): ?>
                    <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => $page + 1])); ?>"
                       class="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50">
                        <span class="sr-only">Next</span>
                        <i class="fas fa-chevron-right"></i>
                    </a>
                <?php endif; ?>
            </nav>
        <?php endif; ?>
    </div>
</div>
</div>

<!-- Activity Details Modal -->
<div id="activityModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 hidden z-50">
    <div class="flex items-center justify-center min-h-screen p-4">
        <div class="bg-white rounded-lg shadow-xl max-w-lg w-full">
            <div class="p-6">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-semibold text-gray-900">Activity Details</h3>
                    <button onclick="closeActivityModal()" class="text-gray-400 hover:text-gray-600">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <pre id="activityDetails" class="bg-gray-100 p-4 rounded-md text-sm overflow-auto max-h-96"></pre>
            </div>
        </div>
    </div>
</div>


<script>
function showActivityDetails(data) {
    document.getElementById('activityDetails').textContent = JSON.stringify(data, null, 2);
    document.getElementById('activityModal').classList.remove('hidden');
}

function closeActivityModal() {
    document.getElementById('activityModal').classList.add('hidden');
}
</script>

<?php include 'includes/adminFooter.php'; ?>
