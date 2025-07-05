<?php
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

require_admin();
$current_admin = get_current_admin();

// Log dashboard access
log_activity('admin_dashboard_access', 'Accessed main admin dashboard', $current_admin['id']);

try {
    // Get statistics (same as before)
    $total_projects = $pdo->query("SELECT COUNT(*) FROM projects")->fetchColumn();
    $ongoing_projects = $pdo->query("SELECT COUNT(*) FROM projects WHERE status = 'ongoing'")->fetchColumn();
    $completed_projects = $pdo->query("SELECT COUNT(*) FROM projects WHERE status = 'completed'")->fetchColumn();
    $planning_projects = $pdo->query("SELECT COUNT(*) FROM projects WHERE status = 'planning'")->fetchColumn();
    $this_month_projects = $pdo->query("SELECT COUNT(*) FROM projects WHERE MONTH(created_at) = MONTH(CURDATE()) AND YEAR(created_at) = YEAR(CURDATE())")->fetchColumn();
    $total_feedback = $pdo->query("SELECT COUNT(*) FROM feedback")->fetchColumn();
    $pending_feedback = $pdo->query("SELECT COUNT(*) FROM feedback WHERE status = 'pending'")->fetchColumn();
    $responded_feedback = $pdo->query("SELECT COUNT(*) FROM feedback WHERE status = 'responded'")->fetchColumn();

    // Get recent projects and feedback (same as before)
    if ($current_admin['role'] === 'super_admin') {
        $recent_projects = $pdo->query("SELECT p.id, p.project_name, p.status, p.created_at, p.progress_percentage, d.name as department_name, sc.name as sub_county_name FROM projects p LEFT JOIN departments d ON p.department_id = d.id LEFT JOIN sub_counties sc ON p.sub_county_id = sc.id ORDER BY p.created_at DESC LIMIT 5")->fetchAll();
    } else {
        $stmt = $pdo->prepare("SELECT p.id, p.project_name, p.status, p.created_at, p.progress_percentage, d.name as department_name, sc.name as sub_county_name FROM projects p LEFT JOIN departments d ON p.department_id = d.id LEFT JOIN sub_counties sc ON p.sub_county_id = sc.id WHERE p.created_by = ? ORDER BY p.created_at DESC LIMIT 5");
        $stmt->execute([$current_admin['id']]);
        $recent_projects = $stmt->fetchAll();
    }

    $recent_feedback = $pdo->query("SELECT f.id, f.subject, f.message, f.created_at, f.citizen_name, p.project_name, f.status as feedback_status FROM feedback f LEFT JOIN projects p ON f.project_id = p.id ORDER BY f.created_at DESC LIMIT 5")->fetchAll();
    $recent_activities = get_recent_activities(5);

} catch (Exception $e) {
    error_log("Admin Index Error: " . $e->getMessage());
    // Set default values (same as before)
}

$page_title = "Admin Dashboard";
include 'includes/adminHeader.php';
?>

<!-- Welcome Card -->
<div class="bg-white rounded-xl p-6 mb-6 shadow-sm border border-gray-200">
    <div class="flex flex-col md:flex-row items-center justify-between">
        <div class="mb-4 md:mb-0">
            <h1 class="text-2xl font-bold mb-2 text-gray-900">Welcome back, <?php echo htmlspecialchars($current_admin['name']); ?>!</h1>
            <p class="text-gray-600">Migori County PMC Portal Dashboard</p>
            <p class="text-sm text-gray-500 mt-2">
                Last login: <?php echo date('F d, Y \a\t H:i A'); ?>
            </p>
        </div>
        <div class="text-center md:text-right">
            <div class="text-3xl font-bold text-pmc-navy"><?php echo number_format($total_projects); ?></div>
            <div class="text-sm text-gray-600">Total Projects</div>
            <?php if (has_permission('download_reports')): ?>
                <a href="dashboard.php" class="inline-block mt-2 bg-pmc-navy text-white px-4 py-2 rounded-lg hover:bg-blue-800 transition-colors text-sm">
                    <i class="fas fa-chart-line mr-1"></i> Advanced Analytics
                </a>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Quick Stats Grid -->
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
    <!-- Total Projects -->
    <div class="bg-white rounded-xl shadow-sm p-6 border border-gray-200">
        <div class="flex items-center">
            <div class="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mr-4">
                <i class="fas fa-folder text-blue-600 text-xl"></i>
            </div>
            <div>
                <p class="text-sm text-gray-600">Total Projects</p>
                <p class="text-2xl font-bold text-gray-900"><?php echo number_format($total_projects); ?></p>
            </div>
        </div>
    </div>

    <!-- Ongoing Projects -->
    <div class="bg-white rounded-xl shadow-sm p-6 border border-gray-200">
        <div class="flex items-center">
            <div class="w-12 h-12 bg-yellow-100 rounded-lg flex items-center justify-center mr-4">
                <i class="fas fa-clock text-yellow-600 text-xl"></i>
            </div>
            <div>
                <p class="text-sm text-gray-600">Ongoing</p>
                <p class="text-2xl font-bold text-gray-900"><?php echo number_format($ongoing_projects); ?></p>
            </div>
        </div>
    </div>

    <!-- Completed Projects -->
    <div class="bg-white rounded-xl shadow-sm p-6 border border-gray-200">
        <div class="flex items-center">
            <div class="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mr-4">
                <i class="fas fa-check-circle text-green-600 text-xl"></i>
            </div>
            <div>
                <p class="text-sm text-gray-600">Completed</p>
                <p class="text-2xl font-bold text-gray-900"><?php echo number_format($completed_projects); ?></p>
            </div>
        </div>
    </div>

    <!-- This Month -->
    <div class="bg-white rounded-xl shadow-sm p-6 border border-gray-200">
        <div class="flex items-center">
            <div class="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center mr-4">
                <i class="fas fa-calendar text-purple-600 text-xl"></i>
            </div>
            <div>
                <p class="text-sm text-gray-600">This Month</p>
                <p class="text-2xl font-bold text-gray-900"><?php echo number_format($this_month_projects); ?></p>
            </div>
        </div>
    </div>
</div>

<!-- Quick Actions -->
<div class="bg-white rounded-xl shadow-sm border border-gray-200 mb-6">
    <div class="px-6 py-4 border-b border-gray-200">
        <h3 class="flex items-center text-lg font-semibold text-gray-900">
            <i class="fas fa-bolt mr-2 text-yellow-500"></i> Quick Actions
        </h3>
    </div>
    <div class="p-6">
        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-4">
            <?php if (has_permission('upload_csv_projects')): ?>
                <a href="importCsv.php" class="bg-blue-50 hover:bg-blue-100 border border-blue-200 rounded-lg p-4 transition-colors text-center">
                    <div class="w-10 h-10 bg-blue-600 rounded-full flex items-center justify-center mb-2 mx-auto">
                        <i class="fas fa-upload text-white"></i>
                    </div>
                    <h4 class="font-medium">Import CSV</h4>
                    <p class="text-sm text-gray-600">Bulk import</p>
                </a>
            <?php endif; ?>

            <?php if (has_permission('manage_projects')): ?>
                <a href="createProject.php" class="bg-green-50 hover:bg-green-100 border border-green-200 rounded-lg p-4 transition-colors text-center">
                    <div class="w-10 h-10 bg-green-600 rounded-full flex items-center justify-center mb-2 mx-auto">
                        <i class="fas fa-plus text-white"></i>
                    </div>
                    <h4 class="font-medium">Add Project</h4>
                    <p class="text-sm text-gray-600">Create new</p>
                </a>
            <?php endif; ?>

            <!-- Other quick action buttons (same as before) -->
        </div>
    </div>
</div>

<!-- Recent Activity Section -->
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
    <!-- Recent Projects -->
    <div class="bg-white rounded-xl shadow-sm border border-gray-200">
        <div class="px-6 py-4 border-b border-gray-200">
            <div class="flex items-center justify-between">
                <h3 class="text-lg font-semibold text-gray-900">Recent Projects</h3>
                <a href="projects.php" class="text-blue-600 hover:text-blue-500 text-sm font-medium">
                    View all <i class="fas fa-arrow-right ml-1"></i>
                </a>
            </div>
        </div>
        <div class="p-6">
            <div class="space-y-4">
                <?php foreach ($recent_projects as $project): ?>
                    <div class="border-l-4 border-blue-500 pl-4 py-2">
                        <div class="flex items-center justify-between">
                            <h4 class="font-medium text-gray-900">
                                <?php echo htmlspecialchars($project['project_name']); ?>
                            </h4>
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?php echo get_status_badge_class($project['status']); ?>">
                                <?php echo ucfirst($project['status']); ?>
                            </span>
                        </div>
                        <p class="text-sm text-gray-600 mt-1">
                            <?php echo htmlspecialchars($project['department_name']); ?> • 
                            <?php echo htmlspecialchars($project['sub_county_name']); ?>
                        </p>
                        <div class="flex items-center justify-between mt-2">
                            <span class="text-xs text-gray-500">
                                <?php echo format_date($project['created_at']); ?>
                            </span>
                            <span class="text-xs text-gray-500">
                                <?php echo $project['progress_percentage']; ?>% complete
                            </span>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <!-- Recent Feedback -->
    <div class="bg-white rounded-xl shadow-sm border border-gray-200">
        <div class="px-6 py-4 border-b border-gray-200">
            <div class="flex items-center justify-between">
                <h3 class="text-lg font-semibold text-gray-900">Recent Feedback</h3>
                <a href="feedback.php" class="text-blue-600 hover:text-blue-500 text-sm font-medium">
                    View all <i class="fas fa-arrow-right ml-1"></i>
                </a>
            </div>
        </div>
        <div class="p-6">
            <div class="space-y-4">
                <?php foreach ($recent_feedback as $feedback): ?>
                    <div class="flex items-start space-x-3">
                        <div class="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0">
                            <span class="text-blue-800 font-bold text-sm">
                                <?php echo strtoupper(substr($feedback['citizen_name'], 0, 1)); ?>
                            </span>
                        </div>
                        <div class="flex-1 min-w-0">
                            <div class="text-sm font-medium text-gray-900">
                                <?php echo htmlspecialchars($feedback['citizen_name']); ?>
                            </div>
                            <div class="text-sm text-gray-600">
                                <?php echo htmlspecialchars(substr($feedback['message'], 0, 100) . (strlen($feedback['message']) > 100 ? '...' : '')); ?>
                            </div>
                            <div class="text-xs text-gray-500 mt-1">
                                <?php echo htmlspecialchars($feedback['project_name'] ?? 'N/A'); ?> • <?php echo format_date($feedback['created_at']); ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
</div>

<!-- Feedback Overview (if permission) -->
<?php if (has_permission('approve_comments')): ?>
<div class="bg-white rounded-xl shadow-sm border border-gray-200 mb-8">
    <div class="px-6 py-4 border-b border-gray-200">
        <div class="flex items-center justify-between">
            <h3 class="text-lg font-semibold text-gray-900">Community Feedback Overview</h3>
            <a href="feedback.php" class="text-blue-600 hover:text-blue-500 text-sm font-medium">
                Manage feedback <i class="fas fa-arrow-right ml-1"></i>
            </a>
        </div>
    </div>
    <div class="p-6">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div class="text-center">
                <div class="text-2xl font-bold text-gray-900"><?php echo number_format($total_feedback); ?></div>
                <div class="text-sm text-gray-600">Total Feedback</div>
            </div>
            <div class="text-center">
                <div class="text-2xl font-bold text-yellow-600"><?php echo number_format($pending_feedback); ?></div>
                <div class="text-sm text-gray-600">Pending Review</div>
            </div>
            <div class="text-center">
                <div class="text-2xl font-bold text-green-600"><?php echo number_format($responded_feedback); ?></div>
                <div class="text-sm text-gray-600">Responded</div>
            </div>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- Auto-refresh script -->
<script>
document.addEventListener('DOMContentLoaded', function() {
    // Auto-refresh stats every 30 seconds
    setInterval(updateStats, 30000);
    updateStats();
    
    function updateStats() {
        // Your existing stats update logic
    }
});
</script>

<?php include 'includes/adminFooter.php'; ?>