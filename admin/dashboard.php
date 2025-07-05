<?php
require_once 'includes/pageSecurity.php';
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';
require_once '../includes/rbac.php';

require_role('admin');
$current_admin = get_current_admin();

$page_title = "Advanced Analytics Dashboard";

include 'includes/adminHeader.php';

// Log dashboard access
log_activity('dashboard_access', 'Accessed PMC analytics dashboard', $current_admin['id']);

// Get dashboard statistics
try {
    // Project statistics
    $stats = [];
    $stats['total_projects'] = $pdo->query("SELECT COUNT(*) FROM projects")->fetchColumn();
    $stats['planning_projects'] = $pdo->query("SELECT COUNT(*) FROM projects WHERE status = 'planning'")->fetchColumn();
    $stats['ongoing_projects'] = $pdo->query("SELECT COUNT(*) FROM projects WHERE status = 'ongoing'")->fetchColumn();
    $stats['completed_projects'] = $pdo->query("SELECT COUNT(*) FROM projects WHERE status = 'completed'")->fetchColumn();
    $stats['suspended_projects'] = $pdo->query("SELECT COUNT(*) FROM projects WHERE status = 'suspended'")->fetchColumn();
    $stats['cancelled_projects'] = $pdo->query("SELECT COUNT(*) FROM projects WHERE status = 'cancelled'")->fetchColumn();

    // Feedback statistics
    $feedback_stats = [];
    $feedback_stats['total_feedback'] = $pdo->query("SELECT COUNT(*) FROM feedback")->fetchColumn();
    $feedback_stats['pending_feedback'] = $pdo->query("SELECT COUNT(*) FROM feedback WHERE status = 'pending'")->fetchColumn();
    $feedback_stats['reviewed_feedback'] = $pdo->query("SELECT COUNT(*) FROM feedback WHERE status = 'reviewed'")->fetchColumn();
    $feedback_stats['responded_feedback'] = $pdo->query("SELECT COUNT(*) FROM feedback WHERE status = 'responded'")->fetchColumn();

    // Recent projects
    $recent_projects = $pdo->query("SELECT p.*, d.name as department_name 
                                   FROM projects p 
                                   JOIN departments d ON p.department_id = d.id 
                                   ORDER BY p.created_at DESC LIMIT 5")->fetchAll();

    // Projects by year
    $projects_by_year = $pdo->query("SELECT project_year, COUNT(*) as count 
                                    FROM projects 
                                    GROUP BY project_year 
                                    ORDER BY project_year DESC")->fetchAll();

    // Projects by status
    $projects_by_status = $pdo->query("SELECT status, COUNT(*) as count 
                                      FROM projects 
                                      GROUP BY status")->fetchAll();

    // Projects by department
    $projects_by_department = $pdo->query("SELECT d.name, COUNT(*) as count 
                                          FROM projects p 
                                          JOIN departments d ON p.department_id = d.id 
                                          GROUP BY d.id, d.name 
                                          ORDER BY count DESC")->fetchAll();

    // Recent activities
    $recent_activities = get_recent_activities(10);

} catch (Exception $e) {
    error_log("Dashboard Error: " . $e->getMessage());
    $stats = [];
    $feedback_stats = [];
    $recent_projects = [];
    $projects_by_year = [];
    $projects_by_status = [];
    $projects_by_department = [];
    $recent_activities = [];
}
?>

<!-- Breadcrumbs -->
<div class="mb-6">
    <nav class="flex" aria-label="Breadcrumb">
        <ol class="flex items-center space-x-2">
            <li><a href="index.php" class="text-gray-500 hover:text-gray-700">Dashboard</a></li>
            <li><span class="text-gray-400">/</span></li>
            <li><span class="text-gray-900">Analytics</span></li>
        </ol>
    </nav>
</div>

<!-- PMC Overview Header -->
<div class="mb-8">
    <div class="bg-gradient-to-r from-pmc-navy to-blue-800 rounded-lg p-6 text-white">
        <div class="flex items-center justify-between">
            <div>
                <h2 class="text-2xl font-bold mb-2">PMC Analytics Dashboard</h2>
                <p class="text-sm text-blue-200 mt-2">
                    Last updated: <?php echo date('F d, Y \a\t H:i A'); ?>
                </p>
            </div>
            <div class="text-right">
                <div class="text-3xl font-bold"><?php echo number_format($stats['total_projects'] ?? 0); ?></div>
                <div class="text-sm text-blue-200">Total Projects</div>
            </div>
        </div>
    </div>
</div>

<!-- Enhanced Stats Overview -->
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
    <!-- Active Projects -->
    <div class="pmc-card">
        <div class="pmc-card-content">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <div class="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
                        <i class="fas fa-clock text-blue-600 text-xl"></i>
                    </div>
                </div>
                <div class="ml-4 flex-1">
                    <p class="text-sm font-medium text-gray-900">Active Projects</p>
                    <p class="text-2xl font-bold text-blue-600"><?php echo number_format($stats['ongoing_projects'] ?? 0); ?></p>
                    <p class="text-xs text-gray-500">Currently in progress</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Completed Projects -->
    <div class="pmc-card">
        <div class="pmc-card-content">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <div class="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
                        <i class="fas fa-check-circle text-green-600 text-xl"></i>
                    </div>
                </div>
                <div class="ml-4 flex-1">
                    <p class="text-sm font-medium text-gray-900">Completed</p>
                    <p class="text-2xl font-bold text-green-600"><?php echo number_format($stats['completed_projects'] ?? 0); ?></p>
                    <p class="text-xs text-gray-500">Successfully delivered</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Community Engagement -->
    <div class="pmc-card">
        <div class="pmc-card-content">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <div class="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center">
                        <i class="fas fa-users text-purple-600 text-xl"></i>
                    </div>
                </div>
                <div class="ml-4 flex-1">
                    <p class="text-sm font-medium text-gray-900">Pending Reviews</p>
                    <p class="text-2xl font-bold text-purple-600"><?php echo number_format($feedback_stats['pending_feedback'] ?? 0); ?></p>
                    <p class="text-xs text-gray-500">Community feedback</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Planning Phase -->
    <div class="pmc-card">
        <div class="pmc-card-content">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <div class="w-12 h-12 bg-yellow-100 rounded-lg flex items-center justify-center">
                        <i class="fas fa-drafting-compass text-yellow-600 text-xl"></i>
                    </div>
                </div>
                <div class="ml-4 flex-1">
                    <p class="text-sm font-medium text-gray-900">Planning Phase</p>
                    <p class="text-2xl font-bold text-yellow-600"><?php echo number_format($stats['planning_projects'] ?? 0); ?></p>
                    <p class="text-xs text-gray-500">In development</p>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Charts and Tables -->
<div class="grid grid-cols-1 xl:grid-cols-2 gap-8 mb-8">
    <!-- Projects by Status Chart -->
    <div class="pmc-card">
        <div class="pmc-card-header">
            <h3 class="text-lg font-semibold text-gray-900">Projects by Status</h3>
        </div>
        <div class="pmc-card-content">
            <canvas id="statusChart" width="400" height="300"></canvas>
        </div>
    </div>

    <!-- Recent Activities -->
    <div class="pmc-card">
        <div class="pmc-card-header">
            <div class="flex items-center justify-between">
                <h3 class="text-lg font-semibold text-gray-900">Recent Activities</h3>
                <a href="activityLogs.php" class="text-blue-600 hover:text-blue-500 text-sm font-medium">
                    View all <i class="fas fa-arrow-right ml-1"></i>
                </a>
            </div>
        </div>
        <div class="pmc-card-content">
            <div class="space-y-4">
                <?php foreach (array_slice($recent_activities, 0, 5) as $activity): ?>
                    <div class="flex items-start space-x-3 p-3 bg-gray-50 rounded-lg">
                        <div class="w-8 h-8 bg-pmc-gold rounded-full flex items-center justify-center flex-shrink-0">
                            <span class="text-pmc-navy font-bold text-sm">
                                <?php echo strtoupper(substr($activity['admin_name'] ?? 'S', 0, 1)); ?>
                            </span>
                        </div>
                        <div class="flex-1 min-w-0">
                            <div class="text-sm font-medium text-gray-900">
                                <?php echo htmlspecialchars($activity['admin_name'] ?? 'System'); ?>
                            </div>
                            <div class="text-sm text-gray-600">
                                <?php echo htmlspecialchars($activity['activity_description']); ?>
                            </div>
                            <div class="text-xs text-gray-500 mt-1">
                                <?php echo format_date($activity['created_at']); ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>

                <?php if (empty($recent_activities)): ?>
                    <div class="text-center text-gray-500 py-6">
                        <i class="fas fa-history text-2xl text-gray-300 mb-2"></i>
                        <p>No recent activities</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<!-- Projects by Department -->
<div class="pmc-card mb-8">
    <div class="pmc-card-header">
        <h3 class="text-lg font-semibold text-gray-900">Projects by Department</h3>
    </div>
    <div class="pmc-card-content">
        <div class="space-y-4">
            <?php foreach ($projects_by_department as $dept): ?>
                <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div class="flex-1">
                        <div class="text-sm font-medium text-gray-900">
                            <?php echo htmlspecialchars($dept['name']); ?>
                        </div>
                    </div>
                    <div class="text-sm font-medium text-gray-900">
                        <?php echo $dept['count']; ?> projects
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
// Status Chart
const statusData = <?php echo json_encode($projects_by_status); ?>;
const statusLabels = statusData.map(item => item.status.charAt(0).toUpperCase() + item.status.slice(1));
const statusCounts = statusData.map(item => item.count);
const statusColors = ['#f59e0b', '#3b82f6', '#10b981', '#f97316', '#ef4444'];

const statusCtx = document.getElementById('statusChart').getContext('2d');
new Chart(statusCtx, {
    type: 'doughnut',
    data: {
        labels: statusLabels,
        datasets: [{
            data: statusCounts,
            backgroundColor: statusColors,
            borderWidth: 2,
            borderColor: '#ffffff'
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'bottom'
            }
        }
    }
});
</script>

<?php include 'includes/adminHooter.php'; ?>