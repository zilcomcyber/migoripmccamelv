<?php
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

require_admin();
$current_admin = get_current_admin();

// Log dashboard access
log_activity('admin_dashboard_access', 'Accessed main admin dashboard', $current_admin['id']);

try {
    // Get statistics
    $total_projects = $pdo->query("SELECT COUNT(*) FROM projects")->fetchColumn();
    $ongoing_projects = $pdo->query("SELECT COUNT(*) FROM projects WHERE status = 'ongoing'")->fetchColumn();
    $completed_projects = $pdo->query("SELECT COUNT(*) FROM projects WHERE status = 'completed'")->fetchColumn();
    $planning_projects = $pdo->query("SELECT COUNT(*) FROM projects WHERE status = 'planning'")->fetchColumn();
    $this_month_projects = $pdo->query("SELECT COUNT(*) FROM projects WHERE MONTH(created_at) = MONTH(CURDATE()) AND YEAR(created_at) = YEAR(CURDATE())")->fetchColumn();
    $total_feedback = $pdo->query("SELECT COUNT(*) FROM feedback")->fetchColumn();
    $pending_feedback = $pdo->query("SELECT COUNT(*) FROM feedback WHERE status = 'pending'")->fetchColumn();
    $responded_feedback = $pdo->query("SELECT COUNT(*) FROM feedback WHERE status = 'responded'")->fetchColumn();

    // Get recent projects and feedback
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
    // Set default values
    $total_projects = 0;
    $ongoing_projects = 0;
    $completed_projects = 0;
    $planning_projects = 0;
    $this_month_projects = 0;
    $total_feedback = 0;
    $pending_feedback = 0;
    $responded_feedback = 0;
    $recent_projects = [];
    $recent_feedback = [];
    $recent_activities = [];
}

$page_title = "Admin Dashboard";
include 'includes/adminHeader.php';
?>

<!-- Breadcrumb -->
<div class="mb-6">
    <nav class="flex" aria-label="Breadcrumb">
        <ol class="flex items-center space-x-2 text-sm">
            <li class="text-gray-600 font-medium">
                <i class="fas fa-home mr-1"></i> Dashboard
            </li>
        </ol>
    </nav>
</div>

<!-- Page Header -->
<div class="mb-8">
    <div class="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
        <div class="flex flex-col md:flex-row items-start justify-between">
            <div class="mb-4 md:mb-0">
                <h1 class="text-2xl font-bold text-gray-900 mb-2">
                    Welcome back, <?php echo htmlspecialchars($current_admin['name']); ?>!
                </h1>
                <p class="text-gray-600">Migori County PMC Portal Dashboard</p>
                <p class="text-sm text-gray-500 mt-2">
                    Last login: <?php echo date('F d, Y \a\t H:i A'); ?>
                </p>
            </div>
            <div class="text-center md:text-right">
                <div class="text-3xl font-bold text-blue-600 mb-1"><?php echo number_format($total_projects); ?></div>
                <div class="text-sm text-gray-600 mb-3">Total Projects</div>
                <?php if (has_permission('download_reports')): ?>
                    <a href="dashboard.php" class="inline-flex items-center px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700 transition-colors">
                        <i class="fas fa-chart-line mr-2"></i> Advanced Analytics
                    </a>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<!-- Quick Stats Grid -->
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
    <!-- Total Projects -->
    <div class="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
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
    <div class="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
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
    <div class="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
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
    <div class="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
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
<div class="bg-white shadow-sm rounded-lg border border-gray-200 mb-8">
    <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
        <h3 class="text-lg font-semibold text-gray-900 flex items-center">
            <i class="fas fa-bolt mr-2 text-yellow-500"></i> Quick Actions
        </h3>
    </div>
    <div class="p-6">
        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-4">
            <?php if (has_permission('upload_csv_projects')): ?>
                <a href="importCsv.php" class="group bg-gray-50 hover:bg-blue-50 border border-gray-200 hover:border-blue-200 rounded-lg p-4 transition-all duration-200 text-center">
                    <div class="w-10 h-10 bg-blue-600 group-hover:bg-blue-700 rounded-full flex items-center justify-center mb-3 mx-auto transition-colors">
                        <i class="fas fa-upload text-white"></i>
                    </div>
                    <h4 class="font-medium text-gray-900 mb-1">Import CSV</h4>
                    <p class="text-sm text-gray-600">Bulk import projects</p>
                </a>
            <?php endif; ?>

            <?php if (has_permission('manage_projects')): ?>
                <a href="createProject.php" class="group bg-gray-50 hover:bg-green-50 border border-gray-200 hover:border-green-200 rounded-lg p-4 transition-all duration-200 text-center">
                    <div class="w-10 h-10 bg-green-600 group-hover:bg-green-700 rounded-full flex items-center justify-center mb-3 mx-auto transition-colors">
                        <i class="fas fa-plus text-white"></i>
                    </div>
                    <h4 class="font-medium text-gray-900 mb-1">Add Project</h4>
                    <p class="text-sm text-gray-600">Create new project</p>
                </a>
            <?php endif; ?>

            <a href="projects.php" class="group bg-gray-50 hover:bg-indigo-50 border border-gray-200 hover:border-indigo-200 rounded-lg p-4 transition-all duration-200 text-center">
                <div class="w-10 h-10 bg-indigo-600 group-hover:bg-indigo-700 rounded-full flex items-center justify-center mb-3 mx-auto transition-colors">
                    <i class="fas fa-list text-white"></i>
                </div>
                <h4 class="font-medium text-gray-900 mb-1">View Projects</h4>
                <p class="text-sm text-gray-600">Manage all projects</p>
            </a>

            <?php if (has_permission('approve_comments')): ?>
                <a href="feedback.php" class="group bg-gray-50 hover:bg-orange-50 border border-gray-200 hover:border-orange-200 rounded-lg p-4 transition-all duration-200 text-center">
                    <div class="w-10 h-10 bg-orange-600 group-hover:bg-orange-700 rounded-full flex items-center justify-center mb-3 mx-auto transition-colors">
                        <i class="fas fa-comments text-white"></i>
                    </div>
                    <h4 class="font-medium text-gray-900 mb-1">Feedback</h4>
                    <p class="text-sm text-gray-600">Review citizen feedback</p>
                </a>
            <?php endif; ?>

            <?php if (has_permission('manage_budgets')): ?>
                <a href="budgetManagement.php" class="group bg-gray-50 hover:bg-emerald-50 border border-gray-200 hover:border-emerald-200 rounded-lg p-4 transition-all duration-200 text-center">
                    <div class="w-10 h-10 bg-emerald-600 group-hover:bg-emerald-700 rounded-full flex items-center justify-center mb-3 mx-auto transition-colors">
                        <i class="fas fa-calculator text-white"></i>
                    </div>
                    <h4 class="font-medium text-gray-900 mb-1">Budget</h4>
                    <p class="text-sm text-gray-600">Manage finances</p>
                </a>
            <?php endif; ?>

            <?php if (has_permission('download_reports')): ?>
                <a href="pmcReports.php" class="group bg-gray-50 hover:bg-purple-50 border border-gray-200 hover:border-purple-200 rounded-lg p-4 transition-all duration-200 text-center">
                    <div class="w-10 h-10 bg-purple-600 group-hover:bg-purple-700 rounded-full flex items-center justify-center mb-3 mx-auto transition-colors">
                        <i class="fas fa-chart-bar text-white"></i>
                    </div>
                    <h4 class="font-medium text-gray-900 mb-1">Reports</h4>
                    <p class="text-sm text-gray-600">Generate reports</p>
                </a>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Recent Activity Section -->
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
    <!-- Recent Projects -->
    <div class="bg-white shadow-sm rounded-lg border border-gray-200">
        <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
            <div class="flex items-center justify-between">
                <h3 class="text-lg font-semibold text-gray-900">Recent Projects</h3>
                <a href="projects.php" class="text-blue-600 hover:text-blue-700 text-sm font-medium transition-colors">
                    View all <i class="fas fa-arrow-right ml-1"></i>
                </a>
            </div>
        </div>
        <div class="p-6">
            <?php if (empty($recent_projects)): ?>
                <div class="text-center py-8">
                    <i class="fas fa-folder-open text-gray-400 text-3xl mb-4"></i>
                    <p class="text-gray-500">No projects found</p>
                    <?php if (has_permission('manage_projects')): ?>
                        <a href="createProject.php" class="inline-flex items-center px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700 transition-colors mt-4">
                            <i class="fas fa-plus mr-2"></i> Create First Project
                        </a>
                    <?php endif; ?>
                </div>
            <?php else: ?>
                <div class="space-y-4">
                    <?php foreach ($recent_projects as $project): ?>
                        <div class="border-l-4 border-blue-500 pl-4 py-2 hover:bg-gray-50 transition-colors">
                            <div class="flex items-center justify-between mb-2">
                                <h4 class="font-medium text-gray-900">
                                    <a href="manageProject.php?id=<?php echo $project['id']; ?>" class="hover:text-blue-600 transition-colors">
                                        <?php echo htmlspecialchars($project['project_name']); ?>
                                    </a>
                                </h4>
                                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?php echo get_status_badge_class($project['status']); ?>">
                                    <?php echo ucfirst($project['status']); ?>
                                </span>
                            </div>
                            <p class="text-sm text-gray-600 mb-2">
                                <?php echo htmlspecialchars($project['department_name']); ?> • 
                                <?php echo htmlspecialchars($project['sub_county_name']); ?>
                            </p>
                            <div class="flex items-center justify-between">
                                <span class="text-xs text-gray-500">
                                    <?php echo format_date($project['created_at']); ?>
                                </span>
                                <div class="flex items-center">
                                    <div class="w-16 bg-gray-200 rounded-full h-2 mr-2">
                                        <div class="bg-blue-600 h-2 rounded-full" style="width: <?php echo $project['progress_percentage']; ?>%"></div>
                                    </div>
                                    <span class="text-xs text-gray-500">
                                        <?php echo $project['progress_percentage']; ?>%
                                    </span>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Recent Feedback -->
    <div class="bg-white shadow-sm rounded-lg border border-gray-200">
        <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
            <div class="flex items-center justify-between">
                <h3 class="text-lg font-semibold text-gray-900">Recent Feedback</h3>
                <?php if (has_permission('approve_comments')): ?>
                    <a href="feedback.php" class="text-blue-600 hover:text-blue-700 text-sm font-medium transition-colors">
                        View all <i class="fas fa-arrow-right ml-1"></i>
                    </a>
                <?php endif; ?>
            </div>
        </div>
        <div class="p-6">
            <?php if (empty($recent_feedback)): ?>
                <div class="text-center py-8">
                    <i class="fas fa-comments text-gray-400 text-3xl mb-4"></i>
                    <p class="text-gray-500">No feedback yet</p>
                </div>
            <?php else: ?>
                <div class="space-y-4">
                    <?php foreach ($recent_feedback as $feedback): ?>
                        <div class="flex items-start space-x-3 hover:bg-gray-50 p-2 rounded transition-colors">
                            <div class="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center flex-shrink-0">
                                <span class="text-blue-800 font-bold text-sm">
                                    <?php echo strtoupper(substr($feedback['citizen_name'], 0, 1)); ?>
                                </span>
                            </div>
                            <div class="flex-1 min-w-0">
                                <div class="text-sm font-medium text-gray-900">
                                    <?php echo htmlspecialchars($feedback['citizen_name']); ?>
                                </div>
                                <div class="text-sm text-gray-600 line-clamp-2">
                                    <?php echo htmlspecialchars(substr($feedback['message'], 0, 100) . (strlen($feedback['message']) > 100 ? '...' : '')); ?>
                                </div>
                                <div class="text-xs text-gray-500 mt-1 flex items-center space-x-2">
                                    <span><?php echo htmlspecialchars($feedback['project_name'] ?? 'General Feedback'); ?></span>
                                    <span>•</span>
                                    <span><?php echo format_date($feedback['created_at']); ?></span>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Community Feedback Overview -->
<?php if (has_permission('approve_comments')): ?>
<div class="bg-white shadow-sm rounded-lg border border-gray-200 mb-8">
    <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
        <div class="flex items-center justify-between">
            <h3 class="text-lg font-semibold text-gray-900">Community Feedback Overview</h3>
            <a href="feedback.php" class="text-blue-600 hover:text-blue-700 text-sm font-medium transition-colors">
                Manage feedback <i class="fas fa-arrow-right ml-1"></i>
            </a>
        </div>
    </div>
    <div class="p-6">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div class="text-center">
                <div class="text-3xl font-bold text-gray-900 mb-1"><?php echo number_format($total_feedback); ?></div>
                <div class="text-sm text-gray-600">Total Feedback</div>
            </div>
            <div class="text-center">
                <div class="text-3xl font-bold text-yellow-600 mb-1"><?php echo number_format($pending_feedback); ?></div>
                <div class="text-sm text-gray-600">Pending Review</div>
                <?php if ($pending_feedback > 0): ?>
                    <div class="mt-2">
                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                            Needs Attention
                        </span>
                    </div>
                <?php endif; ?>
            </div>
            <div class="text-center">
                <div class="text-3xl font-bold text-green-600 mb-1"><?php echo number_format($responded_feedback); ?></div>
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
    
    function updateStats() {
        fetch('ajax/getDashboardStats.php')
            .then(response => response.json())
            .then(data => {
                document.querySelector('.total-projects').textContent = data.total_projects;
                document.querySelector('.ongoing-projects').textContent = data.ongoing_projects;
                document.querySelector('.completed-projects').textContent = data.completed_projects;
                document.querySelector('.this-month-projects').textContent = data.this_month_projects;
                document.querySelector('.total-feedback').textContent = data.total_feedback;
                document.querySelector('.pending-feedback').textContent = data.pending_feedback;
                document.querySelector('.responded-feedback').textContent = data.responded_feedback;
            })
            .catch(error => console.error('Error updating stats:', error));
    }
});
</script>

<?php include 'includes/adminFooter.php'; ?>




