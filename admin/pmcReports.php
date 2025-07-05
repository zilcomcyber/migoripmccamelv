<?php
require_once 'includes/pageSecurity.php';
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';
require_once '../includes/rbac.php';

// Require authentication and permission to view reports
require_admin();
if (!has_permission('view_reports')) {
    header('Location: index.php?error=access_denied');
    exit;
}

$current_admin = get_current_admin();

// Log access to reports
log_activity('pmc_reports_access', 'Accessed PMC reports page', $current_admin['id']);

$page_title = "PMC Reports";

include 'includes/adminHeader.php';

// Get report statistics with role-based filtering
try {
    $where_clause = "";
    $params = [];
    
    // Non-super admins can only see their own projects
    if ($current_admin['role'] !== 'super_admin') {
        $where_clause = " WHERE created_by = ?";
        $params[] = $current_admin['id'];
    }
    
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $where_clause);
    $stmt->execute($params);
    $total_projects = $stmt->fetchColumn();
    
    $completed_params = $params;
    if ($where_clause) {
        $completed_params[] = 'completed';
    } else {
        $completed_params = ['completed'];
    }
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $where_clause . ($where_clause ? " AND" : " WHERE") . " status = ?");
    $stmt->execute($completed_params);
    $completed_projects = $stmt->fetchColumn();
    
    $ongoing_params = $params;
    if ($where_clause) {
        $ongoing_params[] = 'ongoing';
    } else {
        $ongoing_params = ['ongoing'];
    }
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $where_clause . ($where_clause ? " AND" : " WHERE") . " status = ?");
    $stmt->execute($ongoing_params);
    $ongoing_projects = $stmt->fetchColumn();
    
    $stmt = $pdo->prepare("SELECT SUM(total_budget) FROM projects" . $where_clause . ($where_clause ? " AND" : " WHERE") . " total_budget IS NOT NULL");
    $stmt->execute($params);
    $total_budget = $stmt->fetchColumn() ?: 0;

    // Projects by sub-county with role-based filtering
    $location_sql = "
        SELECT sc.name as sub_county, COUNT(*) as project_count, 
               SUM(p.total_budget) as total_budget,
               AVG(p.progress_percentage) as avg_progress
        FROM projects p 
        JOIN sub_counties sc ON p.sub_county_id = sc.id" . $where_clause . "
        GROUP BY sc.id, sc.name 
        ORDER BY project_count DESC
    ";
    $stmt = $pdo->prepare($location_sql);
    $stmt->execute($params);
    $projects_by_location = $stmt->fetchAll();

    // Recent milestones with role-based filtering
    $milestones_sql = "
        SELECT p.project_name, ps.step_name, ps.completion_date, ps.status
        FROM project_steps ps 
        JOIN projects p ON ps.project_id = p.id" . $where_clause . "
        AND ps.completion_date IS NOT NULL 
        ORDER BY ps.completion_date DESC 
        LIMIT 10
    ";
    $stmt = $pdo->prepare($milestones_sql);
    $stmt->execute($params);
    $recent_milestones = $stmt->fetchAll();

    // Pending grievances with role-based filtering
    $grievances_params = $params;
    if ($where_clause) {
        $grievances_params[] = 'pending';
    } else {
        $grievances_params = ['pending'];
    }
    $grievances_sql = "
        SELECT COUNT(*) FROM feedback f
        JOIN projects p ON f.project_id = p.id" . $where_clause . 
        ($where_clause ? " AND" : " WHERE") . " f.status = ?
    ";
    $stmt = $pdo->prepare($grievances_sql);
    $stmt->execute($grievances_params);
    $pending_grievances = $stmt->fetchColumn();

} catch (Exception $e) {
    error_log("PMC Reports Error: " . $e->getMessage());
}

$page_title = "PMC Reports";
$breadcrumbs = [
    ['title' => 'Dashboard', 'url' => 'index.php'],
    ['title' => 'PMC Reports']
];

ob_start();
?>

<!-- Report Overview Cards -->
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
    <div class="bg-white rounded-lg shadow-sm p-6">
        <div class="flex items-center">
            <div class="bg-blue-100 rounded-lg p-3">
                <i class="fas fa-project-diagram text-blue-600 text-xl"></i>
            </div>
            <div class="ml-4">
                <p class="text-gray-600 text-sm font-medium">Total Projects</p>
                <p class="text-2xl font-bold text-gray-800"><?php echo number_format($total_projects ?? 0); ?></p>
            </div>
        </div>
    </div>

    <div class="bg-white rounded-lg shadow-sm p-6">
        <div class="flex items-center">
            <div class="bg-green-100 rounded-lg p-3">
                <i class="fas fa-check-circle text-green-600 text-xl"></i>
            </div>
            <div class="ml-4">
                <p class="text-gray-600 text-sm font-medium">Completed</p>
                <p class="text-2xl font-bold text-green-600"><?php echo number_format($completed_projects ?? 0); ?></p>
            </div>
        </div>
    </div>

    <div class="bg-white rounded-lg shadow-sm p-6">
        <div class="flex items-center">
            <div class="bg-blue-100 rounded-lg p-3">
                <i class="fas fa-clock text-blue-500 text-xl"></i>
            </div>
            <div class="ml-4">
                <p class="text-gray-600 text-sm font-medium">Ongoing</p>
                <p class="text-2xl font-bold text-blue-600"><?php echo number_format($ongoing_projects ?? 0); ?></p>
            </div>
        </div>
    </div>

    <div class="bg-white rounded-lg shadow-sm p-6">
        <div class="flex items-center">
            <div class="bg-yellow-100 rounded-lg p-3">
                <i class="fas fa-money-bill-wave text-yellow-600 text-xl"></i>
            </div>
            <div class="ml-4">
                <p class="text-gray-600 text-sm font-medium">Total Budget</p>
                <p class="text-2xl font-bold text-yellow-600">KES <?php echo number_format($total_budget ?? 0); ?></p>
            </div>
        </div>
    </div>
</div>

<!-- Report Generation -->
<div class="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
    <!-- Generate Reports -->
    <div class="bg-white rounded-lg shadow-sm p-6">
        <div class="flex items-center justify-between mb-6">
            <h3 class="text-lg font-semibold text-gray-800">Generate Official Reports</h3>
            <i class="fas fa-file-download text-blue-600"></i>
        </div>

        <div class="space-y-4">
            <form method="POST" action="../api/exportPdf.php" class="border border-gray-200 rounded-lg p-4">
                <input type="hidden" name="report_type" value="pmc_summary">
                <div class="flex items-center justify-between">
                    <div>
                        <h4 class="font-medium text-gray-800">PMC Summary Report</h4>
                        <p class="text-sm text-gray-600">Comprehensive project overview for county leadership</p>
                    </div>
                    <button type="submit" class="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm">
                        <i class="fas fa-file-pdf mr-2"></i>Generate PDF
                    </button>
                </div>
            </form>

            <form method="POST" action="../api/exportCsv.php" class="border border-gray-200 rounded-lg p-4">
                <input type="hidden" name="report_type" value="project_progress">
                <div class="flex items-center justify-between">
                    <div>
                        <h4 class="font-medium text-gray-800">Project Progress Report</h4>
                        <p class="text-sm text-gray-600">Detailed progress tracking for all projects</p>
                    </div>
                    <button type="submit" class="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm">
                        <i class="fas fa-file-excel mr-2"></i>Export CSV
                    </button>
                </div>
            </form>

            <form method="POST" action="../api/exportPdf.php" class="border border-gray-200 rounded-lg p-4">
                <input type="hidden" name="report_type" value="grievance_summary">
                <div class="flex items-center justify-between">
                    <div>
                        <h4 class="font-medium text-gray-800">Grievance & Feedback Report</h4>
                        <p class="text-sm text-gray-600">Community feedback and grievance management</p>
                    </div>
                    <button type="submit" class="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm">
                        <i class="fas fa-file-pdf mr-2"></i>Generate PDF
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Quick Stats -->
    <div class="bg-white rounded-lg shadow-sm p-6">
        <div class="flex items-center justify-between mb-6">
            <h3 class="text-lg font-semibold text-gray-800">Quick Statistics</h3>
            <i class="fas fa-chart-pie text-blue-600"></i>
        </div>

        <div class="space-y-4">
            <div class="flex items-center justify-between py-2 border-b border-gray-100">
                <span class="text-gray-600">Project Completion Rate</span>
                <span class="font-semibold text-green-600">
                    <?php echo $total_projects > 0 ? round(($completed_projects / $total_projects) * 100, 1) : 0; ?>%
                </span>
            </div>

            <div class="flex items-center justify-between py-2 border-b border-gray-100">
                <span class="text-gray-600">Pending Grievances</span>
                <span class="font-semibold text-red-600"><?php echo $pending_grievances ?? 0; ?></span>
            </div>

            <div class="flex items-center justify-between py-2 border-b border-gray-100">
                <span class="text-gray-600">Sub-Counties Covered</span>
                <span class="font-semibold text-blue-600"><?php echo count($projects_by_location ?? []); ?></span>
            </div>

            <div class="flex items-center justify-between py-2">
                <span class="text-gray-600">Average Progress</span>
                <span class="font-semibold text-blue-600">
                    <?php 
                    $avg_progress = 0;
                    if (!empty($projects_by_location)) {
                        $total_progress = array_sum(array_column($projects_by_location, 'avg_progress'));
                        $avg_progress = round($total_progress / count($projects_by_location), 1);
                    }
                    echo $avg_progress; 
                    ?>%
                </span>
            </div>
        </div>
    </div>
</div>

<!-- Projects by Location -->
<div class="bg-white rounded-lg shadow-sm mb-8">
    <div class="px-6 py-4 border-b border-gray-200">
        <h3 class="text-lg font-semibold text-gray-800">Projects by Sub-County</h3>
    </div>
    <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Sub-County</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Projects</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Budget (KES)</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Avg. Progress</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
                <?php if (!empty($projects_by_location)): ?>
                    <?php foreach ($projects_by_location as $location): ?>
                        <tr>
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                <?php echo htmlspecialchars($location['sub_county']); ?>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                <?php echo number_format($location['project_count']); ?>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                <?php echo number_format($location['total_budget'] ?? 0); ?>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap">
                                <div class="flex items-center">
                                    <div class="flex-1 bg-gray-200 rounded-full h-2 mr-3">
                                        <div class="bg-green-500 h-2 rounded-full" style="width: <?php echo $location['avg_progress']; ?>%"></div>
                                    </div>
                                    <span class="text-sm text-gray-900"><?php echo round($location['avg_progress'] ?? 0, 1); ?>%</span>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php else: ?>
                    <tr>
                        <td colspan="4" class="px-6 py-4 text-center text-gray-500">No data available</td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- Recent Milestones -->
<div class="bg-white rounded-lg shadow-sm">
    <div class="px-6 py-4 border-b border-gray-200">
        <h3 class="text-lg font-semibold text-gray-800">Recent Project Milestones</h3>
    </div>
    <div class="p-6">
        <?php if (!empty($recent_milestones)): ?>
            <div class="space-y-4">
                <?php foreach ($recent_milestones as $milestone): ?>
                    <div class="flex items-center p-3 bg-gray-50 rounded-lg">
                        <div class="flex-shrink-0">
                            <div class="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center">
                                <i class="fas fa-check text-white text-sm"></i>
                            </div>
                        </div>
                        <div class="ml-4 flex-1">
                            <h4 class="text-sm font-medium text-gray-800"><?php echo htmlspecialchars($milestone['project_name']); ?></h4>
                            <p class="text-sm text-gray-600"><?php echo htmlspecialchars($milestone['step_name']); ?></p>
                        </div>
                        <div class="text-sm text-gray-500">
                            <?php echo date('M d, Y', strtotime($milestone['completion_date'])); ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php else: ?>
            <p class="text-gray-500 text-center py-4">No recent milestones</p>
        <?php endif; ?>
    </div>
</div>

<?php
$content = ob_get_clean();
echo '<div class="admin-content">' . $content . '</div>';
include 'includes/adminFooter.php';
?>