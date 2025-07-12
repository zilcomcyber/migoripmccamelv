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

<style>
/* Mobile-first responsive design for PMC Reports */
.reports-container {
    background: #f8f9fa;
}

.main-card {
    background: #ffffff !important;
    border-radius: 8px;
    border: 1px solid #e5e7eb;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

.card-header {
    background: #ffffff !important;
    border-bottom: 1px solid #e5e7eb;
    border-radius: 8px 8px 0 0;
}

.card-content {
    background: #ffffff !important;
}

.stats-header {
    background: #ffffff !important;
    border-radius: 8px;
    border: 1px solid #e5e7eb;
    margin-bottom: 1rem;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 0.75rem;
    margin-bottom: 1rem;
}

.stat-card {
    background: #f8f9fa;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    padding: 0.75rem;
    text-align: center;
}

.stat-icon {
    width: 32px;
    height: 32px;
    border-radius: 6px;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0 auto 0.5rem;
    font-size: 1rem;
}

.stat-value {
    font-size: 1.25rem;
    font-weight: bold;
    margin-bottom: 0.25rem;
}

.stat-label {
    font-size: 0.75rem;
    color: #6b7280;
}

.reports-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 1rem;
    margin-bottom: 1rem;
}

.report-card {
    background: #ffffff !important;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    padding: 1rem;
}

.report-form {
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    padding: 0.75rem;
    margin-bottom: 0.75rem;
    background: #f8f9fa;
}

.location-table-container {
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
    margin: 1rem 0;
}

.location-table {
    width: 100%;
    min-width: 500px;
    border-collapse: collapse;
    background: white;
    border-radius: 6px;
    overflow: hidden;
    border: 1px solid #e5e7eb;
}

.location-table th {
    background: #f8f9fa;
    padding: 0.75rem;
    text-align: left;
    font-weight: 600;
    color: #374151;
    border-bottom: 1px solid #e5e7eb;
    font-size: 0.875rem;
}

.location-table td {
    padding: 0.75rem;
    border-bottom: 1px solid #f3f4f6;
    font-size: 0.875rem;
}

.location-table tr:hover {
    background: #f9fafb;
}

.progress-bar {
    width: 100%;
    height: 8px;
    background: #e5e7eb;
    border-radius: 4px;
    overflow: hidden;
}

.progress-fill {
    height: 100%;
    background: #10b981;
    border-radius: 4px;
}

.milestone-item {
    padding: 0.75rem;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    margin-bottom: 0.5rem;
    background: #f8f9fa;
}

.milestone-header {
    font-weight: 600;
    color: #374151;
    font-size: 0.875rem;
    margin-bottom: 0.25rem;
}

.milestone-project {
    color: #6b7280;
    font-size: 0.8125rem;
    margin-bottom: 0.25rem;
}

.milestone-date {
    color: #9ca3af;
    font-size: 0.75rem;
}

.btn-export {
    padding: 0.5rem 0.75rem;
    font-size: 0.875rem;
    border-radius: 6px;
    border: none;
    cursor: pointer;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.5rem;
    width: 100%;
    justify-content: center;
}

.btn-primary { background: #3b82f6; color: white; }
.btn-primary:hover { background: #2563eb; }
.btn-success { background: #10b981; color: white; }
.btn-success:hover { background: #059669; }
.btn-danger { background: #ef4444; color: white; }
.btn-danger:hover { background: #dc2626; }

@media (min-width: 640px) {

    .stats-grid {
        grid-template-columns: repeat(2, 1fr);
        gap: 1rem;
    }

    .stat-card {
        padding: 1rem;
    }

    .stat-icon {
        width: 40px;
        height: 40px;
        font-size: 1.25rem;
    }

    .stat-value {
        font-size: 1.5rem;
    }

    .stat-label {
        font-size: 0.875rem;
    }

    .btn-export {
        width: auto;
    }
}

@media (min-width: 768px) {
    .reports-container {
        padding: 1rem;
    }

    .reports-grid {
        grid-template-columns: repeat(2, 1fr);
        gap: 1.5rem;
    }

    .stats-grid {
        grid-template-columns: repeat(4, 1fr);
    }

    .card-header, .card-content {
        padding: 1.5rem;
    }
}

@media (min-width: 1024px) {
    .reports-container {
        padding: 1.5rem;
    }
}
</style>

<div class="mb-8 reports-container">
    <!-- Breadcrumb -->
    <div class="mb-4">
        <nav class="flex text-sm" aria-label="Breadcrumb">
            <ol class="flex items-center space-x-2">
                <li>
                    <a href="index.php" class="text-blue-600 hover:text-blue-800 font-medium">
                        <i class="fas fa-home mr-1"></i> Dashboard
                    </a>
                </li>
                <li class="text-gray-400">/</li>
                <li class="text-gray-600 font-medium">PMC Reports</li>
            </ol>
        </nav>
    </div>

    <!-- Page Header -->
    <div class="stats-header">
        <div class="flex flex-col md:flex-row items-start justify-between">
            <div>
                <h1 class="text-xl font-bold text-gray-900 mb-1">PMC Reports</h1>
                <p class="text-sm text-gray-600">Comprehensive project reporting and analytics</p>
                <p class="text-xs text-gray-500 mt-1">Generate detailed reports for project monitoring</p>
            </div>
            <div class="text-center mt-2 md:mt-0">
                <div class="text-2xl font-bold text-blue-600"><?php echo number_format($total_projects); ?></div>
                <div class="text-xs text-gray-600">Total Projects</div>
            </div>
        </div>
    </div>

    <!-- Main Card -->
    <div class="main-card">
        <div class="card-content">
            <!-- Statistics Grid -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon bg-blue-100 text-blue-600">
                        <i class="fas fa-project-diagram"></i>
                    </div>
                    <div class="stat-value text-blue-600"><?php echo number_format($total_projects ?? 0); ?></div>
                    <div class="stat-label">Total Projects</div>
                </div>

                <div class="stat-card">
                    <div class="stat-icon bg-green-100 text-green-600">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <div class="stat-value text-green-600"><?php echo number_format($completed_projects ?? 0); ?></div>
                    <div class="stat-label">Completed</div>
                </div>

                <div class="stat-card">
                    <div class="stat-icon bg-blue-100 text-blue-500">
                        <i class="fas fa-clock"></i>
                    </div>
                    <div class="stat-value text-blue-600"><?php echo number_format($ongoing_projects ?? 0); ?></div>
                    <div class="stat-label">Ongoing</div>
                </div>

                <div class="stat-card">
                    <div class="stat-icon bg-yellow-100 text-yellow-600">
                        <i class="fas fa-money-bill-wave"></i>
                    </div>
                    <div class="stat-value text-yellow-600">KES <?php echo number_format($total_budget ?? 0); ?></div>
                    <div class="stat-label">Total Budget</div>
                </div>
            </div>

            <!-- Reports Grid -->
            <div class="reports-grid">
                <!-- Generate Reports -->
                <div class="report-card">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="text-lg font-semibold text-gray-800">Generate Official Reports</h3>
                        <i class="fas fa-file-download text-blue-600"></i>
                    </div>

                    <div class="space-y-3">
                        <form method="POST" action="../api/exportPdf.php" class="report-form">
                            <input type="hidden" name="report_type" value="pmc_summary">
                            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                                <div class="flex-1">
                                    <h4 class="font-medium text-gray-800 text-sm">PMC Summary Report</h4>
                                    <p class="text-xs text-gray-600">Comprehensive project overview for county leadership</p>
                                </div>
                                <button type="submit" class="btn-export btn-danger">
                                    <i class="fas fa-file-pdf"></i>Generate PDF
                                </button>
                            </div>
                        </form>

                        <form method="POST" action="../api/exportCsv.php" class="report-form">
                            <input type="hidden" name="report_type" value="project_progress">
                            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                                <div class="flex-1">
                                    <h4 class="font-medium text-gray-800 text-sm">Project Progress Report</h4>
                                    <p class="text-xs text-gray-600">Detailed progress tracking for all projects</p>
                                </div>
                                <button type="submit" class="btn-export btn-success">
                                    <i class="fas fa-file-excel"></i>Export CSV
                                </button>
                            </div>
                        </form>

                        <form method="POST" action="../api/exportPdf.php" class="report-form">
                            <input type="hidden" name="report_type" value="grievance_summary">
                            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                                <div class="flex-1">
                                    <h4 class="font-medium text-gray-800 text-sm">Grievance & Feedback Report</h4>
                                    <p class="text-xs text-gray-600">Community feedback and grievance management</p>
                                </div>
                                <button type="submit" class="btn-export btn-danger">
                                    <i class="fas fa-file-pdf"></i>Generate PDF
                                </button>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Quick Stats -->
                <div class="report-card">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="text-lg font-semibold text-gray-800">Quick Statistics</h3>
                        <i class="fas fa-chart-pie text-blue-600"></i>
                    </div>

                    <div class="space-y-3">
                        <div class="flex items-center justify-between py-2 border-b border-gray-100">
                            <span class="text-gray-600 text-sm">Project Completion Rate</span>
                            <span class="font-semibold text-green-600 text-sm">
                                <?php echo $total_projects > 0 ? round(($completed_projects / $total_projects) * 100, 1) : 0; ?>%
                            </span>
                        </div>

                        <div class="flex items-center justify-between py-2 border-b border-gray-100">
                            <span class="text-gray-600 text-sm">Pending Grievances</span>
                            <span class="font-semibold text-red-600 text-sm"><?php echo $pending_grievances ?? 0; ?></span>
                        </div>

                        <div class="flex items-center justify-between py-2 border-b border-gray-100">
                            <span class="text-gray-600 text-sm">Sub-Counties Covered</span>
                            <span class="font-semibold text-blue-600 text-sm"><?php echo count($projects_by_location ?? []); ?></span>
                        </div>

                        <div class="flex items-center justify-between py-2">
                            <span class="text-gray-600 text-sm">Average Progress</span>
                            <span class="font-semibold text-blue-600 text-sm">
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
            <div class="report-card">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-semibold text-gray-800">Projects by Sub-County</h3>
                </div>

                <div class="location-table-container">
                    <table class="location-table">
                        <thead>
                            <tr>
                                <th>Sub-County</th>
                                <th>Projects</th>
                                <th>Budget (KES)</th>
                                <th>Avg. Progress</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (!empty($projects_by_location)): ?>
                                <?php foreach ($projects_by_location as $location): ?>
                                    <tr>
                                        <td class="font-medium text-gray-900">
                                            <?php echo htmlspecialchars($location['sub_county']); ?>
                                        </td>
                                        <td class="text-gray-900">
                                            <?php echo number_format($location['project_count']); ?>
                                        </td>
                                        <td class="text-gray-900">
                                            <?php echo number_format($location['total_budget'] ?? 0); ?>
                                        </td>
                                        <td>
                                            <div class="flex items-center gap-2">
                                                <div class="progress-bar flex-1">
                                                    <div class="progress-fill" style="width: <?php echo $location['avg_progress']; ?>%"></div>
                                                </div>
                                                <span class="text-sm text-gray-900 min-w-0"><?php echo round($location['avg_progress'] ?? 0, 1); ?>%</span>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php else: ?>
                                <tr>
                                    <td colspan="4" class="text-center text-gray-500 py-4">No data available</td>
                                </tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Recent Milestones -->
            <div class="report-card">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-semibold text-gray-800">Recent Project Milestones</h3>
                </div>

                <div>
                    <?php if (!empty($recent_milestones)): ?>
                        <div class="space-y-2">
                            <?php foreach ($recent_milestones as $milestone): ?>
                                <div class="milestone-item">
                                    <div class="flex items-start gap-3">
                                        <div class="w-6 h-6 bg-green-500 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5">
                                            <i class="fas fa-check text-white text-xs"></i>
                                        </div>
                                        <div class="flex-1 min-w-0">
                                            <div class="milestone-header"><?php echo htmlspecialchars($milestone['project_name']); ?></div>
                                            <div class="milestone-project"><?php echo htmlspecialchars($milestone['step_name']); ?></div>
                                            <div class="milestone-date">
                                                <?php echo date('M d, Y', strtotime($milestone['completion_date'])); ?>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php else: ?>
                        <div class="text-center py-8">
                            <i class="fas fa-calendar-check text-3xl text-gray-400 mb-2"></i>
                            <p class="text-gray-500">No recent milestones</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
</div>

<?php
include 'includes/adminFooter.php';
?>
