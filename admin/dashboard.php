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

// Get comprehensive dashboard statistics with enhanced real data queries
try {
    // Basic project statistics with role-based filtering
    $role_filter = "";
    $role_params = [];

    if ($current_admin['role'] !== 'super_admin') {
        $role_filter = " WHERE created_by = ?";
        $role_params = [$current_admin['id']];
    }

    $stats = [];
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $role_filter);
    $stmt->execute($role_params);
    $stats['total_projects'] = (int)$stmt->fetchColumn();

    // Fix the parameter issue by using proper condition building
    $planning_filter = $role_filter ? $role_filter . " AND status = ?" : " WHERE status = ?";
    $planning_params = $role_filter ? array_merge($role_params, ['planning']) : ['planning'];
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $planning_filter);
    $stmt->execute($planning_params);
    $stats['planning_projects'] = (int)$stmt->fetchColumn();

    $ongoing_filter = $role_filter ? $role_filter . " AND status = ?" : " WHERE status = ?";
    $ongoing_params = $role_filter ? array_merge($role_params, ['ongoing']) : ['ongoing'];
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $ongoing_filter);
    $stmt->execute($ongoing_params);
    $stats['ongoing_projects'] = (int)$stmt->fetchColumn();

    $completed_filter = $role_filter ? $role_filter . " AND status = ?" : " WHERE status = ?";
    $completed_params = $role_filter ? array_merge($role_params, ['completed']) : ['completed'];
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $completed_filter);
    $stmt->execute($completed_params);
    $stats['completed_projects'] = (int)$stmt->fetchColumn();

    $suspended_filter = $role_filter ? $role_filter . " AND status = ?" : " WHERE status = ?";
    $suspended_params = $role_filter ? array_merge($role_params, ['suspended']) : ['suspended'];
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $suspended_filter);
    $stmt->execute($suspended_params);
    $stats['suspended_projects'] = (int)$stmt->fetchColumn();

    $cancelled_filter = $role_filter ? $role_filter . " AND status = ?" : " WHERE status = ?";
    $cancelled_params = $role_filter ? array_merge($role_params, ['cancelled']) : ['cancelled'];
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $cancelled_filter);
    $stmt->execute($cancelled_params);
    $stats['cancelled_projects'] = (int)$stmt->fetchColumn();

    // Enhanced financial analytics with real transaction data
    $financial_stats = [];

    // Get total budget from projects table
    $stmt = $pdo->prepare("
        SELECT 
            COALESCE(SUM(total_budget), 0) as base_budget,
            COUNT(*) as project_count
        FROM projects 
        " . $role_filter . "
        AND total_budget IS NOT NULL AND total_budget > 0
    ");
    $stmt->execute($role_params);
    $budget_data = $stmt->fetch();

    // Get budget increases from transactions
    $budget_increase_filter = $role_filter ? "JOIN projects p ON pt.project_id = p.id " . $role_filter . " AND" : "WHERE";
    $stmt = $pdo->prepare("
        SELECT 
            COALESCE(SUM(pt.amount), 0) as budget_increases
        FROM project_transactions pt
        " . ($role_filter ? "JOIN projects p ON pt.project_id = p.id " . $role_filter . " AND" : "WHERE") . " 
        pt.transaction_type = 'budget_increase' AND pt.transaction_status = 'active'
    ");
    $stmt->execute($role_params);
    $increase_data = $stmt->fetch();

    $financial_stats['base_budget'] = (float)($budget_data['base_budget'] ?? 0);
    $financial_stats['total_budget_increases'] = (float)($increase_data['budget_increases'] ?? 0);
    $financial_stats['total_budget'] = $financial_stats['base_budget'] + $financial_stats['total_budget_increases'];

    // Get actual expenditure and disbursements from transactions
    $transaction_filter = $role_filter ? "JOIN projects p ON pt.project_id = p.id " . $role_filter : "";
    $stmt = $pdo->prepare("
        SELECT 
            COALESCE(SUM(CASE WHEN pt.transaction_type = 'expenditure' AND pt.transaction_status = 'active' THEN pt.amount ELSE 0 END), 0) as total_expenditure,
            COALESCE(SUM(CASE WHEN pt.transaction_type = 'disbursement' AND pt.transaction_status = 'active' THEN pt.amount ELSE 0 END), 0) as total_disbursed
        FROM project_transactions pt
        " . $transaction_filter
    );
    $stmt->execute($role_params);
    $transaction_data = $stmt->fetch();

    $financial_stats['total_expenditure'] = (float)($transaction_data['total_expenditure'] ?? 0);
    $financial_stats['total_allocated'] = $financial_stats['total_budget']; // Use total budget as allocated
    $financial_stats['total_disbursed'] = (float)($transaction_data['total_disbursed'] ?? 0);
    $financial_stats['remaining_funds'] = $financial_stats['total_allocated'] - $financial_stats['total_expenditure'];
    $financial_stats['avg_budget_per_project'] = $stats['total_projects'] > 0 ? 
        round($financial_stats['total_budget'] / $stats['total_projects'], 2) : 0;

    // Enhanced progress analytics with real data
    $progress_stats = [];

    $stmt = $pdo->prepare("SELECT AVG(COALESCE(progress_percentage, 0)) FROM projects" . $role_filter);
    $stmt->execute($role_params);
    $progress_stats['avg_progress'] = round((float)($stmt->fetchColumn() ?: 0), 1);

    $over_50_filter = $role_filter ? $role_filter . " AND progress_percentage > 50" : " WHERE progress_percentage > 50";
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $over_50_filter);
    $stmt->execute($role_params);
    $progress_stats['projects_over_50'] = (int)$stmt->fetchColumn();

    $over_75_filter = $role_filter ? $role_filter . " AND progress_percentage > 75" : " WHERE progress_percentage > 75";
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $over_75_filter);
    $stmt->execute($role_params);
    $progress_stats['projects_over_75'] = (int)$stmt->fetchColumn();

    $stalled_filter = $role_filter ? $role_filter . " AND progress_percentage = 0 AND status = 'ongoing'" : " WHERE progress_percentage = 0 AND status = 'ongoing'";
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $stalled_filter);
    $stmt->execute($role_params);
    $progress_stats['stalled_projects'] = (int)$stmt->fetchColumn();

    $range_0_25_filter = $role_filter ? $role_filter . " AND progress_percentage BETWEEN 0 AND 25" : " WHERE progress_percentage BETWEEN 0 AND 25";
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $range_0_25_filter);
    $stmt->execute($role_params);
    $progress_stats['projects_0_25'] = (int)$stmt->fetchColumn();

    $range_26_50_filter = $role_filter ? $role_filter . " AND progress_percentage BETWEEN 26 AND 50" : " WHERE progress_percentage BETWEEN 26 AND 50";
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $range_26_50_filter);
    $stmt->execute($role_params);
    $progress_stats['projects_26_50'] = (int)$stmt->fetchColumn();

    $range_51_75_filter = $role_filter ? $role_filter . " AND progress_percentage BETWEEN 51 AND 75" : " WHERE progress_percentage BETWEEN 51 AND 75";
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $range_51_75_filter);
    $stmt->execute($role_params);
    $progress_stats['projects_51_75'] = (int)$stmt->fetchColumn();

    $range_76_100_filter = $role_filter ? $role_filter . " AND progress_percentage BETWEEN 76 AND 100" : " WHERE progress_percentage BETWEEN 76 AND 100";
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM projects" . $range_76_100_filter);
    $stmt->execute($role_params);
    $progress_stats['projects_76_100'] = (int)$stmt->fetchColumn();

    // Enhanced feedback statistics with project filtering
    $feedback_stats = [];

    if ($current_admin['role'] === 'super_admin') {
        $feedback_stats['total_feedback'] = $pdo->query("SELECT COUNT(*) FROM feedback")->fetchColumn();
        $feedback_stats['pending_feedback'] = $pdo->query("SELECT COUNT(*) FROM feedback WHERE status = 'pending'")->fetchColumn();
        $feedback_stats['reviewed_feedback'] = $pdo->query("SELECT COUNT(*) FROM feedback WHERE status = 'reviewed'")->fetchColumn();
        $feedback_stats['responded_feedback'] = $pdo->query("SELECT COUNT(*) FROM feedback WHERE status = 'responded'")->fetchColumn();
        $feedback_stats['grievances_count'] = $pdo->query("SELECT COUNT(*) FROM feedback WHERE status = 'grievance'")->fetchColumn();
        $feedback_stats['avg_rating'] = $pdo->query("SELECT AVG(rating) FROM feedback WHERE rating IS NOT NULL")->fetchColumn() ?: 0;
    } else {
        // Filter feedback for projects owned by current admin
        $stmt = $pdo->prepare("
            SELECT COUNT(*) FROM feedback f 
            JOIN projects p ON f.project_id = p.id 
            WHERE p.created_by = ?
        ");
        $stmt->execute([$current_admin['id']]);
        $feedback_stats['total_feedback'] = $stmt->fetchColumn();

        $stmt = $pdo->prepare("
            SELECT COUNT(*) FROM feedback f 
            JOIN projects p ON f.project_id = p.id 
            WHERE p.created_by = ? AND f.status = 'pending'
        ");
        $stmt->execute([$current_admin['id']]);
        $feedback_stats['pending_feedback'] = $stmt->fetchColumn();

        $stmt = $pdo->prepare("
            SELECT COUNT(*) FROM feedback f 
            JOIN projects p ON f.project_id = p.id 
            WHERE p.created_by = ? AND f.status = 'reviewed'
        ");
        $stmt->execute([$current_admin['id']]);
        $feedback_stats['reviewed_feedback'] = $stmt->fetchColumn();

        $stmt = $pdo->prepare("
            SELECT COUNT(*) FROM feedback f 
            JOIN projects p ON f.project_id = p.id 
            WHERE p.created_by = ? AND f.status = 'responded'
        ");
        $stmt->execute([$current_admin['id']]);
        $feedback_stats['responded_feedback'] = $stmt->fetchColumn();

        $stmt = $pdo->prepare("
            SELECT COUNT(*) FROM feedback f 
            JOIN projects p ON f.project_id = p.id 
            WHERE p.created_by = ? AND f.status = 'grievance'
        ");
        $stmt->execute([$current_admin['id']]);
        $feedback_stats['grievances_count'] = $stmt->fetchColumn();

        $stmt = $pdo->prepare("
            SELECT AVG(f.rating) FROM feedback f 
            JOIN projects p ON f.project_id = p.id 
            WHERE p.created_by = ? AND f.rating IS NOT NULL
        ");
        $stmt->execute([$current_admin['id']]);
        $feedback_stats['avg_rating'] = $stmt->fetchColumn() ?: 0;
    }

    // Department performance
    $department_performance = $pdo->query("
        SELECT d.name, 
               COUNT(p.id) as project_count,
               COALESCE(AVG(p.progress_percentage), 0) as avg_progress,
               COALESCE(SUM(p.total_budget), 0) as total_budget,
               COUNT(CASE WHEN p.status = 'completed' THEN 1 END) as completed_count
        FROM departments d 
        LEFT JOIN projects p ON d.id = p.department_id 
        GROUP BY d.id, d.name 
        HAVING project_count > 0
        ORDER BY project_count DESC
        LIMIT 10
    ")->fetchAll();

    // Monthly project creation trend - get actual data from your database
    $monthly_trends = $pdo->query("
        SELECT 
            DATE_FORMAT(created_at, '%Y-%m') as month,
            COUNT(*) as projects_created,
            COALESCE(SUM(total_budget), 0) as monthly_budget,
            COALESCE(AVG(total_budget), 0) as avg_monthly_budget
        FROM projects 
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
        GROUP BY DATE_FORMAT(created_at, '%Y-%m')
        ORDER BY month DESC
        LIMIT 12
    ")->fetchAll();

    // Location analytics
    $location_stats = $pdo->query("
        SELECT 
            sc.name as sub_county,
            COUNT(p.id) as project_count,
            AVG(p.progress_percentage) as avg_progress,
            SUM(p.total_budget) as total_budget
        FROM sub_counties sc
        LEFT JOIN projects p ON sc.id = p.sub_county_id
        GROUP BY sc.id, sc.name
        HAVING project_count > 0
        ORDER BY project_count DESC
        LIMIT 10
    ")->fetchAll();

    // Budget vs expenditure by department
    $budget_expenditure = $pdo->query("
        SELECT 
            d.name as department,
            SUM(p.total_budget) as allocated_budget,
            COALESCE(SUM(t.amount), 0) as total_expenditure
        FROM departments d
        LEFT JOIN projects p ON d.id = p.department_id
        LEFT JOIN project_transactions t ON p.id = t.project_id AND t.transaction_type = 'expenditure' AND t.transaction_status = 'active'
        GROUP BY d.id, d.name
        HAVING allocated_budget > 0
        ORDER BY allocated_budget DESC
    ")->fetchAll();

    // Recent activities with real-time data
    $recent_activities = get_recent_activities(10);

    // Enhanced projects by status for pie chart with role filtering
    $stmt = $pdo->prepare("
        SELECT status, COUNT(*) as count 
        FROM projects 
        " . $role_filter . "
        GROUP BY status
    ");
    $stmt->execute($role_params);
    $projects_by_status = $stmt->fetchAll();

    // Weekly progress changes with role filtering
    $stmt = $pdo->prepare("
        SELECT 
            WEEK(updated_at) as week_num,
            AVG(progress_percentage) as avg_progress
        FROM projects 
        WHERE updated_at >= DATE_SUB(NOW(), INTERVAL 8 WEEK)
        " . ($role_filter ? " AND " . str_replace("WHERE ", "", $role_filter) : "") . "
        GROUP BY WEEK(updated_at)
        ORDER BY week_num
    ");
    $stmt->execute($role_params);
    $weekly_progress = $stmt->fetchAll();

    // Real-time transaction statistics
    $transaction_stats = [];
    $stmt = $pdo->prepare("
        SELECT 
            transaction_type,
            COUNT(*) as count,
            SUM(amount) as total_amount,
            AVG(amount) as avg_amount
        FROM project_transactions pt
        " . ($role_filter ? "JOIN projects p ON pt.project_id = p.id " . $role_filter : "") . "
        WHERE pt.transaction_status = 'active'
        GROUP BY transaction_type
    ");
    $stmt->execute($role_params);
    $transaction_stats = $stmt->fetchAll();

    // Project creation trends by month with actual data
    $stmt = $pdo->prepare("
        SELECT 
            DATE_FORMAT(created_at, '%Y-%m') as month,
            COUNT(*) as projects_created,
            SUM(total_budget) as monthly_budget,
            AVG(total_budget) as avg_monthly_budget
        FROM projects 
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
        " . ($role_filter ? " AND " . str_replace("WHERE ", "", $role_filter) : "") . "
        GROUP BY DATE_FORMAT(created_at, '%Y-%m')
        ORDER BY month
    ");
    $stmt->execute($role_params);
    $monthly_trends = $stmt->fetchAll();

    // Department efficiency metrics
    $dept_efficiency = [];
    if ($current_admin['role'] === 'super_admin') {
        $dept_efficiency = $pdo->query("
            SELECT 
                d.name as department_name,
                COUNT(p.id) as total_projects,
                AVG(p.progress_percentage) as avg_progress,
                SUM(p.total_budget) as total_budget,
                COUNT(CASE WHEN p.status = 'completed' THEN 1 END) as completed_projects,
                COUNT(CASE WHEN p.status = 'ongoing' THEN 1 END) as ongoing_projects,
                DATEDIFF(NOW(), MIN(p.created_at)) as days_since_first_project
            FROM departments d
            LEFT JOIN projects p ON d.id = p.department_id
            GROUP BY d.id, d.name
            HAVING total_projects > 0
            ORDER BY avg_progress DESC, completed_projects DESC
        ")->fetchAll();
    }

// Production ready - debug information removed

} catch (Exception $e) {
    error_log("Dashboard Error: " . $e->getMessage());
    // Initialize empty arrays for error cases
    $stats = $financial_stats = $progress_stats = $feedback_stats = [];
    $department_performance = $monthly_trends = $location_stats = [];
    $budget_expenditure = $recent_activities = $projects_by_status = $weekly_progress = [];

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

    // Initialize default dashboard data
    $projects_by_status = [];
    $budget_expenditure = [];
    $monthly_trends = [];
    $progress_stats = [
        'projects_0_25' => 0,
        'projects_26_50' => 0,
        'projects_51_75' => 0,
        'projects_76_100' => 0
    ];
    $feedback_stats = [
        'pending_feedback' => 0,
        'reviewed_feedback' => 0,
        'responded_feedback' => 0
    ];
}
?>

<!-- Breadcrumb -->
<div class="mb-6">
    <nav class="flex" aria-label="Breadcrumb">
        <ol class="flex items-center space-x-2 text-sm">
            <li class="text-gray-600 font-medium">
                <i class="fas fa-home mr-1"></i> Dashboard
            </li>
            <li class="text-gray-400">/</li>
            <li class="text-gray-600 font-medium">Analytics</li>
        </ol>
    </nav>
</div>

<!-- Page Header -->
<div class="mb-8">
    <div class="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
        <div class="flex flex-col md:flex-row items-start justify-between">
            <div class="mb-4 md:mb-0">
                <h1 class="text-2xl font-bold text-gray-900 mb-2">PMC Advanced Analytics</h1>
                <p class="text-gray-600">Comprehensive project management insights and performance metrics</p>
                <p class="text-sm text-gray-500 mt-2">
                    Last updated: <?php echo date('F d, Y \a\t H:i A'); ?>
                </p>
            </div>
            <div class="text-center md:text-right">
                <div class="text-3xl font-bold text-blue-600 mb-1"><?php echo number_format($stats['total_projects'] ?? 0); ?></div>
                <div class="text-sm text-gray-600 mb-3">Total Projects</div>
                <div class="text-xs text-gray-500">Across all departments</div>
            </div>
        </div>
    </div>
</div>

<!-- Key Performance Indicators -->
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
    <!-- Financial Overview -->
    <div class="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
        <div class="flex items-center">
            <div class="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mr-4">
                <i class="fas fa-coins text-blue-600 text-xl"></i>
            </div>
            <div>
                <p class="text-sm text-gray-600">Total Budget</p>
                <p class="text-2xl font-bold text-gray-900">KES <?php echo number_format($financial_stats['total_budget']); ?></p>
                <p class="text-xs text-gray-500 mt-1">Avg: KES <?php echo number_format($financial_stats['avg_budget_per_project']); ?> per project</p>
            </div>
        </div>
    </div>

    <!-- Progress Performance -->
    <div class="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
        <div class="flex items-center">
            <div class="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center mr-4">
                <i class="fas fa-chart-line text-green-600 text-xl"></i>
            </div>
            <div>
                <p class="text-sm text-gray-600">Average Progress</p>
                <p class="text-2xl font-bold text-gray-900"><?php echo round($progress_stats['avg_progress'], 1); ?>%</p>
                <p class="text-xs text-gray-500 mt-1"><?php echo $progress_stats['projects_over_75']; ?> projects >75% complete</p>
            </div>
        </div>
    </div>

    <!-- Community Engagement -->
    <div class="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
        <div class="flex items-center">
            <div class="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center mr-4">
                <i class="fas fa-users text-purple-600 text-xl"></i>
            </div>
            <div>
                <p class="text-sm text-gray-600">Community Feedback</p>
                <p class="text-2xl font-bold text-gray-900"><?php echo $feedback_stats['total_feedback']; ?></p>
                <p class="text-xs text-gray-500 mt-1">Rating: <?php echo round($feedback_stats['avg_rating'], 1); ?>/5.0 ⭐</p>
            </div>
        </div>
    </div>

    <!-- Expenditure Efficiency -->
    <div class="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
        <div class="flex items-center">
            <div class="w-12 h-12 bg-orange-100 rounded-lg flex items-center justify-center mr-4">
                <i class="fas fa-chart-pie text-orange-600 text-xl"></i>
            </div>
            <div>
                <p class="text-sm text-gray-600">Expenditure</p>
                <p class="text-2xl font-bold text-gray-900">KES <?php echo number_format($financial_stats['total_expenditure']); ?></p>
                <p class="text-xs text-gray-500 mt-1">
                    <?php 
                    $expenditure_rate = $financial_stats['total_budget'] > 0 ? 
                        round(($financial_stats['total_expenditure'] / $financial_stats['total_budget']) * 100, 1) : 0;
                    echo $expenditure_rate; 
                    ?>% of budget utilized
                </p>
            </div>
        </div>
    </div>
</div>

<!-- Project Status Distribution and Department Performance -->
<div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
    <div class="bg-white shadow-sm rounded-lg border border-gray-200">
        <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
            <h3 class="text-lg font-semibold text-gray-900 flex items-center">
                <i class="fas fa-chart-pie mr-2 text-blue-600"></i>
                Project Status Distribution
            </h3>
        </div>
        <div class="p-6">
            <div class="flex justify-center">
                <canvas id="statusDistributionChart" width="300" height="300"></canvas>
            </div>
        </div>
    </div>

    <!-- Department Performance Leaderboard -->
    <div class="bg-white shadow-sm rounded-lg border border-gray-200 lg:col-span-2">
        <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
            <h3 class="text-lg font-semibold text-gray-900 flex items-center">
                <i class="fas fa-trophy mr-2 text-yellow-600"></i>
                Department Performance Leaderboard
            </h3>
        </div>
        <div class="p-6">
            <div class="space-y-3 max-h-80 overflow-y-auto">
                <?php foreach ($department_performance as $index => $dept): ?>
                    <div class="flex items-center justify-between p-4 bg-gray-50 rounded-lg border border-gray-200">
                        <div class="flex items-center space-x-4">
                            <div class="w-10 h-10 bg-blue-600 rounded-full flex items-center justify-center text-white font-bold">
                                <?php echo $index + 1; ?>
                            </div>
                            <div>
                                <h4 class="font-semibold text-gray-900"><?php echo htmlspecialchars($dept['name']); ?></h4>
                                <p class="text-sm text-gray-600"><?php echo $dept['project_count']; ?> projects • <?php echo round($dept['avg_progress'], 1); ?>% avg progress</p>
                            </div>
                        </div>
                        <div class="text-right">
                            <p class="font-bold text-green-600">KES <?php echo number_format($dept['total_budget']); ?></p>
                            <p class="text-sm text-gray-500"><?php echo $dept['completed_count']; ?> completed</p>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
</div>

<!-- Financial Analytics Charts -->
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
    <!-- Budget vs Expenditure Analysis -->
    <div class="bg-white shadow-sm rounded-lg border border-gray-200">
        <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
            <h3 class="text-lg font-semibold text-gray-900 flex items-center">
                <i class="fas fa-balance-scale mr-2 text-green-600"></i>
                Budget vs Expenditure by Department
            </h3>
        </div>
        <div class="p-6">
            <div class="chart-container">
                <canvas id="budgetExpenditureChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Monthly Project Trends -->
    <div class="bg-white shadow-sm rounded-lg border border-gray-200">
        <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
            <h3 class="text-lg font-semibold text-gray-900 flex items-center">
                <i class="fas fa-trending-up mr-2 text-purple-600"></i>
                Monthly Project Creation Trends
            </h3>
        </div>
        <div class="p-6">
            <div class="chart-container">
                <canvas id="monthlyTrendsChart"></canvas>
            </div>
        </div>
    </div>
</div>

<!-- Location Analytics and Progress Tracking -->
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
    <!-- Geographic Distribution -->
    <div class="bg-white shadow-sm rounded-lg border border-gray-200">
        <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
            <h3 class="text-lg font-semibold text-gray-900 flex items-center">
                <i class="fas fa-map-marked-alt mr-2 text-red-600"></i>
                Top Performing Sub-Counties
            </h3>
        </div>
        <div class="p-6">
            <div class="space-y-3 max-h-80 overflow-y-auto">
                <?php foreach ($location_stats as $location): ?>
                    <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg border border-gray-200">
                        <div>
                            <h4 class="font-semibold text-gray-900"><?php echo htmlspecialchars($location['sub_county']); ?></h4>
                            <p class="text-sm text-gray-600"><?php echo $location['project_count']; ?> projects</p>
                        </div>
                        <div class="text-right">
                            <div class="flex items-center space-x-2">
                                <div class="progress-ring" style="--progress: <?php echo round($location['avg_progress'] * 3.6); ?>deg; width: 40px; height: 40px;">
                                    <span class="text-xs font-bold relative z-10"><?php echo round($location['avg_progress']); ?>%</span>
                                </div>
                            </div>
                            <p class="text-sm text-gray-500 mt-1">KES <?php echo number_format($location['total_budget'] / 1000000, 1); ?>M</p>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <!-- Progress Analytics -->
    <div class="bg-white shadow-sm rounded-lg border border-gray-200">
        <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
            <h3 class="text-lg font-semibold text-gray-900 flex items-center">
                <i class="fas fa-tasks mr-2 text-indigo-600"></i>
                Progress Analytics
            </h3>
        </div>
        <div class="p-6">
            <div class="grid grid-cols-2 gap-4 mb-6">
                <div class="text-center p-4 bg-gray-50 rounded-lg border border-gray-200">
                    <div class="text-2xl font-bold text-green-600"><?php echo $progress_stats['projects_over_50']; ?></div>
                    <div class="text-sm text-gray-600">Projects >50%</div>
                </div>
                <div class="text-center p-4 bg-gray-50 rounded-lg border border-gray-200">
                    <div class="text-2xl font-bold text-blue-600"><?php echo $progress_stats['projects_over_75']; ?></div>
                    <div class="text-sm text-gray-600">Projects >75%</div>
                </div>
                <div class="text-center p-4 bg-gray-50 rounded-lg border border-gray-200">
                    <div class="text-2xl font-bold text-orange-600"><?php echo $progress_stats['stalled_projects']; ?></div>
                    <div class="text-sm text-gray-600">Stalled Projects</div>
                </div>
                <div class="text-center p-4 bg-gray-50 rounded-lg border border-gray-200">
                    <div class="text-2xl font-bold text-purple-600"><?php echo round($progress_stats['avg_progress'], 1); ?>%</div>
                    <div class="text-sm text-gray-600">Average Progress</div>
                </div>
            </div>
            <div class="chart-container" style="height: 200px;">
                <canvas id="progressDistributionChart"></canvas>
            </div>
        </div>
    </div>
</div>

<!-- Feedback Analytics and Recent Activities -->
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
    <!-- Community Feedback Analysis -->
    <div class="bg-white shadow-sm rounded-lg border border-gray-200">
        <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
            <h3 class="text-lg font-semibold text-gray-900 flex items-center">
                <i class="fas fa-comments mr-2 text-blue-600"></i>
                Community Feedback Analytics
            </h3>
        </div>
        <div class="p-6">
            <div class="grid grid-cols-2 gap-4 mb-4">
                <div class="text-center p-4 bg-gray-50 rounded-lg border border-gray-200">
                    <div class="text-xl font-bold text-blue-600"><?php echo $feedback_stats['total_feedback']; ?></div>
                    <div class="text-sm text-gray-600">Total Feedback</div>
                </div>
                <div class="text-center p-4 bg-gray-50 rounded-lg border border-gray-200">
                    <div class="text-xl font-bold text-orange-600"><?php echo $feedback_stats['pending_feedback']; ?></div>
                    <div class="text-sm text-gray-600">Pending Review</div>
                </div>
            </div>
            <div class="chart-container" style="height: 250px;">
                <canvas id="feedbackStatusChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Recent Activities Feed -->
    <div class="bg-white shadow-sm rounded-lg border border-gray-200">
        <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
            <h3 class="text-lg font-semibold text-gray-900 flex items-center">
                <i class="fas fa-clock mr-2 text-green-600"></i>
                Recent System Activities
            </h3>
        </div>
        <div class="p-6">
            <div class="space-y-3 max-h-80 overflow-y-auto">
                <?php foreach (array_slice($recent_activities, 0, 8) as $activity): ?>
                    <div class="flex items-start space-x-3 p-3 bg-gray-50 rounded-lg border border-gray-200">
                        <div class="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center flex-shrink-0">
                            <span class="text-white font-bold text-xs">
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
            </div>
        </div>
    </div>
</div>

<!-- Chart.js -->
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
// Pass PHP data to JavaScript
window.dashboardData = {
    projects_by_status: <?php echo json_encode($projects_by_status ?? []); ?>,
    budget_expenditure: <?php echo json_encode($budget_expenditure ?? []); ?>,
    monthly_trends: <?php echo json_encode($monthly_trends ?? []); ?>,
    progress_stats: {
        projects_0_25: <?php echo $progress_stats['projects_0_25'] ?? 0; ?>,
        projects_26_50: <?php echo $progress_stats['projects_26_50'] ?? 0; ?>,
        projects_51_75: <?php echo $progress_stats['projects_51_75'] ?? 0; ?>,
        projects_76_100: <?php echo $progress_stats['projects_76_100'] ?? 0; ?>
    },
    feedback_stats: {
        pending_feedback: <?php echo $feedback_stats['pending_feedback'] ?? 0; ?>,
        reviewed_feedback: <?php echo $feedback_stats['reviewed_feedback'] ?? 0; ?>,
        responded_feedback: <?php echo $feedback_stats['responded_feedback'] ?? 0; ?>
    }
};
</script>

<?php include 'includes/adminFooter.php'; ?>