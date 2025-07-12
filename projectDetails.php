<?php
// Start session only if not already active
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Include configuration and functions
require_once 'config.php';
require_once 'includes/functions.php';

$project_id = 0;
$url_slug = '';

if (isset($_GET['id'])) {
    $project_id = (int)$_GET['id'];
    $url_slug = isset($_GET['slug']) ? $_GET['slug'] : '';
} else {
    // Parse clean URL format 
    $uri = $_SERVER['REQUEST_URI'];
    $segments = explode('/', trim($uri, '/'));
    if (count($segments) >= 2 && $segments[0] === 'projectDetails' && is_numeric($segments[1])) {
        $project_id = (int)$segments[1];
        $url_slug = isset($segments[2]) ? $segments[2] : '';
    }
}

// Get project details - force fresh data
$stmt = $pdo->prepare("SELECT p.*, d.name as department_name, sc.name as sub_county_name, 
                              w.name as ward_name, c.name as county_name
                       FROM projects p 
                       LEFT JOIN departments d ON p.department_id = d.id
                       LEFT JOIN sub_counties sc ON p.sub_county_id = sc.id  
                       LEFT JOIN wards w ON p.ward_id = w.id
                       LEFT JOIN counties c ON p.county_id = c.id
                       WHERE p.id = ?");
$stmt->execute([$project_id]);
$project = $stmt->fetch();

if (!$project) {
    header("HTTP/1.0 404 Not Found");
    include '404.php';
    exit;
}

// Generate correct slug and redirect if necessary for SEO
$correct_slug = create_url_slug($project['project_name']);
$correct_url = generate_project_url($project_id, $project['project_name']);

// Check if we need to redirect to the canonical URL
if ($correct_slug && $url_slug !== $correct_slug) {
    header("HTTP/1.1 301 Moved Permanently");
    header("Location: $correct_url");
    exit;
}

// Check if project is private and user is not logged in
if ($project['visibility'] === 'private' && !isset($_SESSION['admin_id'])) {
    header("HTTP/1.0 404 Not Found");
    include '404.php';
    exit;
}

$is_admin = isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'];

// Check if project is accessible to public
if ($project['visibility'] === 'private' && !$is_admin) {
    header("HTTP/1.0 404 Not Found");
    include '404.php';
    exit;
}

// Get project steps
$stmt = $pdo->prepare("SELECT * FROM project_steps WHERE project_id = ? ORDER BY step_number");
$stmt->execute([$project_id]);
$project_steps = $stmt->fetchAll();

// Get project comments
$project_comments = get_project_comments($project_id);

// Get approved comments count for display
$approved_comments_count = get_approved_comments_count($project_id);

// Get related ongoing projects
$stmt = $pdo->prepare("SELECT p.*, d.name as department_name, sc.name as sub_county_name, 
                              w.name as ward_name
                       FROM projects p 
                       LEFT JOIN departments d ON p.department_id = d.id
                       LEFT JOIN sub_counties sc ON p.sub_county_id = sc.id  
                       LEFT JOIN wards w ON p.ward_id = w.id
                       WHERE p.status = 'ongoing' AND p.id != ?
                       ORDER BY p.created_at DESC 
                       LIMIT 3");
$stmt->execute([$project_id]);
$related_projects = $stmt->fetchAll();

// Calculate actual quick stats
$total_steps_count = count($project_steps);
$completed_steps_count = 0;
foreach ($project_steps as $step) {
    if ($step['status'] === 'completed') {
        $completed_steps_count++;
    }
}

// Get enhanced financial data for this project
$stmt = $pdo->prepare("
    SELECT 
        SUM(CASE WHEN transaction_type = 'budget_increase' AND transaction_status = 'active' THEN amount ELSE 0 END) as budget_increases,
        SUM(CASE WHEN transaction_type = 'disbursement' AND transaction_status = 'active' THEN amount ELSE 0 END) as total_disbursed,
        SUM(CASE WHEN transaction_type = 'expenditure' AND transaction_status = 'active' THEN amount ELSE 0 END) as total_spent,
        COUNT(CASE WHEN transaction_status = 'active' THEN 1 END) as transaction_count
    FROM project_transactions 
    WHERE project_id = ?
");
$stmt->execute([$project_id]);
$financial_data = $stmt->fetch();

$initial_budget = $project['total_budget'] ?? 0;
$budget_increases = $financial_data['budget_increases'] ?? 0;
$total_allocated = $initial_budget + $budget_increases;
$total_disbursed = $financial_data['total_disbursed'] ?? 0;
$total_spent = $financial_data['total_spent'] ?? 0;
$remaining_balance = $total_disbursed - $total_spent;

// Calculate approved budget (initial + increases)
$project_total_budget = $total_allocated;

// Get recent transactions with supporting documents (only active ones for public view)
$stmt = $pdo->prepare("
    SELECT pt.*, ptd.id as document_id, ptd.file_path, ptd.original_filename 
    FROM project_transactions pt
    LEFT JOIN project_transaction_documents ptd ON pt.id = ptd.transaction_id
    WHERE pt.project_id = ? AND pt.transaction_status = 'active'
    ORDER BY pt.transaction_date DESC, pt.created_at DESC 
    LIMIT 10
");
$stmt->execute([$project_id]);
$recent_transactions = $stmt->fetchAll();

// Get project documents
$stmt = $pdo->prepare("
    SELECT * FROM project_documents 
    WHERE project_id = ? AND document_type IN ('tender', 'contract', 'budget', 'report')
    ORDER BY created_at DESC
");
$stmt->execute([$project_id]);
$project_documents = $stmt->fetchAll();

// Helper function to format time ago
function time_ago($datetime) {
    $time = time() - strtotime($datetime);

    if ($time < 60) return 'just now';
    if ($time < 3600) return floor($time / 60) . ' minutes ago';
    if ($time < 86400) return floor($time / 3600) . ' hours ago';
    if ($time < 2592000) return floor($time / 86400) . ' days ago';
    if ($time < 31536000) return floor($time / 2592000) . ' months ago';
    return floor($time / 31536000) . ' years ago';
}

$page_title = htmlspecialchars($project['project_name']);
$page_description = 'View details, progress and location information for ' . htmlspecialchars($project['project_name']);
$show_nav = true;

include 'includes/header.php';
?>

<!-- Leaflet CSS -->
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin=""/>

<!-- Animated Background -->
<div class="animated-bg"></div>

<!-- Compact Header Section -->
<div class="bg-gradient-to-r from-slate-600 to-slate-700 text-white py-4">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <!-- Breadcrumb Navigation -->
        <nav class="flex mb-3" aria-label="Breadcrumb">
            <ol class="flex items-center space-x-2 text-sm">
                <li>
                    <a href="<?php echo BASE_URL; ?>index.php" class="text-white/70 hover:text-white transition-colors flex items-center">
                        <i class="fas fa-home mr-1"></i>
                        Home
                    </a>
                </li>
                <li class="flex items-center">
                    <i class="fas fa-chevron-right text-white/50 mx-2"></i>
                    <span class="text-white/90">Project Details</span>
                </li>
            </ol>
        </nav>

        <!-- Project Title and Status -->
        <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div>
                <h1 class="text-2xl sm:text-3xl font-bold text-white leading-tight">
                    <?php echo htmlspecialchars($project['project_name']); ?>
                </h1>
                <div class="flex flex-wrap items-center gap-3 mt-2">
                    <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-semibold text-white
                        <?php echo $project['status'] === 'ongoing' ? 'bg-blue-600' : 
                                  ($project['status'] === 'completed' ? 'bg-green-600' : 
                                  ($project['status'] === 'planning' ? 'bg-yellow-600' : 
                                  ($project['status'] === 'suspended' ? 'bg-orange-600' : 'bg-red-600'))); ?>">
                        <?php echo ucfirst($project['status']); ?>
                    </span>
                    <span class="text-white/80 text-sm">
                        <i class="fas fa-calendar mr-1"></i>
                        <?php echo $project['project_year']; ?>
                    </span>
                </div>
            </div>

            <!-- Quick Actions -->
            <div class="flex gap-2">
                <?php
                // Get subscription count for this project
                require_once 'includes/projectSubscriptions.php';
                $subscription_manager = new ProjectSubscriptionManager($pdo);
                $subscriber_count = $subscription_manager->getSubscriberCount($project_id);
                ?>
                <button onclick="showSubscriptionModal()" class="bg-green-600 hover:bg-green-700 text-white border border-green-600 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-300">
                    <i class="fas fa-bell mr-2"></i>
                    Subscribe to Updates
                </button>
                <button onclick="scrollToComments()" class="bg-white/20 hover:bg-white/30 text-white border border-white/30 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-300">
                    <i class="fas fa-comments mr-2"></i>
                    Join Discussion
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Main Content Container with Jumia-style layout -->
<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 relative z-10">
    <div class="flex flex-col lg:flex-row gap-6">
        
        <!-- Left Sidebar -->
        <div class="lg:w-80 flex-shrink-0 space-y-6">
            
            <!-- Project Overview Cards -->
            <div class="glass-card p-4">
                <h3 class="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                    <i class="fas fa-chart-pie mr-2 text-blue-500"></i>
                    Project Overview
                </h3>
                
                <!-- Progress Card -->
                <div class="mb-4 text-center cursor-pointer" onclick="showProgressBreakdown()">
                    <?php 
                    $progress = $project['progress_percentage'];
                    ?>
                    <div class="progress-circle-container mx-auto mb-3 relative hover:scale-105 transition-transform" style="width: 120px; height: 120px;">
                        <div class="progress-ring" 
                             id="progressRing<?php echo $project['id']; ?>"
                             style="position: relative; width: 120px; height: 120px; border-radius: 50%; 
                                    background: conic-gradient(from 180deg, rgba(148,163,184,0.3) 0deg, rgba(148,163,184,0.3) 360deg);
                                    display: flex; justify-content: center; align-items: center;">
                            <div class="inner-circle" 
                                 style="position: absolute; width: 90px; height: 90px; 
                                        background: linear-gradient(135deg, rgba(255,255,255,0.9), rgba(248,250,252,0.8));
                                        border-radius: 50%; display: flex; align-items: center; justify-content: center;
                                        box-shadow: inset 0 2px 8px rgba(0,0,0,0.1);">
                                <div class="percentage" style="font-size: 18px; font-weight: bold; color: #1f2937;">
                                    <?php echo $progress; ?>%
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="text-gray-900 text-sm font-medium">Overall Progress</div>
                    <div class="text-xs text-gray-500 mt-1">Click for breakdown</div>
                </div>

                <!-- Quick Stats Grid -->
                <div class="grid grid-cols-2 gap-3">
                    <div class="bg-gray-50 rounded-lg p-3 text-center cursor-pointer hover:bg-gray-100 transition-colors" onclick="showStepsBreakdown()">
                        <div class="text-lg font-bold text-gray-900"><?php echo $completed_steps_count; ?>/<?php echo $total_steps_count; ?></div>
                        <div class="text-xs text-gray-600">Steps Complete</div>
                    </div>
                    
                    <div class="bg-gray-50 rounded-lg p-3 text-center cursor-pointer hover:bg-gray-100 transition-colors" onclick="showDepartmentInfo()">
                        <div class="text-xs text-gray-600 mb-1">
                            <i class="fas fa-building text-blue-500"></i>
                        </div>
                        <div class="text-xs text-gray-900 font-medium truncate">
                            <?php echo htmlspecialchars($project['department_name']); ?>
                        </div>
                    </div>
                    
                    <div class="bg-gray-50 rounded-lg p-3 text-center cursor-pointer hover:bg-gray-100 transition-colors" onclick="showYearInfo()">
                        <div class="text-xs text-gray-600 mb-1">
                            <i class="fas fa-calendar text-gray-500"></i>
                        </div>
                        <div class="text-xs text-gray-900 font-medium">
                            <?php echo $project['project_year']; ?>
                        </div>
                    </div>
                    
                    <div class="bg-gray-50 rounded-lg p-3 text-center cursor-pointer hover:bg-gray-100 transition-colors" onclick="showBudgetBreakdown()">
                        <div class="text-xs text-gray-600 mb-1">
                            <i class="fas fa-money-bill text-green-500"></i>
                        </div>
                        <div class="text-xs text-gray-900 font-medium">
                            KES <?php echo number_format($project_total_budget / 1000000, 1); ?>M
                        </div>
                    </div>
                </div>
            </div>

            <!-- Project Location Card -->
            <?php if (!empty($project['location_coordinates'])): ?>
            <div class="glass-card p-4">
                <h3 class="text-lg font-semibold text-gray-900 mb-3 flex items-center">
                    <i class="fas fa-map-marker-alt mr-2 text-red-500"></i>
                    Project Location
                </h3>
                <div id="projectMap" class="w-full h-40 rounded-lg border border-gray-200 mb-3"></div>
                <div class="text-center">
                    <p class="text-sm text-gray-600 mb-1">
                        <i class="fas fa-map-marker-alt mr-1 text-red-500"></i>
                        <?php echo htmlspecialchars($project['ward_name'] . ', ' . $project['sub_county_name']); ?>
                    </p>
                    <p class="text-xs text-gray-500">
                        <?php echo htmlspecialchars($project['county_name']); ?>
                    </p>
                </div>
            </div>
            <?php endif; ?>

            <!-- Related Projects Card -->
            <?php if (!empty($related_projects)): ?>
            <div class="glass-card p-4">
                <h3 class="text-lg font-semibold text-gray-900 mb-3 flex items-center">
                    <i class="fas fa-project-diagram mr-2 text-purple-500"></i>
                    Related Projects
                </h3>
                <div class="space-y-3">
                    <?php foreach ($related_projects as $related_project): ?>
                    <?php 
                    $related_progress = $related_project['progress_percentage'] ?? 0;
                    ?>
                    <div class="bg-white rounded-lg p-3 border border-gray-200 cursor-pointer hover:shadow-sm transition-shadow"
                         onclick="window.location.href='<?php echo generate_project_url($related_project['id'], $related_project['project_name']); ?>'">
                        <h4 class="font-medium text-gray-900 text-sm line-clamp-2 mb-2">
                            <?php echo htmlspecialchars($related_project['project_name']); ?>
                        </h4>
                        <p class="text-xs text-gray-600 mb-2 flex items-center">
                            <i class="fas fa-map-marker-alt mr-1 text-red-400"></i>
                            <?php echo htmlspecialchars($related_project['ward_name']); ?>
                        </p>
                        <div class="flex items-center justify-between">
                            <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium <?php echo get_status_badge_class($related_project['status']); ?>">
                                <?php echo ucfirst($related_project['status']); ?>
                            </span>
                            <span class="text-xs text-gray-500">
                                <?php echo $related_progress; ?>%
                            </span>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
                <div class="mt-3 text-center">
                    <a href="../index" class="text-sm text-blue-600 hover:text-blue-800 font-medium">
                        View All Projects →
                    </a>
                </div>
            </div>
            <?php endif; ?>
        </div>

        <!-- Main Content Area -->
        <div class="flex-1 space-y-6">
            
            <!-- Project Details Section -->
            <div class="glass-card p-6">
                <h2 class="text-2xl font-bold text-gray-900 mb-6 flex items-center">
                    <i class="fas fa-info-circle mr-3 text-blue-500"></i>
                    Project Details
                </h2>

                <!-- Project Description -->
                <div class="mb-6">
                    <div class="bg-gradient-to-r from-blue-50 to-indigo-50 p-4 rounded-xl border-l-4 border-blue-500">
                        <h3 class="text-lg font-semibold text-gray-900 mb-3 flex items-center">
                            <i class="fas fa-file-text mr-2 text-blue-500"></i>
                            Description
                        </h3>
                        <p class="text-gray-700 leading-relaxed">
                            <?php echo htmlspecialchars($project['description']); ?>
                        </p>
                    </div>
                </div>

                <!-- Project Information Grid -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <!-- Location -->
                    <div class="bg-gradient-to-br from-red-50 to-pink-50 p-4 rounded-xl border border-red-100">
                        <div class="flex items-center gap-3 mb-3">
                            <div class="w-10 h-10 bg-gradient-to-br from-red-500 to-red-600 rounded-full flex items-center justify-center">
                                <i class="fas fa-map-marker-alt text-white text-sm"></i>
                            </div>
                            <div>
                                <h4 class="font-semibold text-gray-900">Location</h4>
                                <p class="text-xs text-gray-600">Project Area</p>
                            </div>
                        </div>
                        <p class="text-gray-800 font-medium">
                            <?php echo htmlspecialchars($project['ward_name']); ?>
                        </p>
                        <p class="text-sm text-gray-600">
                            <?php echo htmlspecialchars($project['sub_county_name'] . ', ' . $project['county_name']); ?>
                        </p>
                    </div>

                    <!-- Department -->
                    <div class="bg-gradient-to-br from-purple-50 to-indigo-50 p-4 rounded-xl border border-purple-100">
                        <div class="flex items-center gap-3 mb-3">
                            <div class="w-10 h-10 bg-gradient-to-br from-purple-500 to-purple-600 rounded-full flex items-center justify-center">
                                <i class="fas fa-building text-white text-sm"></i>
                            </div>
                            <div>
                                <h4 class="font-semibold text-gray-900">Department</h4>
                                <p class="text-xs text-gray-600">Implementing Authority</p>
                            </div>
                        </div>
                        <p class="text-gray-800 font-medium">
                            <?php echo htmlspecialchars($project['department_name']); ?>
                        </p>
                    </div>

                    <?php if ($project['contractor_name']): ?>
                    <!-- Contractor -->
                    <div class="bg-gradient-to-br from-yellow-50 to-orange-50 p-4 rounded-xl border border-yellow-100">
                        <div class="flex items-center gap-3 mb-3">
                            <div class="w-10 h-10 bg-gradient-to-br from-yellow-500 to-orange-500 rounded-full flex items-center justify-center">
                                <i class="fas fa-hard-hat text-white text-sm"></i>
                            </div>
                            <div>
                                <h4 class="font-semibold text-gray-900">Contractor</h4>
                                <p class="text-xs text-gray-600">Implementation Partner</p>
                            </div>
                        </div>
                        <p class="text-gray-800 font-medium">
                            <?php echo htmlspecialchars($project['contractor_name']); ?>
                        </p>
                    </div>
                    <?php endif; ?>

                    <?php if ($project['start_date']): ?>
                    <!-- Start Date -->
                    <div class="bg-gradient-to-br from-green-50 to-emerald-50 p-4 rounded-xl border border-green-100">
                        <div class="flex items-center gap-3 mb-3">
                            <div class="w-10 h-10 bg-gradient-to-br from-green-500 to-emerald-500 rounded-full flex items-center justify-center">
                                <i class="fas fa-play-circle text-white text-sm"></i>
                            </div>
                            <div>
                                <h4 class="font-semibold text-gray-900">Start Date</h4>
                                <p class="text-xs text-gray-600">Project Commencement</p>
                            </div>
                        </div>
                        <p class="text-gray-800 font-medium">
                            <?php echo format_date($project['start_date']); ?>
                        </p>
                    </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Financial Transparency Section -->
            <?php if ($project_total_budget > 0 || $total_allocated > 0 || !empty($recent_transactions)): ?>
            <div class="glass-card p-6">
                <div class="flex items-center justify-between mb-6 cursor-pointer" onclick="toggleFinancialSection()">
                    <h2 class="text-2xl font-bold text-gray-900 flex items-center">
                        <i class="fas fa-money-bill-wave mr-3 text-green-500"></i>
                        Financial Transparency
                    </h2>
                    <i id="financialToggle" class="fas fa-chevron-down text-gray-500 transition-transform"></i>
                </div>

                <div id="financialContent" class="space-y-6">
                    <!-- Financial Summary Cards -->
                    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                        <!-- Approved Budget Card -->
                        <div class="bg-gradient-to-br from-blue-50 to-blue-100 p-4 rounded-xl border border-blue-100">
                            <div class="flex items-center gap-3 mb-2">
                                <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-blue-600 rounded-full flex items-center justify-center">
                                    <i class="fas fa-coins text-white text-sm"></i>
                                </div>
                                <div>
                                    <h4 class="font-semibold text-gray-900 text-sm">Approved Budget</h4>
                                    <p class="text-xs text-gray-600">Total Project Budget</p>
                                </div>
                            </div>
                            <p class="text-lg font-bold text-blue-600">KES <?php echo number_format($project_total_budget); ?></p>
                        </div>

                        <!-- Disbursed Amount Card -->
                        <div class="bg-gradient-to-br from-purple-50 to-indigo-50 p-4 rounded-xl border border-purple-100">
                            <div class="flex items-center gap-3 mb-2">
                                <div class="w-10 h-10 bg-gradient-to-br from-purple-500 to-indigo-500 rounded-full flex items-center justify-center">
                                    <i class="fas fa-money-check-alt text-white text-sm"></i>
                                </div>
                                <div>
                                    <h4 class="font-semibold text-gray-900 text-sm">Disbursed</h4>
                                    <p class="text-xs text-gray-600">Sent to Project Account</p>
                                </div>
                            </div>
                            <p class="text-lg font-bold text-purple-600">KES <?php echo number_format($total_disbursed); ?></p>
                        </div>

                        <!-- Expenditure Card -->
                        <div class="bg-gradient-to-br from-red-50 to-pink-50 p-4 rounded-xl border border-red-100">
                            <div class="flex items-center gap-3 mb-2">
                                <div class="w-10 h-10 bg-gradient-to-br from-red-500 to-pink-500 rounded-full flex items-center justify-center">
                                    <i class="fas fa-credit-card text-white text-sm"></i>
                                </div>
                                <div>
                                    <h4 class="font-semibold text-gray-900 text-sm">Spent Amount</h4>
                                    <p class="text-xs text-gray-600">Actually Spent</p>
                                </div>
                            </div>
                            <p class="text-lg font-bold text-red-600">KES <?php echo number_format($total_spent); ?></p>
                        </div>

                        <!-- Remaining Balance Card -->
                        <div class="bg-gradient-to-br from-green-50 to-emerald-50 p-4 rounded-xl border border-green-100">
                            <div class="flex items-center gap-3 mb-2">
                                <div class="w-10 h-10 bg-gradient-to-br from-green-500 to-emerald-500 rounded-full flex items-center justify-center">
                                    <i class="fas fa-wallet text-white text-sm"></i>
                                </div>
                                <div>
                                    <h4 class="font-semibold text-gray-900 text-sm">Remaining Balance</h4>
                                    <p class="text-xs text-gray-600">Disbursed minus Spent</p>
                                </div>
                            </div>
                            <p class="text-lg font-bold <?php echo $remaining_balance >= 0 ? 'text-green-600' : 'text-red-600'; ?>">
                                KES <?php echo number_format($remaining_balance); ?>
                            </p>
                        </div>
                    </div>

                    <!-- Collapsible Transaction Activities -->
                    <?php if (!empty($recent_transactions)): ?>
                    <div class="border border-gray-200 rounded-lg">
                        <div class="bg-gray-50 px-4 py-3 cursor-pointer flex items-center justify-between" onclick="toggleTransactions()">
                            <h3 class="text-lg font-semibold text-gray-900 flex items-center">
                                <i class="fas fa-receipt mr-2 text-blue-500"></i>
                                Recent Financial Activities
                            </h3>
                            <i id="transactionToggle" class="fas fa-chevron-down text-gray-500 transition-transform"></i>
                        </div>
                        <div id="transactionContent" class="hidden p-4 space-y-3">
                            <?php foreach ($recent_transactions as $transaction): ?>
                                <?php
                                // Determine if transaction adds or subtracts from project account
                                $is_positive = in_array($transaction['transaction_type'], ['budget_increase', 'disbursement']);
                                $is_negative = in_array($transaction['transaction_type'], ['expenditure']);

                                // Set colors and icons based on transaction type
                                if ($is_positive) {
                                    $bg_color = 'bg-green-500';
                                    $text_color = 'text-green-600';
                                    $icon = 'fa-plus';
                                    $sign = '+';
                                } else {
                                    $bg_color = 'bg-red-500';
                                    $text_color = 'text-red-600';
                                    $icon = 'fa-minus';
                                    $sign = '-';
                                }

                                // Transaction type labels for public display
                                $type_labels = [
                                    'budget_increase' => 'Additional Budget',
                                    'disbursement' => 'Funds Disbursed', 
                                    'expenditure' => 'Project Expenditure',
                                    'adjustment' => 'Budget Adjustment'
                                ];
                                ?>
                                <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                    <div class="flex items-center gap-3">
                                        <div class="w-8 h-8 <?php echo $bg_color; ?> rounded-full flex items-center justify-center">
                                            <i class="fas <?php echo $icon; ?> text-white text-xs"></i>
                                        </div>
                                        <div>
                                            <h4 class="font-medium text-sm text-gray-900"><?php echo htmlspecialchars($transaction['description']); ?></h4>
                                            <p class="text-xs text-gray-600">
                                                <?php echo $type_labels[$transaction['transaction_type']] ?? ucfirst($transaction['transaction_type']); ?> • 
                                                <?php echo date('M j, Y', strtotime($transaction['transaction_date'])); ?>
                                            </p>
                                            <?php if ($transaction['document_id']): ?>
                                            <div class="mt-1">
                                                <button onclick="openDocumentModal('<?php echo htmlspecialchars($transaction['original_filename']); ?>', '<?php echo BASE_URL . 'uploads/' . $transaction['file_path']; ?>')" 
                                                        class="text-xs text-blue-600 hover:text-blue-800 flex items-center">
                                                    <i class="fas fa-file-invoice mr-1"></i>
                                                    View Supporting Document
                                                </button>
                                            </div>
                                        <?php endif; ?>
                                        </div>
                                    </div>
                                    <div class="text-right">
                                        <p class="font-semibold text-sm <?php echo $text_color; ?>">
                                            <?php echo $sign; ?>KES <?php echo number_format($transaction['amount']); ?>
                                        </p>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
            <?php endif; ?>

            <!-- Project Timeline -->
            <div class="glass-card p-6">
                <h2 class="text-2xl font-bold text-gray-900 mb-6 flex items-center">
                    <i class="fas fa-tasks mr-3 text-blue-500"></i>
                    Project Timeline
                </h2>

                <?php if (!empty($project_steps)): ?>
                <div class="space-y-6">
                    <?php foreach ($project_steps as $index => $step): ?>
                    <div class="relative flex items-start space-x-4 fade-in-up" style="--stagger-delay: <?php echo $index * 0.1; ?>s">
                        <!-- Timeline line -->
                        <?php if ($index < count($project_steps) - 1): ?>
                        <div class="absolute left-6 top-12 w-0.5 h-16 bg-gradient-to-b from-gray-300 to-gray-200"></div>
                        <?php endif; ?>

                        <!-- Step indicator -->
                        <div class="flex-shrink-0 mt-1">
                            <?php if ($step['status'] === 'completed'): ?>
                                <div class="w-12 h-12 bg-gradient-to-br from-green-400 to-green-600 rounded-full flex items-center justify-center shadow-lg">
                                    <i class="fas fa-check text-white text-lg"></i>
                                </div>
                            <?php elseif ($step['status'] === 'in_progress'): ?>
                                <div class="w-12 h-12 bg-gradient-to-br from-blue-400 to-blue-600 rounded-full flex items-center justify-center shadow-lg animate-pulse">
                                    <div class="w-4 h-4 bg-white rounded-full"></div>
                                </div>
                            <?php else: ?>
                                <div class="w-12 h-12 bg-gradient-to-br from-gray-300 to-gray-400 rounded-full flex items-center justify-center shadow-lg">
                                    <span class="text-white font-bold text-sm"><?php echo $step['step_number']; ?></span>
                                </div>
                            <?php endif; ?>
                        </div>

                        <!-- Step content -->
                        <div class="flex-1 min-w-0 bg-gray-50 p-6 rounded-2xl">
                            <div class="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
                                <div class="flex-1">
                                    <h4 class="text-lg font-semibold text-gray-900 mb-2">
                                        <?php echo htmlspecialchars($step['step_name']); ?>
                                    </h4>
                                    <?php if ($step['description']): ?>
                                        <p class="text-gray-600 mb-3 leading-relaxed">
                                            <?php echo htmlspecialchars($step['description']); ?>
                                        </p>
                                    <?php endif; ?>
                                    <?php if ($step['expected_end_date']): ?>
                                        <div class="flex items-center text-sm text-gray-500">
                                            <i class="fas fa-calendar mr-2"></i>
                                            Expected completion: <?php echo format_date($step['expected_end_date']); ?>
                                        </div>
                                    <?php endif; ?>
                                </div>
                                <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium
                                    <?php echo $step['status'] === 'completed' ? 'bg-green-100 text-green-800' : 
                                              ($step['status'] === 'in_progress' ? 'bg-blue-100 text-blue-800' : 
                                               'bg-gray-100 text-gray-800'); ?>">
                                    <?php echo ucfirst(str_replace('_', ' ', $step['status'])); ?>
                                </span>
                            </div>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
                <?php else: ?>
                <div class="text-center py-16">
                    <div class="w-24 h-24 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-6">
                        <i class="fas fa-tasks text-3xl text-gray-400"></i>
                    </div>
                    <h3 class="text-xl font-medium text-gray-900 mb-2">No Timeline Available</h3>
                    <p class="text-sm">Project timeline steps have not been defined yet.</p>
                </div>
                <?php endif; ?>
            </div>

            <!-- Community Comments Section -->
            <div id="comments-section" class="glass-card p-6">
                <h3 class="text-xl font-semibold text-gray-900 mb-6 flex items-center">
                    <i class="fas fa-comments mr-3 text-blue-500"></i>
                    Community Discussion
                    <span class="ml-auto text-sm font-normal text-gray-600">
                        <?php echo $approved_comments_count; ?> <?php echo $approved_comments_count === 1 ? 'comment' : 'comments'; ?>
                    </span>
                </h3>

                <!-- Display Comments -->
                <div id="comments-container" class="space-y-4 mb-6">
                    <?php if (!empty($project_comments)): ?>
                        <?php foreach ($project_comments as $comment): ?>
                            <?php
                            // Determine display name and admin status
                            $is_admin_comment = isset($comment['is_admin_comment']) ? 
                                $comment['is_admin_comment'] : 
                                (strpos($comment['id'], 'admin_') === 0 || $comment['subject'] === 'Admin Response' || empty($comment['citizen_name']));

                            $display_name = $is_admin_comment ? 
                                ($comment['admin_name'] ?? 'Admin') : 
                                $comment['citizen_name'];

                            // Check if this is user's own pending comment
                            $is_user_pending = isset($comment['is_user_pending']) ? $comment['is_user_pending'] : false;
                            ?>
                            <div class="comment-thread" data-comment-id="<?php echo $comment['id']; ?>">
                                <!-- Main Comment -->
                                <div class="comment-main">
                                    <div class="flex items-start space-x-3">
                                        <div class="flex-shrink-0">
                                            <?php if ($is_admin_comment): ?>
                                                <div class="w-10 h-10 bg-red-600 rounded-full flex items-center justify-center text-white text-sm font-semibold">
                                                    <i class="fas fa-shield-alt"></i>
                                                </div>
                                            <?php else: ?>
                                                <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-blue-600 rounded-full flex items-center justify-center text-white text-sm font-semibold">
                                                    <?php echo strtoupper(substr($display_name, 0, 1)); ?>
                                                </div>
                                            <?php endif; ?>
                                        </div>
                                        <div class="flex-1 min-w-0">
                                            <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
                                                <div class="flex items-center space-x-2 mb-2">
                                                    <span class="font-semibold text-gray-900">
                                                        <?php echo htmlspecialchars($display_name); ?>
                                                    </span>
                                                    <?php if ($is_admin_comment): ?>
                                                        <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                                            <i class="fas fa-shield-alt mr-1"></i>Admin
                                                        </span>
                                                    <?php endif; ?>
                                                    <?php if ($is_user_pending): ?>
                                                        <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                                                            <i class="fas fa-clock mr-1"></i>Pending Approval
                                                        </span>
                                                    <?php endif; ?>
                                                    <span class="text-sm text-gray-500">
                                                        <?php echo time_ago($comment['created_at']); ?>
                                                    </span>
                                                </div>
                                                <div class="text-gray-700 leading-relaxed break-words">
                                                    <?php echo nl2br(htmlspecialchars($comment['message'])); ?>
                                                </div>
                                                <div class="flex items-center space-x-4 mt-3 pt-2 border-t border-gray-100">
                                                    <button onclick="replyToComment(<?php echo $comment['id']; ?>, '<?php echo addslashes($display_name); ?>')" 
                                                            class="text-sm text-gray-500 hover:text-blue-600 font-medium transition-colors">
                                                        <i class="fas fa-reply mr-1"></i>Reply
                                                    </button>
                                                    <?php if (!empty($comment['replies']) || $comment['total_replies'] > 0): ?>
                                                        <span class="text-sm text-gray-500">
                                                            <i class="fas fa-comment-dots mr-1"></i>
                                                            <?php echo $comment['total_replies']; ?> <?php echo $comment['total_replies'] === 1 ? 'reply' : 'replies'; ?>
                                                        </span>
                                                    <?php endif; ?>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <!-- Replies Section -->
                                <?php if (!empty($comment['replies'])): ?>
                                    <div class="replies-container ml-12 mt-3 space-y-3">
                                        <?php foreach ($comment['replies'] as $reply): ?>
                                            <?php
                                            $reply_is_admin = isset($reply['is_admin_comment']) ? 
                                                $reply['is_admin_comment'] : 
                                                (strpos($reply['id'], 'admin_') === 0 || $reply['subject'] === 'Admin Response' || empty($reply['citizen_name']));

                                            $reply_display_name = $reply_is_admin ? 
                                                ($reply['admin_name'] ?? 'Admin') : 
                                                $reply['citizen_name'];

                                            $reply_is_user_pending = isset($reply['is_user_pending']) ? $reply['is_user_pending'] : false;
                                            ?>
                                            <div class="reply-item flex items-start space-x-3">
                                                <div class="flex-shrink-0">
                                                    <div class="w-8 h-8 <?php echo $reply_is_admin ? 'bg-red-500' : 'bg-gray-500'; ?> rounded-full flex items-center justify-center text-white text-xs font-semibold">
                                                        <?php if ($reply_is_admin): ?>
                                                            <i class="fas fa-shield-alt"></i>
                                                        <?php else: ?>
                                                            <?php echo strtoupper(substr($reply_display_name, 0, 1)); ?>
                                                        <?php endif; ?>
                                                    </div>
                                                </div>
                                                <div class="flex-1 min-w-0">
                                                    <div class="bg-gray-50 rounded-lg p-3">
                                                        <div class="flex items-center space-x-2 mb-1">
                                                            <span class="text-sm font-semibold text-gray-900">
                                                                <?php echo htmlspecialchars($reply_display_name); ?>
                                                            </span>
                                                            <?php if ($reply_is_admin): ?>
                                                                <span class="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                                                    <i class="fas fa-shield-alt mr-1"></i>Admin
                                                                </span>
                                                            <?php else: ?>
                                                                <span class="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                                                    <i class="fas fa-reply mr-1"></i>Reply
                                                                </span>
                                                            <?php endif; ?>
                                                            <?php if ($reply_is_user_pending): ?>
                                                                <span class="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                                                                    <i class="fas fa-clock mr-1"></i>Pending
                                                                </span>
                                                            <?php endif; ?>
                                                            <span class="text-xs text-gray-500">
                                                                <?php echo time_ago($reply['created_at']); ?>
                                                            </span>
                                                        </div>
                                                        <div class="text-sm text-gray-700 leading-relaxed break-words">
                                                            <?php echo nl2br(htmlspecialchars($reply['message'])); ?>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                        <?php endforeach; ?>

                                        <!-- Load More Replies Button -->
                                        <?php if ($comment['total_replies'] > 3): ?>
                                            <div class="load-more-replies-container">
                                                <button onclick="loadMoreReplies(<?php echo $comment['id']; ?>, 3)" 
                                                        class="load-more-replies text-sm text-blue-600 hover:text-blue-800 font-medium flex items-center transition-colors">
                                                    <i class="fas fa-chevron-down mr-2"></i>
                                                    Load <?php echo min($comment['total_replies'] - 3, 5); ?> more replies
                                                </button>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                <?php endif; ?>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="text-center py-12 text-gray-500">
                            <i class="fas fa-comments text-4xl mb-4"></i>
                            <p class="text-lg font-medium mb-2">No comments yet</p>
                            <p class="text-sm">Be the first to share your thoughts about this project!</p>
                        </div>
                    <?php endif; ?>
                </div>

                <!-- Add New Comment Form -->
                <div class="border-t border-gray-200 pt-6">
                    <h4 class="text-lg font-semibold text-gray-900 mb-4">Join the Discussion</h4>
                    <form id="commentForm" class="bg-gray-50 p-4 rounded-lg">
                        <input type="hidden" name="project_id" value="<?php echo $project['id']; ?>">
                        <input type="hidden" name="parent_comment_id" value="0">

                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                            <div>
                                <label class="form-label">Your Name *</label>
                                <input type="text" name="citizen_name" required 
                                       class="form-input w-full">
                            </div>
                            <div>
                                <label class="form-label">Email (Optional)</label>
                                <input type="email" name="citizen_email" 
                                       class="form-input w-full">
                            </div>
                        </div>

                        <div class="mb-4">
                            <label class="form-label">Your Comment *</label>
                            <textarea name="message" rows="4" required 
                                      placeholder="Share your thoughts about this project..."
                                      class="form-textarea w-full"></textarea>
                        </div>

                        <button type="submit" class="btn-submit">
                            <i class="fas fa-paper-plane mr-2"></i>
                            Submit Comment
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Document Modal -->
<div id="documentModal" class="fixed inset-0 z-50 hidden overflow-y-auto">
    <div class="flex items-center justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
        <div class="fixed inset-0 transition-opacity" aria-hidden="true">
            <div class="absolute inset-0 bg-gray-500 opacity-75"></div>
        </div>
        <span class="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>
        <div class="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-4xl sm:w-full">
            <div class="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                <div class="sm:flex sm:items-start">
                    <div class="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left w-full">
                        <h3 id="documentModalTitle" class="text-lg leading-6 font-medium text-gray-900 mb-4"></h3>
                        <div class="mt-2">
                            <iframe id="documentViewer" class="w-full h-96 border border-gray-300 rounded-md"></iframe>
                        </div>
                    </div>
                </div>
            </div>
            <div class="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                <button type="button" onclick="closeDocumentModal()" class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm">
                    Close
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Stats Breakdown Modal -->
<div id="statsModal" class="fixed inset-0 z-50 hidden overflow-y-auto">
    <div class="flex items-center justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
        <div class="fixed inset-0 transition-opacity" aria-hidden="true" onclick="closeStatsModal()">
            <div class="absolute inset-0 bg-gray-500 opacity-75"></div>
        </div>
        <span class="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>
        <div class="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
            <div class="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                <div class="flex items-center justify-between mb-4">
                    <h3 id="statsModalTitle" class="text-lg leading-6 font-medium text-gray-900"></h3>
                    <button onclick="closeStatsModal()" class="text-gray-400 hover:text-gray-600 transition-colors">
                        <i class="fas fa-times text-xl"></i>
                    </button>
                </div>
                <div id="statsModalContent" class="mt-2">
                    <!-- Content will be populated by JavaScript -->
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Subscription Modal -->
<div id="subscriptionModal" class="fixed inset-0 z-50 hidden overflow-y-auto">
    <div class="flex items-center justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
        <div class="fixed inset-0 transition-opacity" aria-hidden="true" onclick="closeSubscriptionModal()">
            <div class="absolute inset-0 bg-gray-500 opacity-75"></div>
        </div>
        <span class="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>
        <div class="inline-block align-bottom bg-white rounded-xl text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-md sm:w-full">
            <div class="bg-gradient-to-r from-green-600 to-blue-600 px-6 py-4 text-white">
                <div class="flex items-center justify-between">
                    <div class="flex items-center">
                        <div class="w-10 h-10 bg-white/20 rounded-full flex items-center justify-center mr-3">
                            <i class="fas fa-bell text-white"></i>
                        </div>
                        <div>
                            <h3 class="text-lg font-bold">Subscribe to Updates</h3>
                            <p class="text-sm text-green-100">Stay informed about this project</p>
                        </div>
                    </div>
                    <button onclick="closeSubscriptionModal()" class="text-white hover:text-gray-200 transition-colors">
                        <i class="fas fa-times text-xl"></i>
                    </button>
                </div>
            </div>

            <div class="px-6 py-6">
                <div class="mb-4">
                    <p class="text-sm text-gray-600 mb-2">
                        Get notified about important updates for:
                    </p>
                    <p class="font-semibold text-gray-900 bg-gray-50 p-3 rounded-lg">
                        <?php echo htmlspecialchars($project['project_name']); ?>
                    </p>
                </div>

                <form id="subscriptionForm" class="space-y-4">
                    <div>
                        <label for="subscriptionEmail" class="block text-sm font-medium text-gray-700 mb-2">
                            <i class="fas fa-envelope mr-1 text-blue-500"></i>
                            Email Address *
                        </label>
                        <input type="email" 
                               id="subscriptionEmail" 
                               name="email" 
                               required 
                               class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all"
                               placeholder="Enter your email address">
                        <p id="emailError" class="text-red-500 text-xs mt-1 hidden"></p>
                    </div>

                    <div class="text-xs text-gray-500 text-center">
                        By subscribing, you agree to receive email notifications about this project only.
                        We respect your privacy and follow data protection regulations.
                    </div>
                </form>
            </div>

            <div class="bg-gray-50 px-6 py-4 flex flex-col sm:flex-row-reverse gap-3">
                <button type="button" 
                        id="subscribeBtn"
                        onclick="submitSubscription()" 
                        class="flex-1 sm:flex-none inline-flex items-center justify-center px-6 py-3 bg-gradient-to-r from-green-600 to-blue-600 text-white rounded-lg hover:from-green-700 hover:to-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-all font-medium">
                    <i class="fas fa-bell mr-2"></i>
                    Subscribe Now
                </button>
                <button type="button" 
                        onclick="closeSubscriptionModal()" 
                        class="flex-1 sm:flex-none px-6 py-3 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-all font-medium">
                    Cancel
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Scroll to Top Button -->
<button id="scrollToTop" class="fixed bottom-6 right-6 bg-blue-600 text-white p-3 rounded-full shadow-lg hover:bg-blue-700 transition-all z-50 opacity-0 invisible transform translate-y-4">
    <i class="fas fa-arrow-up"></i>
</button>

<!-- Scroll Progress Indicator -->
<div class="scroll-indicator"></div>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" crossorigin=""></script>
<script src="<?php echo BASE_URL; ?>assets/js/main.js"></script>

<script>
// Define BASE_URL and project data from PHP
window.BASE_URL = "<?php echo BASE_URL; ?>";
window.projectData = {
    <?php if (!empty($project['location_coordinates'])): ?>
    coordinates: "<?php echo $project['location_coordinates']; ?>",
    name: "<?php echo addslashes($project['project_name']); ?>",
    ward: "<?php echo addslashes($project['ward_name']); ?>",
    sub_county: "<?php echo addslashes($project['sub_county_name']); ?>",
    status: "<?php echo ucfirst($project['status']); ?>",
    department: "<?php echo addslashes($project['department_name']); ?>",
    year: "<?php echo $project['project_year']; ?>",
    progress: <?php echo $progress; ?>
    <?php else: ?>
    coordinates: null
    <?php endif; ?>
};

// Global scroll to comments function
window.scrollToComments = function() {
    const commentsSection = document.getElementById('comments-section');
    if (commentsSection) {
        const headerHeight = 100;
        const elementPosition = commentsSection.offsetTop;
        const offsetPosition = elementPosition - headerHeight;

        window.scrollTo({
            top: offsetPosition,
            behavior: 'smooth'
        });

        // Add highlight effect
        commentsSection.style.transform = 'scale(1.02)';
        commentsSection.style.transition = 'transform 0.3s ease';
        setTimeout(() => {
            commentsSection.style.transform = 'scale(1)';
        }, 300);
    }
};

// Collapsible sections functionality
window.toggleFinancialSection = function() {
    const content = document.getElementById('financialContent');
    const toggle = document.getElementById('financialToggle');
    
    if (content.style.display === 'none') {
        content.style.display = 'block';
        toggle.classList.remove('fa-chevron-right');
        toggle.classList.add('fa-chevron-down');
    } else {
        content.style.display = 'none';
        toggle.classList.remove('fa-chevron-down');
        toggle.classList.add('fa-chevron-right');
    }
};

window.toggleTransactions = function() {
    const content = document.getElementById('transactionContent');
    const toggle = document.getElementById('transactionToggle');
    
    if (content.classList.contains('hidden')) {
        content.classList.remove('hidden');
        toggle.style.transform = 'rotate(180deg)';
    } else {
        content.classList.add('hidden');
        toggle.style.transform = 'rotate(0deg)';
    }
};

// Stats breakdown modal functions
window.showProgressBreakdown = function() {
    const modal = document.getElementById('statsModal');
    const title = document.getElementById('statsModalTitle');
    const content = document.getElementById('statsModalContent');
    
    title.textContent = 'Progress Breakdown';
    content.innerHTML = `
        <div class="space-y-4">
            <div class="bg-blue-50 p-4 rounded-lg">
                <h4 class="font-semibold text-blue-900 mb-2">Overall Progress: <?php echo $progress; ?>%</h4>
                <p class="text-blue-700 text-sm">This represents the completion status based on project milestones and deliverables.</p>
            </div>
            <div class="grid grid-cols-2 gap-4">
                <div class="text-center p-3 bg-green-50 rounded-lg">
                    <div class="text-2xl font-bold text-green-600"><?php echo $completed_steps_count; ?></div>
                    <div class="text-sm text-green-700">Completed Steps</div>
                </div>
                <div class="text-center p-3 bg-gray-50 rounded-lg">
                    <div class="text-2xl font-bold text-gray-600"><?php echo $total_steps_count - $completed_steps_count; ?></div>
                    <div class="text-sm text-gray-700">Remaining Steps</div>
                </div>
            </div>
        </div>
    `;
    modal.classList.remove('hidden');
};

window.showStepsBreakdown = function() {
    const modal = document.getElementById('statsModal');
    const title = document.getElementById('statsModalTitle');
    const content = document.getElementById('statsModalContent');
    
    title.textContent = 'Project Steps';
    content.innerHTML = `
        <div class="space-y-3">
            <div class="bg-gray-50 p-4 rounded-lg">
                <h4 class="font-semibold text-gray-900 mb-2">Step Completion Status</h4>
                <div class="space-y-2">
                    <div class="flex justify-between">
                        <span class="text-green-600">✓ Completed</span>
                        <span class="font-medium"><?php echo $completed_steps_count; ?></span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-600">○ Remaining</span>
                        <span class="font-medium"><?php echo $total_steps_count - $completed_steps_count; ?></span>
                    </div>
                    <div class="flex justify-between border-t pt-2">
                        <span class="font-semibold">Total Steps</span>
                        <span class="font-bold"><?php echo $total_steps_count; ?></span>
                    </div>
                </div>
            </div>
        </div>
    `;
    modal.classList.remove('hidden');
};

window.showDepartmentInfo = function() {
    const modal = document.getElementById('statsModal');
    const title = document.getElementById('statsModalTitle');
    const content = document.getElementById('statsModalContent');
    
    title.textContent = 'Department Information';
    content.innerHTML = `
        <div class="space-y-4">
            <div class="bg-blue-50 p-4 rounded-lg">
                <h4 class="font-semibold text-blue-900 mb-2"><?php echo htmlspecialchars($project['department_name']); ?></h4>
                <p class="text-blue-700 text-sm">This is the implementing department responsible for overseeing this project.</p>
            </div>
            <div class="text-sm text-gray-600">
                <p><strong>Project Year:</strong> <?php echo $project['project_year']; ?></p>
                <p><strong>Status:</strong> <?php echo ucfirst($project['status']); ?></p>
            </div>
        </div>
    `;
    modal.classList.remove('hidden');
};

window.showYearInfo = function() {
    const modal = document.getElementById('statsModal');
    const title = document.getElementById('statsModalTitle');
    const content = document.getElementById('statsModalContent');
    
    title.textContent = 'Project Year';
    content.innerHTML = `
        <div class="space-y-4">
            <div class="bg-gray-50 p-4 rounded-lg">
                <h4 class="font-semibold text-gray-900 mb-2">Project Year: <?php echo $project['project_year']; ?></h4>
                <p class="text-gray-700 text-sm">This project was initiated in the <?php echo $project['project_year']; ?> financial year.</p>
            </div>
        </div>
    `;
    modal.classList.remove('hidden');
};

window.showBudgetBreakdown = function() {
    const modal = document.getElementById('statsModal');
    const title = document.getElementById('statsModalTitle');
    const content = document.getElementById('statsModalContent');
    
    title.textContent = 'Budget Information';
    content.innerHTML = `
        <div class="space-y-4">
            <div class="bg-green-50 p-4 rounded-lg">
                <h4 class="font-semibold text-green-900 mb-2">Total Budget: KES <?php echo number_format($project_total_budget); ?></h4>
                <p class="text-green-700 text-sm">This is the total approved budget for the project.</p>
            </div>
            <div class="grid grid-cols-1 gap-3">
                <div class="flex justify-between p-3 bg-blue-50 rounded">
                    <span class="text-blue-700">Disbursed</span>
                    <span class="font-semibold text-blue-900">KES <?php echo number_format($total_disbursed); ?></span>
                </div>
                <div class="flex justify-between p-3 bg-red-50 rounded">
                    <span class="text-red-700">Spent</span>
                    <span class="font-semibold text-red-900">KES <?php echo number_format($total_spent); ?></span>
                </div>
                <div class="flex justify-between p-3 bg-gray-50 rounded">
                    <span class="text-gray-700">Balance</span>
                    <span class="font-semibold <?php echo $remaining_balance >= 0 ? 'text-green-900' : 'text-red-900'; ?>">KES <?php echo number_format($remaining_balance); ?></span>
                </div>
            </div>
        </div>
    `;
    modal.classList.remove('hidden');
};

window.closeStatsModal = function() {
    const modal = document.getElementById('statsModal');
    modal.classList.add('hidden');
};

// Subscription Modal Functions
window.showSubscriptionModal = function() {
    document.getElementById('subscriptionModal').classList.remove('hidden');
    document.body.style.overflow = 'hidden';
    // Clear any previous error messages
    document.getElementById('emailError').classList.add('hidden');
    document.getElementById('subscriptionEmail').value = '';
};

window.closeSubscriptionModal = function() {
    document.getElementById('subscriptionModal').classList.add('hidden');
    document.body.style.overflow = 'auto';
    // Reset form
    document.getElementById('subscriptionForm').reset();
    document.getElementById('emailError').classList.add('hidden');
};

window.submitSubscription = async function() {
    const email = document.getElementById('subscriptionEmail').value.trim();
    const emailError = document.getElementById('emailError');
    const subscribeBtn = document.getElementById('subscribeBtn');
    
    // Reset error state
    emailError.classList.add('hidden');
    
    // Validate email
    if (!email) {
        emailError.textContent = 'Email address is required';
        emailError.classList.remove('hidden');
        return;
    }
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        emailError.textContent = 'Please enter a valid email address';
        emailError.classList.remove('hidden');
        return;
    }
    
    // Disable button and show loading
    subscribeBtn.disabled = true;
    subscribeBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Subscribing...';
    
    try {
        const response = await fetch(BASE_URL + 'api/subscribe.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                project_id: <?php echo $project_id; ?>,
                email: email
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            // Show success message
            alert('✅ ' + result.message);
            closeSubscriptionModal();
        } else {
            // Show error message
            emailError.textContent = result.message;
            emailError.classList.remove('hidden');
        }
    } catch (error) {
        console.error('Subscription error:', error);
        emailError.textContent = 'An error occurred. Please try again later.';
        emailError.classList.remove('hidden');
    } finally {
        // Re-enable button
        subscribeBtn.disabled = false;
        subscribeBtn.innerHTML = '<i class="fas fa-bell mr-2"></i>Subscribe Now';
    }
};

// Close modal with Escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeSubscriptionModal();
        closeStatsModal();
    }
});
</script>


<!-- Feedback Modal -->
<div id="feedbackModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 hidden">
    <div class="bg-white rounded-lg p-6 w-full max-w-md mx-4">
        <div class="flex justify-between items-center mb-4">
            <h3 id="feedbackModalTitle" class="text-lg font-semibold text-gray-900">Leave Feedback</h3>
            <button type="button" onclick="closeFeedbackModal()" class="text-gray-400 hover:text-gray-600">
                <i class="fas fa-times"></i>
            </button>
        </div>
        
        <form id="feedbackForm" class="space-y-4">
            <input type="hidden" id="projectId" name="project_id" value="<?php echo $project['id']; ?>">
            <input type="hidden" id="parentCommentId" name="parent_comment_id" value="">
            
            <div>
                <label for="citizenName" class="block text-sm font-medium text-gray-700 mb-1">Name *</label>
                <input type="text" id="citizenName" name="citizen_name" required 
                       class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>
            
            <div>
                <label for="citizenEmail" class="block text-sm font-medium text-gray-700 mb-1">Email (optional)</label>
                <input type="email" id="citizenEmail" name="citizen_email"
                       class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>
            
            <div>
                <label for="feedbackMessage" class="block text-sm font-medium text-gray-700 mb-1">Message *</label>
                <textarea id="feedbackMessage" name="message" required rows="4"
                          class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                          placeholder="Share your thoughts about this project..."></textarea>
            </div>
            
            <div class="flex justify-end space-x-3">
                <button type="button" onclick="closeFeedbackModal()" 
                        class="px-4 py-2 text-gray-600 hover:text-gray-800">
                    Cancel
                </button>
                <button type="submit" id="submitFeedbackBtn"
                        class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500">
                    Submit Feedback
                </button>
            </div>
        </form>
    </div>
</div>

<?php include 'includes/footer.php'; ?>
