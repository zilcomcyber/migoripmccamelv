<?php
// Start session only if not already active
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Include configuration and functions
require_once 'config.php';
require_once 'includes/functions.php';

$project_id = 0;
if (isset($_GET['id'])) {
    $project_id = (int)$_GET['id'];
} else {
    // Parse clean URL format 
    $uri = $_SERVER['REQUEST_URI'];
    $segments = explode('/', trim($uri, '/'));
    if (count($segments) >= 2 && $segments[0] === 'project_details' && is_numeric($segments[1])) {
        $project_id = (int)$segments[1];
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

// Add Leaflet CSS and JS
echo '<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin=""/>';

include 'includes/header.php';
?>

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
                <button onclick="scrollToComments()" class="bg-white/20 hover:bg-white/30 text-white border border-white/30 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-300">
                    <i class="fas fa-comments mr-2"></i>
                    Join Discussion
                </button>
                <span class="text-white/80 text-sm bg-white/20 px-3 py-2 rounded-full">
                    <i class="fas fa-comment-dots mr-1"></i>
                    <?php echo $approved_comments_count; ?> comments
                </span>
            </div>
        </div>
    </div>
</div>

<!-- Main Content -->
<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 relative z-10">

    <!-- Project Overview Cards Row -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <!-- Progress Card - Takes full width on mobile -->
        <div class="col-span-1 md:col-span-2 lg:col-span-1 glass-card p-4 text-center">
            <?php 
            $progress = $project['progress_percentage'];
            ?>
            <div class="progress-circle-container mx-auto mb-4 relative" style="width: 160px; height: 160px;">
                <div class="progress-ring" 
                     id="progressRing<?php echo $project['id']; ?>"
                     style="position: relative; width: 160px; height: 160px; border-radius: 50%; 
                            background: conic-gradient(from 180deg, rgba(148,163,184,0.3) 0deg, rgba(148,163,184,0.3) 360deg);
                            display: flex; justify-content: center; align-items: center;">
                    <div class="inner-circle" 
                         style="position: absolute; width: 120px; height: 120px; 
                                background: linear-gradient(135deg, rgba(255,255,255,0.9), rgba(248,250,252,0.8));
                                border-radius: 50%; display: flex; align-items: center; justify-content: center;
                                box-shadow: inset 0 2px 8px rgba(0,0,0,0.1);">
                        <div class="percentage" style="font-size: 24px; font-weight: bold; color: #1f2937;">
                            <?php echo $progress; ?>%
                        </div>
                    </div>
                </div>
            </div>

            <div class="text-gray-900 dark:text-white text-sm font-medium">Overall Progress</div>

            <script>
            (function() {
                const percentage = <?php echo $progress; ?>;

                // Create gradient based on linear progress bar colors
                let gradientColor;
                if (percentage <= 33) {
                    // Yellow to transition
                    const factor = percentage / 33;
                    const yellow = [250, 204, 21];   // #facc15
                    const yellowBlue = [162, 176, 133]; // transition color
                    gradientColor = `rgb(${Math.round(yellow[0] + (yellowBlue[0] - yellow[0]) * factor)}, ${Math.round(yellow[1] + (yellowBlue[1] - yellow[1]) * factor)}, ${Math.round(yellow[2] + (yellowBlue[2] - yellow[2]) * factor)})`;
                } else if (percentage <= 66) {
                    // Transition to blue
                    const factor = (percentage - 33) / 33;
                    const yellowBlue = [162, 176, 133];
                    const blue = [59, 130, 246];   // #3b82f6
                    gradientColor = `rgb(${Math.round(yellowBlue[0] + (blue[0] - yellowBlue[0]) * factor)}, ${Math.round(yellowBlue[1] + (blue[1] - yellowBlue[1]) * factor)}, ${Math.round(yellowBlue[2] + (blue[2] - yellowBlue[2]) * factor)})`;
                } else {
                    // Blue to green
                    const factor = (percentage - 66) / 34;
                    const blue = [59, 130, 246];   // #3b82f6
                    const green = [34, 197, 94];    // #22c55e
                    gradientColor = `rgb(${Math.round(blue[0] + (green[0] - blue[0]) * factor)}, ${Math.round(blue[1] + (green[1] - blue[1]) * factor)}, ${Math.round(blue[2] + (green[2] - blue[2]) * factor)})`;
                }

                const fillDeg = (percentage / 100) * 360;

                const circle = document.getElementById('progressRing<?php echo $project['id']; ?>');
                if (circle) {
                    // Use the same gradient as the linear bar: yellow -> blue -> green
                    circle.style.background = `
                        conic-gradient(
                            from 180deg,
                            #facc15 0deg,
                            #facc15 ${fillDeg * 0.33}deg,
                            #3b82f6 ${fillDeg * 0.66}deg,
                            #22c55e ${fillDeg}deg,
                            rgba(148,163,184,0.3) ${fillDeg}deg,
                            rgba(148,163,184,0.3) 360deg
                        )
                    `;
                }
            })();
            </script>
        </div>

        <!-- Steps Card - Full width on mobile -->
        <div class="col-span-1 md:col-span-1 lg:col-span-1 glass-card p-2 md:p-4 text-center">
            <div class="text-lg md:text-2xl font-bold text-gray-900 mb-1">
                <?php echo $completed_steps_count; ?>/<?php echo $total_steps_count; ?>
            </div>
            <div class="text-gray-600 text-xs">Steps Complete</div>
        </div>

        <!-- Department Card - Full width on mobile -->
        <div class="col-span-1 md:col-span-1 lg:col-span-1 glass-card p-2 md:p-4 text-center">
            <div class="text-gray-900 text-xs md:text-sm font-medium mb-1">
                <i class="fas fa-building text-blue-500 mr-1"></i>
                Department
            </div>
            <div class="text-gray-600 text-xs truncate">
                <?php echo htmlspecialchars($project['department_name']); ?>
            </div>
        </div>

        <!-- Project Year Card - Full width on mobile -->
        <div class="col-span-1 md:col-span-1 lg:col-span-1 glass-card p-2 md:p-4 text-center">
            <div class="text-gray-900 text-xs md:text-sm font-medium mb-1">
                <i class="fas fa-calendar text-gray-500 mr-1"></i>
                Year
            </div>
            <div class="text-gray-600 text-xs">
                <?php echo $project['project_year']; ?>
            </div>
        </div>
    </div>

    <!-- Project Details Cards -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Main Content Column -->
        <div class="lg:col-span-2 space-y-6">

            <?php
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
            ?>

            <?php if ($project_total_budget > 0 || $total_allocated > 0 || !empty($recent_transactions)): ?>
            <div class="glass-card p-6">
                <h2 class="text-2xl font-bold text-gray-900 mb-6 flex items-center">
                    <i class="fas fa-money-bill-wave mr-3 text-green-500"></i>
                    Financial Transparency
                </h2>

                <!-- Financial Summary Cards -->
                <div class="grid grid-cols-1 sm:grid-cols-4 gap-4 mb-6">
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

                <!-- Recent Transactions -->
                <?php if (!empty($recent_transactions)): ?>
                <div>
                    <h3 class="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                        <i class="fas fa-receipt mr-2 text-blue-500"></i>
                        Recent Financial Activities
                    </h3>
                    <div class="space-y-3">
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
                            <div class="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
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
                                        <div class="mt-2">
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
            <?php endif; ?>

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

            <!-- Project Documents Viewer -->
            <?php if (!empty($project_documents)): ?>
            <div class="glass-card p-6">
                <h2 class="text-2xl font-bold text-gray-900 mb-6 flex items-center">
                    <i class="fas fa-file-contract mr-3 text-blue-500"></i>
                    Project Documents
                </h2>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <?php foreach ($project_documents as $doc): ?>
                        <?php 
                        $file_extension = strtolower(pathinfo($doc['file_name'], PATHINFO_EXTENSION));
                        $is_viewable = in_array($file_extension, ['pdf', 'jpg', 'jpeg', 'png', 'gif']);
                        ?>
                        <div class="border border-gray-200 rounded-lg p-4">
                            <h4 class="font-semibold text-gray-900 mb-2">
                                <?php echo htmlspecialchars($doc['document_title'] ?? ucfirst($doc['document_type']) . ' Document'); ?>
                            </h4>
                            
                            <?php if ($is_viewable): ?>
                                <?php if ($file_extension === 'pdf'): ?>
                                    <iframe src="uploads/<?php echo urlencode($doc['file_name']); ?>" 
                                            width="100%" 
                                            height="400px" 
                                            style="border:1px solid #ccc; border-radius:8px;">
                                        <p>Your browser does not support PDFs. 
                                           <a href="uploads/<?php echo urlencode($doc['file_name']); ?>">Download the PDF</a>
                                        </p>
                                    </iframe>
                                <?php else: ?>
                                    <img src="uploads/<?php echo urlencode($doc['file_name']); ?>" 
                                         alt="<?php echo htmlspecialchars($doc['document_title'] ?? 'Document'); ?>"
                                         class="w-full h-48 object-cover rounded-lg border border-gray-200">
                                <?php endif; ?>
                            <?php else: ?>
                                <div class="bg-gray-100 p-8 rounded-lg text-center">
                                    <i class="fas fa-file text-3xl text-gray-400 mb-2"></i>
                                    <p class="text-gray-600">Preview not available for this file type</p>
                                    <a href="uploads/<?php echo urlencode($doc['file_name']); ?>" 
                                       class="text-blue-600 hover:text-blue-800 text-sm">View File</a>
                                </div>
                            <?php endif; ?>
                            
                            <div class="mt-3 text-xs text-gray-500">
                                <p><strong>Type:</strong> <?php echo ucfirst($doc['document_type']); ?></p>
                                <p><strong>Uploaded:</strong> <?php echo date('M j, Y', strtotime($doc['uploaded_at'])); ?></p>
                            </div>
                        </div>
                    <?php endforeach; ?>
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
                        <div class="absolute left-6 top-12 w-0.5 h-16 bg-gradient-to-b from-gray-300 to-gray-200 dark:from-gray-600 dark:to-gray-700"></div>
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
                                <div class="w-12 h-12 bg-gradient-to-br from-gray-300 to-gray-400 dark:from-gray-600 dark:to-gray-700 rounded-full flex items-center justify-center shadow-lg">
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
                    <div class="w-24 h-24 bg-gray-100 dark:bg-gray-800 rounded-full flex items-center justify-center mx-auto mb-6">
                        <i class="fas fa-tasks text-3xl text-gray-400 dark:text-gray-600"></i>
                    </div>
                    <h3 class="text-xl font-medium text-gray-900 dark:text-white mb-2">No Timeline Available</h3>
                    <p class="text-sm">Project timeline steps have not been defined yet.</p>
                </div>
                <?php endif; ?>
            </div>

            <!-- Project Information Card -->
            <div class="glass-card p-6">
                <h2 class="text-xl font-bold text-gray-900 mb-6 flex items-center">
                    <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-blue-600 rounded-full flex items-center justify-center mr-3">
                        <i class="fas fa-info-circle text-white"></i>
                    </div>
                    Project Information
                </h2>

                <!-- Project Description -->
                <div class="mb-8">
                    <div class="bg-gradient-to-r from-blue-50 to-indigo-50 p-6 rounded-xl border-l-4 border-blue-500">
                        <h3 class="text-lg font-semibold text-gray-900 mb-3 flex items-center">
                            <i class="fas fa-file-text mr-2 text-blue-500"></i>
                            Description
                        </h3>
                        <p class="text-gray-700 leading-relaxed">
                            <?php echo htmlspecialchars($project['description']); ?>
                        </p>
                    </div>
                </div>

                <!-- Project Details Grid -->
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-6">
                    <!-- Location -->
                    <div class="bg-gradient-to-br from-red-50 to-pink-50 p-5 rounded-xl border border-red-100 hover:shadow-lg transition-shadow">
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
                    <div class="bg-gradient-to-br from-purple-50 to-indigo-50 p-5 rounded-xl border border-purple-100 hover:shadow-lg transition-shadow">
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
                    <div class="bg-gradient-to-br from-yellow-50 to-orange-50 p-5 rounded-xl border border-yellow-100 hover:shadow-lg transition-shadow">
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
                    <div class="bg-gradient-to-br from-green-50 to-emerald-50 p-5 rounded-xl border border-green-100 hover:shadow-lg transition-shadow">
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
                                <?php if (!empty($comment['admin_response']) && $comment['status'] === 'responded'): ?>
                                                <div class="ml-6 mt-3 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg border-l-4 border-blue-400">
                                                    <div class="flex items-start space-x-3">
                                                        <div class="flex-shrink-0">
                                                            <div class="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center">
                                                                <i class="fas fa-user-shield text-white text-sm"></i>
                                                            </div>
                                                        </div>
                                                        <div class="flex-1">
                                                            <div class="flex items-center space-x-2 mb-1">
                                                                <span class="font-medium text-blue-900 dark:text-blue-100">
                                                                    <?php echo htmlspecialchars($comment['admin_name'] ?? 'Admin'); ?>
                                                                </span>
                                                                <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                                                                    Admin
                                                                </span>
                                                                <span class="text-xs text-gray-500 dark:text-gray-400">
                                                                    <?php echo date('M j, Y \a\t g:i A', strtotime($comment['responded_at'] ?? $comment['updated_at'])); ?>
                                                                </span>
                                                            </div>
                                                            <p class="text-sm text-gray-700 dark:text-gray-300">
                                                                <?php echo nl2br(htmlspecialchars($comment['admin_response'])); ?>
                                                            </p>
                                                        </div>
                                                    </div>
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
                                <label class="block text-sm font-medium text-gray-700 mb-1">Your Name *</label>
                                <input type="text" name="citizen_name" required 
                                       class="w-full px-3 py-2 border border-gray-300 rounded-md bg-white text-gray-900 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">Email (Optional)</label>
                                <input type="email" name="citizen_email" 
                                       class="w-full px-3 py-2 border border-gray-300 rounded-md bg-white text-gray-900 focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                            </div>
                        </div>

                        <div class="mb-4">
                            <label class="block text-sm font-medium text-gray-700 mb-1">Your Comment *</label>
                            <textarea name="message" rows="4" required 
                                      placeholder="Share your thoughts about this project..."
                                      class="w-full px-3 py-2 border border-gray-300 rounded-md bg-white text-gray-900 resize-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"></textarea>
                        </div>

                        <button type="submit" class="btn-submit">
                            <i class="fas fa-paper-plane mr-2"></i>
                            Submit Comment
                        </button>
                    </form>
                </div>
            </div>

        </div>

        <!-- Sidebar Content -->
        <div class="lg:col-span-1 space-y-6">
            <!-- Project Location Card -->
            <?php if (!empty($project['location_coordinates'])): ?>
            <div class="glass-card p-6">
                <h3 class="text-xl font-semibold text-gray-900 mb-4 flex items-center">
                    <div class="custom-map-pin mr-3">
                        <div class="pin-body"></div>
                        <div class="pin-tip"></div>
                        <div class="pin-center">
                            <i class="fas fa-map-marker-alt text-white text-xs"></i>
                        </div>
                    </div>
                    Project Location
                </h3>
                <div id="projectMap" class="w-full h-48 rounded-lg border border-gray-200 dark:border-gray-700 mb-4"></div>
                <div class="text-center">
                    <p class="text-sm text-gray-600 mb-2">
                        <i class="fas fa-map-marker-alt mr-1 text-red-500"></i>
                        <?php echo htmlspecialchars($project['ward_name'] . ', ' . $project['sub_county_name']); ?>
                    </p>
                    <p class="text-xs text-gray-500">
                        <?php echo htmlspecialchars($project['county_name']); ?>
                    </p>
                </div>
            </div>
            <?php endif; ?>

            <!-- Quick Stats Card -->
            <div class="glass-card p-6">
                <h3 class="text-xl font-semibold text-gray-900 mb-4 flex items-center">
                    <i class="fas fa-chart-pie mr-3 text-blue-500"></i>
                    Quick Statistics
                </h3>
                <div class="space-y-4">
                    <div class="text-center">
                        <div class="relative inline-flex items-center justify-center w-24 h-24 mb-2">
                            <div class="progress-ring-small" 
                                 id="statsProgressRing<?php echo $project['id']; ?>"
                                 style="position: relative; width: 80px; height: 80px; border-radius: 50%; 
                                        background: conic-gradient(from 180deg, rgba(148,163,184,0.3) 0deg, rgba(148,163,184,0.3) 360deg);
                                        display: flex; justify-content: center; align-items: center;">
                                <div class="inner-circle-small" 
                                     style="position: absolute; width: 60px; height: 60px; 
                                            background: linear-gradient(135deg, rgba(255,255,255,0.9), rgba(248,250,252,0.8));
                                            border-radius: 50%; display: flex; align-items: center; justify-content: center;
                                            box-shadow: inset 0 1px 4px rgba(0,0,0,0.1);">
                                    <div class="percentage-small" style="font-size: 12px; font-weight: bold; color: #1f2937;">
                                        <?php echo $progress; ?>%
                                    </div>
                                </div>
                            </div>
                        </div>
                        <p class="text-xs text-gray-600 dark:text-gray-400">Overall Progress</p>

                        <script>
                        (function() {
                            const percentage = <?php echo $progress; ?>;

                            // Color stops - yellow, blue, green
                            const yellow = [250, 204, 21];   // #facc15
                            const blue   = [59, 130, 246];   // #3b82f6
                            const green  = [34, 197, 94];    // #22c55e

                            function blend(c1, c2, factor) {
                                return c1.map((val, i) => Math.round(val + (c2[i] - val) * factor));
                            }

                            function getBlendedColor(p) {
                                if (p <= 66) {
                                    const factor = p / 66;
                                    return blend(yellow, blue, factor);
                                } else {
                                    const factor = (p - 66) / 34;
                                    return blend(blue, green, factor);
                                }
                            }

                            function toRGB(c) {
                                return `rgb(${c[0]}, ${c[1]}, ${c[2]})`;
                            }

                            const fillColor = toRGB(getBlendedColor(percentage));
                            const fillDeg = (percentage / 100) * 360;

                            const circle = document.getElementById('statsProgressRing<?php echo $project['id']; ?>');
                            if (circle) {
                                circle.style.background = `
                                    conic-gradient(
                                        from 180deg,
                                        ${fillColor} 0deg,
                                        ${fillColor} ${fillDeg}deg,
                                        rgba(148,163,184,0.3) ${fillDeg}deg,
                                        rgba(148,163,184,0.3) 360deg
                                    )
                                `;
                            }
                        })();
                        </script>
                    </div>
                    <div class="grid grid-cols-2 gap-3 text-center">
                        <div class="bg-gray-50 rounded-lg p-3">
                            <div class="text-lg font-bold text-gray-900"><?php echo $completed_steps_count; ?></div>
                            <div class="text-xs text-gray-600">Completed</div>
                        </div>
                        <div class="bg-gray-50 rounded-lg p-3">
                            <div class="text-lg font-bold text-gray-900"><?php echo $total_steps_count; ?></div>
                            <div class="text-xs text-gray-600">Total Steps</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Related Projects Card -->
            <?php if (!empty($related_projects)): ?>
            <div class="glass-card p-6">
                <h3 class="text-xl font-semibold text-gray-900 mb-4 flex items-center">
                    <i class="fas fa-project-diagram mr-3 text-purple-500"></i>
                    Related Projects
                </h3>
                <div class="space-y-4">
                    <?php foreach ($related_projects as $related_project): ?>
                    <?php 
                    $related_progress = $related_project['progress_percentage'] ?? 0;
                    $progress_color = $related_progress <= 25 ? '#ef4444' : ($related_progress <= 50 ? '#f59e0b' : ($related_progress <= 75 ? '#3b82f6' : '#10b981'));
                    ?>
                    <div class="bg-white rounded-xl p-4 border border-gray-200 cursor-pointer"
                         onclick="window.location.href='project_details/<?php echo $related_project['id']; ?>'">
                        <div class="flex items-start space-x-3">
                            <!-- Simple Progress -->
                            <div class="flex-shrink-0 w-12 h-12 bg-gray-100 rounded-full flex items-center justify-center">
                                <span class="text-xs font-semibold text-gray-700">
                                    <?php echo $related_progress; ?>%
                                </span>
                            </div>

                            <!-- Project Info -->
                            <div class="flex-1 min-w-0">
                                <h4 class="font-semibold text-gray-900 text-sm line-clamp-2">
                                    <?php echo htmlspecialchars($related_project['project_name']); ?>
                                </h4>
                                <p class="text-xs text-gray-600 mt-1 flex items-center">
                                    <i class="fas fa-map-marker-alt mr-1 text-red-400"></i>
                                    <?php echo htmlspecialchars($related_project['ward_name']); ?>
                                </p>
                                <div class="mt-2 flex items-center space-x-2">
                                    <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium <?php echo get_status_badge_class($related_project['status']); ?>">
                                        <?php echo ucfirst($related_project['status']); ?>
                                    </span>
                                    <span class="text-xs text-gray-500">
                                        <?php echo $related_project['project_year']; ?>
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
                <div class="mt-4 text-center">
                    <a href="../index" class="text-sm text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium">
                        View All Projects →
                    </a>
                </div>
            </div>
            <?php endif; ?>

 <?php
// Get documents
$stmt = $pdo->prepare("SELECT * FROM project_documents WHERE project_id = ?");
$stmt->execute([$project_id]);
$project_docs = $stmt->fetchAll();

if (!empty($project_docs)): ?>
<div class="glass-card p-6">
    <h3 class="text-xl font-semibold text-gray-900 mb-4 flex items-center">
        <i class="fas fa-file-alt mr-3 text-purple-500"></i>
        Project Documents
    </h3>
    
    <div class="space-y-3">
        <?php foreach ($project_docs as $doc): ?>
            <?php
            $filename = $doc['filename'];
            $full_path = UPLOADS_DIR . '/' . $filename;
            $web_path = UPLOADS_URL . $filename;
            $file_exists = file_exists($full_path);
            $file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
            ?>
            
            <div class="border border-gray-200 rounded-lg p-3 hover:shadow-sm transition-shadow">
                <div class="flex items-start space-x-3">
                    <div class="flex-shrink-0 pt-1">
                        <i class="fas 
                            <?php 
                            if ($file_extension === 'pdf') {
                                echo 'fa-file-pdf text-red-500';
                            } elseif (in_array($file_extension, ['jpg','jpeg','png','gif'])) {
                                echo 'fa-file-image text-blue-500';
                            } else {
                                echo 'fa-file text-gray-500';
                            }
                            ?> 
                            text-xl"></i>
                    </div>
                    <div class="flex-1 min-w-0">
                        <h4 class="font-medium text-gray-900 text-sm line-clamp-2">
                            <?php echo htmlspecialchars($doc['original_name'] ?? $doc['document_type']); ?>
                        </h4>
                        <p class="text-xs text-gray-500 mt-1">
                            <?php echo htmlspecialchars($doc['document_type']); ?> • 
                            <?php echo date('M j, Y', strtotime($doc['created_at'])); ?>
                        </p>
                        
                        <?php if ($file_exists): ?>
                            <div class="mt-3 flex gap-2">
                                <a href="<?php echo $web_path; ?>" 
                                   target="_blank"
                                   class="text-xs bg-blue-50 text-blue-600 px-2 py-1 rounded hover:bg-blue-100">
                                    <i class="fas fa-eye mr-1"></i> View
                                </a>
                                <a href="<?php echo $web_path; ?>" 
                                   download
                                   class="text-xs bg-green-50 text-green-600 px-2 py-1 rounded hover:bg-green-100">
                                    <i class="fas fa-download mr-1"></i> Download
                                </a>
                            </div>
                        <?php else: ?>
                            <div class="mt-2 p-2 bg-red-50 text-red-600 rounded text-xs">
                                <i class="fas fa-exclamation-triangle mr-1"></i>
                                File missing from server (<?php echo htmlspecialchars($filename); ?>)
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
</div>
<?php endif; ?>


            <!-- Project Statistics Card -->
            <div class="glass-card p-6">
                <h3 class="text-xl font-semibold text-gray-900 mb-4 flex items-center">
                    <i class="fas fa-chart-line mr-3 text-green-500"></i>
                    Project Stats
                </h3>
                <div class="space-y-3">
                    <div class="flex items-center justify-between">
                        <span class="text-sm text-gray-600">Department:</span>
                        <span class="font-medium text-gray-900 text-sm"><?php echo htmlspecialchars($project['department_name']); ?></span>
                    </div>
                    <div class="flex items-center justify-between">
                        <span class="text-sm text-gray-600">Year:</span>
                        <span class="font-medium text-gray-900"><?php echo $project['project_year']; ?></span>
                    </div>
                    <?php if ($project['contractor_name']): ?>
                    <div class="flex items-center justify-between">
                        <span class="text-sm text-gray-600">Contractor:</span>
                        <span class="font-medium text-gray-900 text-sm"><?php echo htmlspecialchars($project['contractor_name']); ?></span>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" crossorigin=""></script>
<script src="<?php echo BASE_URL; ?>assets/js/app.js"></script>

<script>
// Define BASE_URL from PHP in global scope
    window.BASE_URL = "<?php echo BASE_URL; ?>";

// Scroll to comments functionality
function scrollToComments() {
    const commentsSection = document.getElementById('comments-section');
    if (commentsSection) {
        commentsSection.scrollIntoView({ 
            behavior: 'smooth', 
            block: 'start' 
        });

        // Add a subtle highlight effect
        commentsSection.style.transform = 'scale(1.02)';
        commentsSection.style.transition = 'transform 0.3s ease';
        setTimeout(() => {
            commentsSection.style.transform = 'scale(1)';
        }, 300);
    }
}

// Document modal functions
function openDocumentModal(title, fileUrl) {
    const modal = document.getElementById('documentModal');
    const modalTitle = document.getElementById('documentModalTitle');
    const viewer = document.getElementById('documentViewer');
    
    modalTitle.textContent = title;
    
    // Check file extension to determine how to display it
    const extension = fileUrl.split('.').pop().toLowerCase();
    if (extension === 'pdf') {
        viewer.src = fileUrl;
        viewer.style.display = 'block';
    } else if (['jpg', 'jpeg', 'png', 'gif'].includes(extension)) {
        viewer.innerHTML = `<img src="${fileUrl}" alt="${title}" class="w-full h-full object-contain">`;
    } else {
        viewer.innerHTML = `
            <div class="h-full flex flex-col items-center justify-center p-4">
                <i class="fas fa-file text-4xl text-gray-400 mb-4"></i>
                <p class="text-gray-600 mb-2">Preview not available for this file type</p>
                <a href="${fileUrl}" class="text-blue-600 hover:text-blue-800">Download File</a>
            </div>
        `;
    }
    
    modal.classList.remove('hidden');
}

function closeDocumentModal() {
    const modal = document.getElementById('documentModal');
    const viewer = document.getElementById('documentViewer');
    
    // Reset viewer content
    viewer.src = '';
    viewer.innerHTML = '';
    modal.classList.add('hidden');
}

// Comment functionality
function replyToComment(commentId, userName) {
    const commentForm = document.getElementById('commentForm');
    if (commentForm) {
        // Set parent comment id
        commentForm.querySelector('input[name="parent_comment_id"]').value = commentId;

        // Update the comment form's title/placeholder to indicate replying
        const commentTextarea = commentForm.querySelector('textarea[name="message"]');
        commentTextarea.placeholder = `Replying to ${userName}...`;

        // Add reply indicator
        const existingIndicator = document.querySelector('.reply-indicator');
        if (existingIndicator) {
            existingIndicator.remove();
        }

        const replyIndicator = document.createElement('div');
        replyIndicator.className = 'reply-indicator bg-blue-50 border-l-4 border-blue-400 p-3 mb-4 rounded-r-lg';
        replyIndicator.innerHTML = `
            <div class="flex items-center justify-between">
                <span class="text-sm text-blue-700">
                    <i class="fas fa-reply mr-2"></i>Replying to <strong>${userName}</strong>
                </span>
                <button onclick="cancelReply()" class="text-blue-600 hover:text-blue-800">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;

        commentForm.insertBefore(replyIndicator, commentForm.firstChild);

        // Scroll to comment form
        commentForm.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });

        // Focus to the textarea
        commentTextarea.focus();
    }
}

function cancelReply() {
    const commentForm = document.getElementById('commentForm');
    if (commentForm) {
        // Reset parent comment id
        commentForm.querySelector('input[name="parent_comment_id"]').value = '0';

        // Reset textarea placeholder
        const textarea = commentForm.querySelector('textarea[name="message"]');
        textarea.placeholder = 'Share your thoughts about this project...';

        // Remove reply indicator
        const replyIndicator = document.querySelector('.reply-indicator');
        if (replyIndicator) {
            replyIndicator.remove();
        }
    }
}

// Load more replies functionality
async function loadMoreReplies(parentId, currentOffset) {
    const loadMoreBtn = event.target;
    const originalText = loadMoreBtn.innerHTML;

    // Show loading state
    loadMoreBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Loading...';
    loadMoreBtn.disabled = true;

    try {
        const response = await fetch(`${window.BASE_URL}api/loadMoreReplies.php?parent_id=${parentId}&offset=${currentOffset}&limit=5`);
        const data = await response.json();

        if (data.success && data.replies.length > 0) {
            const repliesContainer = loadMoreBtn.closest('.comment-thread').querySelector('.replies-container');
            const loadMoreContainer = loadMoreBtn.closest('.load-more-replies-container');

            // Create new reply elements
            data.replies.forEach(reply => {
                const replyElement = createReplyElement(reply);
                repliesContainer.insertBefore(replyElement, loadMoreContainer);
            });

            // Update or remove load more button
            if (data.has_more) {
                loadMoreBtn.innerHTML = `<i class="fas fa-chevron-down mr-2"></i>Load ${Math.min(data.remaining, 5)} more replies`;
                loadMoreBtn.disabled = false;
                // Update onclick with new offset
                loadMoreBtn.setAttribute('onclick', `loadMoreReplies(${parentId}, ${currentOffset + 5})`);
            } else {
                loadMoreContainer.remove();
            }
        } else {
            loadMoreBtn.innerHTML = 'No more replies';
            setTimeout(() => {
                loadMoreBtn.closest('.load-more-replies-container').remove();
            }, 1000);
        }
    } catch (error) {
        console.error('Error loading more replies:', error);
        loadMoreBtn.innerHTML = originalText;
        loadMoreBtn.disabled = false;
        showNotification('Failed to load more replies', 'error');
    }
}

function createReplyElement(reply) {
    const replyDiv = document.createElement('div');
    replyDiv.className = 'reply-item flex items-start space-x-3';

    const avatarClass = reply.is_admin ? 'bg-red-500' : 'bg-gray-500';
    const avatarContent = reply.is_admin ? '<i class="fas fa-shield-alt"></i>' : reply.display_name.charAt(0).toUpperCase();

    let badges = '';
    if (reply.is_admin) {
        badges += '<span class="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800"><i class="fas fa-shield-alt mr-1"></i>Admin</span>';
    } else {
        badges += '<span class="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800"><i class="fas fa-reply mr-1"></i>Reply</span>';
    }

    if (reply.is_user_pending) {
        badges += '<span class="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800"><i class="fas fa-clock mr-1"></i>Pending</span>';
    }

    replyDiv.innerHTML = `
        <div class="flex-shrink-0">
            <div class="w-8 h-8 ${avatarClass} rounded-full flex items-center justify-center text-white text-xs font-semibold">
                ${avatarContent}
            </div>
        </div>
        <div class="flex-1 min-w-0">
            <div class="bg-gray-50 rounded-lg p-3">
                <div class="flex items-center space-x-2 mb-1">
                    <span class="text-sm font-semibold text-gray-900">${reply.display_name}</span>
                    ${badges}
                    <span class="text-xs text-gray-500">${reply.time_ago}</span>
                </div>
                <div class="text-sm text-gray-700 leading-relaxed break-words">
                    ${reply.message.replace(/\n/g, '<br>')}
                </div>
            </div>
        </div>
    `;

    return replyDiv;
}

// Initialize map if coordinates exist
document.addEventListener('DOMContentLoaded', function() {
    <?php if (!empty($project['location_coordinates'])): ?>
    const coordinates = '<?php echo $project['location_coordinates']; ?>'.split(',');
    if (coordinates.length === 2) {
        const lat = parseFloat(coordinates[0].trim());
        const lng = parseFloat(coordinates[1].trim());

        if (!isNaN(lat) && !isNaN(lng) && lat !== 0 && lng !== 0) {
            try {
                // Initialize map
                const map = L.map('projectMap').setView([lat, lng], 15);

                // Add tile layer
                L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    attribution: '© OpenStreetMap contributors',
                    maxZoom: 18
                }).addTo(map);

                // Default Leaflet pin style marker icon
                const markerIcon = new L.Icon({
                    iconUrl: `data:image/svg+xml;charset=UTF-8,${encodeURIComponent(`
                        <svg width="25" height="41" viewBox="0 0 25 41" xmlns="http://www.w3.org/2000/svg">
                            <path fill="#3b82f6" stroke="#FFFFFF" stroke-width="1" d="M12.5,0C5.6,0,0,5.6,0,12.5c0,6.9,12.5,28.5,12.5,28.5s12.5-21.6,12.5-28.5C25,5.6,19.4,0,12.5,0z"/>
                            <circle fill="#FFFFFF" cx="12.5" cy="12.5" r="4"/>
                        </svg>
                    `)}`,
                    iconSize: [25, 41],
                    iconAnchor: [12.5, 41],
                    popupAnchor: [0, -41]
                });

                // Create marker with popup
                const marker = L.marker([lat, lng], { icon: markerIcon }).addTo(map);
                marker.bindPopup(`
                    <div class="relative p-3 min-w-48">
                        <h4 class="font-semibold text-gray-900 mb-2"><?php echo addslashes($project['project_name']); ?></h4>
                        <p class="text-sm text-gray-600 mb-2"><?php echo addslashes($project['ward_name'] . ', ' . $project['sub_county_name']); ?></p>
                        <div class="mb-3">
                            <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                <?php echo ucfirst($project['status']); ?>
                            </span>
                        </div>
                        <div class="text-xs text-gray-500">
                            <p><strong>Department:</strong> <?php echo addslashes($project['department_name']); ?></p>
                            <p><strong>Year:</strong> <?php echo $project['project_year']; ?></p>
                            <p><strong>Progress:</strong> <?php echo $progress; ?>%</p>
                        </div>
                    </div>
                `, {
                    maxWidth: 250,
                    closeButton: true
                });

                // Add map controls
                L.control.scale().addTo(map);

                // Ensure map renders properly
                setTimeout(() => {
                    map.invalidateSize();
                }, 100);
            } catch (error) {
                console.error('Error initializing map:', error);
            }
        }
    }
    <?php endif; ?>
});

// Handle main comment form submission
const commentForm = document.getElementById('commentForm');
if (commentForm) {
    commentForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        await submitComment(this);
    });
}

async function submitComment(form) {
    const formData = new FormData(form);
    const submitBtn = form.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    const parentId = parseInt(formData.get('parent_comment_id')) || 0;
    const userName = formData.get('citizen_name');
    const message = formData.get('message');

    // Disable submit button and show loading
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Submitting...';
    submitBtn.disabled = true;

    try {
        const response = await fetch(window.BASE_URL + 'api/feedback.php', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();

        if (data.success) {
            // Show success message
            showNotification('Comment submitted and is pending approval!', 'success');

            // Reset form
            form.reset();

            // Reset parent comment id to 0
            form.querySelector('input[name="parent_comment_id"]').value = '0';

            // Reset textarea placeholder and remove reply indicator
            const textarea = form.querySelector('textarea[name="message"]');
            textarea.placeholder = 'Share your thoughts about this project...';
            cancelReply();

            // Add pending comment to DOM immediately (visible only to user)
            addPendingCommentToDOM({
                message: message,
                userName: userName,
                parentId: parentId,
                isPending: true,
                timestamp: new Date()
            });

        } else {
            showNotification(data.message || 'Failed to submit comment', 'error');
        }
    } catch (error) {
        console.error('Comment submission error:', error);
        showNotification('Network error: Failed to submit comment. Please try again.', 'error');
    } finally {
        // Re-enable submit button
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
    }
}

function addPendingCommentToDOM(commentData) {
    const commentsContainer = document.getElementById('comments-container');

    if (commentData.parentId === 0) {
        // Main comment
        const commentElement = createPendingCommentElement(commentData);

        // Insert at the beginning for main comments
        if (commentsContainer.firstChild) {
            commentsContainer.insertBefore(commentElement, commentsContainer.firstChild);
        } else {
            commentsContainer.appendChild(commentElement);
        }
    } else {
        // Reply comment
        const parentThread = document.querySelector(`[data-comment-id="${commentData.parentId}"]`);
        if (parentThread) {
            let repliesContainer = parentThread.querySelector('.replies-container');
            if (!repliesContainer) {
                // Create replies container if it doesn't exist
                repliesContainer = document.createElement('div');
                repliesContainer.className = 'replies-container ml-12 mt-3 space-y-3';
                repliesContainer.innerHTML = '<div class="replies-container::before"></div>';
                parentThread.appendChild(repliesContainer);
            }

            const replyElement = createPendingReplyElement(commentData);
            const loadMoreContainer = repliesContainer.querySelector('.load-more-replies-container');

            if (loadMoreContainer) {
                repliesContainer.insertBefore(replyElement, loadMoreContainer);
            } else {
                repliesContainer.appendChild(replyElement);
            }
        }
    }
}

function createPendingCommentElement(commentData) {
    const div = document.createElement('div');
    div.className = 'comment-thread pending-comment';
    div.setAttribute('data-comment-id', 'pending-' + Date.now());

    div.innerHTML = `
        <div class="comment-main">
            <div class="flex items-start space-x-3">
                <div class="flex-shrink-0">
                    <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-blue-600 rounded-full flex items-center justify-center text-white text-sm font-semibold">
                        ${commentData.userName.charAt(0).toUpperCase()}
                    </div>
                </div>
                <div class="flex-1 min-w-0">
                    <div class="bg-white rounded-lg shadow-sm border-2 border-dashed border-yellow-300 p-4">
                        <div class="flex items-center space-x-2 mb-2">
                            <span class="font-semibold text-gray-900">${commentData.userName}</span>
                            <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                                <i class="fas fa-clock mr-1"></i>Pending Approval
                            </span>
                            <span class="text-sm text-gray-500">just now</span>
                        </div>
                        <div class="text-gray-700 leading-relaxed break-words">
                            ${commentData.message.replace(/\n/g, '<br>')}
                        </div>
                        <div class="flex items-center space-x-4 mt-3 pt-2 border-t border-gray-100">
                            <span class="text-sm text-gray-400">
                                <i class="fas fa-eye-slash mr-1"></i>Only visible to you
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    return div;
}

function createPendingReplyElement(commentData) {
    const div = document.createElement('div');
    div.className = 'reply-item pending-reply flex items-start space-x-3';

    div.innerHTML = `
        <div class="flex-shrink-0">
            <div class="w-8 h-8 bg-gray-500 rounded-full flex items-center justify-center text-white text-xs font-semibold">
                ${commentData.userName.charAt(0).toUpperCase()}
            </div>
        </div>
        <div class="flex-1 min-w-0">
            <div class="bg-gray-50 rounded-lg p-3 border-2 border-dashed border-yellow-300">
                <div class="flex items-center space-x-2 mb-1">
                    <span class="text-sm font-semibold text-gray-900">${commentData.userName}</span>
                    <span class="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                        <i class="fas fa-reply mr-1"></i>Reply
                    </span>
                    <span class="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                        <i class="fas fa-clock mr-1"></i>Pending
                    </span>
                    <span class="text-xs text-gray-500">just now</span>
                </div>
                <div class="text-sm text-gray-700 leading-relaxed break-words">
                    ${commentData.message.replace(/\n/g, '<br>')}
                </div>
                <div class="text-xs text-gray-400 mt-2">
                    <i class="fas fa-eye-slash mr-1"></i>Only visible to you
                </div>
            </div>
        </div>
    `;

    return div;
}

function showNotification(message, type) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 p-4 rounded-md shadow-lg z-50 max-w-sm`;
    notification.style.background = type === 'success' ? '#10b981' : '#ef4444';
    notification.style.color = 'white';

    notification.innerHTML = `
        <div class="flex items-center">
            <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'} mr-3"></i>
            <span>${message}</span>
            <button onclick="this.parentElement.parentElement.remove()" class="ml-4 text-white hover:text-gray-200">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;

    document.body.appendChild(notification);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

// Update scroll indicator on scroll and scroll to top button
window.addEventListener('scroll', () => {
    const scrollHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
    const scrollTop = document.documentElement.scrollTop;
    const progress = scrollTop / scrollHeight;

    // Update scroll progress indicator
    const scrollIndicator = document.querySelector('.scroll-indicator');
    if (scrollIndicator) {
        scrollIndicator.style.setProperty('--scroll-progress', progress);
    }

    // Handle scroll to top button visibility
    const scrollToTop = document.getElementById('scrollToTop');
    if (scrollTop > 300) {
        scrollToTop.classList.remove('opacity-0', 'invisible', 'translate-y-4');
        scrollToTop.classList.add('opacity-100', 'visible', 'translate-y-0');
    } else {
        scrollToTop.classList.add('opacity-0', 'invisible', 'translate-y-4');
        scrollToTop.classList.remove('opacity-100', 'visible', 'translate-y-0');
    }
});

// Scroll to top functionality
const scrollToTopBtn = document.getElementById('scrollToTop');
if (scrollToTopBtn) {
    scrollToTopBtn.addEventListener('click', function() {
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    });
}
</script>

<!-- Scroll Progress Indicator -->
<div class="scroll-indicator"></div>

<!-- Scroll to Top Button -->
<button id="scrollToTop" class="fixed bottom-6 right-6 bg-blue-600 text-white p-3 rounded-full shadow-lg hover:bg-blue-700 transition-all z-50 opacity-0 invisible transform translate-y-4">
    <i class="fas fa-arrow-up"></i>
</button>

<script>
// Scroll to top functionality
window.addEventListener('scroll', function() {
    const scrollToTop = document.getElementById('scrollToTop');
    if (window.pageYOffset > 300) {
        scrollToTop.classList.remove('opacity-0', 'invisible', 'translate-y-4');
        scrollToTop.classList.add('opacity-100', 'visible', 'translate-y-0');
    } else {
        scrollToTop.classList.add('opacity-0', 'invisible', 'translate-y-4');
        scrollToTop.classList.remove('opacity-100', 'visible', 'translate-y-0');
    }
});

document.getElementById('scrollToTop').addEventListener('click', function() {
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
});
</script>

<?php include 'includes/footer.php'; ?>