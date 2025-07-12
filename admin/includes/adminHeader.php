<?php
require_once __DIR__ . '/../../config.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/../../includes/rbac.php';

require_admin();
$current_admin = get_current_admin();

// Get allowed pages and feedback counts
$allowed_pages = getAllowedPages();
$pending_count = 0;
$grievance_count = 0;
$has_feedback_permission = hasPagePermission('manage_feedback');

if ($has_feedback_permission) {
    try {
        $pending_count = $pdo->query("SELECT COUNT(*) FROM feedback WHERE status = 'pending'")->fetchColumn();

        if ($current_admin['role'] === 'super_admin') {
            $grievance_count = $pdo->query("SELECT COUNT(*) FROM feedback WHERE status = 'grievance' AND grievance_status = 'open'")->fetchColumn();
        } else {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM feedback f
                                  JOIN projects p ON f.project_id = p.id
                                  WHERE f.status = 'grievance' 
                                  AND f.grievance_status = 'open'
                                  AND p.created_by = ?");
            $stmt->execute([$current_admin['id']]);
            $grievance_count = $stmt->fetchColumn();
        }
    } catch (PDOException $e) {
        error_log("Error getting feedback counts: " . $e->getMessage());
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo isset($page_title) ? $page_title . ' - ' : ''; ?>Migori County PMC Portal - Admin</title>

    <!-- Favicon -->
    <link rel="icon" type="image/png" href="../migoriLogo.png">

    <!-- TailwindCSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        'pmc-navy': '#003366',
                        'pmc-gold': '#FFD966',
                        'pmc-gray': '#F4F4F4',
                        'pmc-text': '#333333',
                        'pmc-green': '#4CAF50'
                    }
                }
            }
        }
    </script>

    <!-- FontAwesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">

    <link rel="stylesheet" href="../assets/css/admin.css">

    <style>
        .sidebar-nav-item {
            transition: all 0.2s ease;
            position: relative;
        }
        .sidebar-nav-item:hover {
            background: #f3f4f6;
            border-left: 3px solid #FFD966;
        }
        .sidebar-nav-item.active {
            background: #eff6ff;
            border-left: 3px solid #003366;
            color: #003366;
            font-weight: 600;
        }
        .notification-badge {
            position: absolute;
            top: -0.5rem;
            right: -0.5rem;
            background: #ef4444;
            color: white;
            border-radius: 9999px;
            width: 1.25rem;
            height: 1.25rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            line-height: 1;
        }

        /* Layout improvements */
        body {
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        #content-container {
            display: flex;
            flex: 1;
        }
        #sidebar {
            width: 250px;
            flex-shrink: 0;
        }
        #main-content {
            flex: 1;
            overflow-y: auto;
        }
        #mobile-sidebar {
            transform: translateX(-100%);
            transition: transform 0.3s ease;
        }
        #mobile-sidebar.active {
            transform: translateX(0);
        }
        #mobile-sidebar-overlay {
            opacity: 0;
            visibility: hidden;
            transition: opacity 0.3s ease, visibility 0.3s ease;
        }
        #mobile-sidebar-overlay.active {
            opacity: 1;
            visibility: visible;
        }
		/* Mobile Styles */
		@media (max-width: 767px) {
			#sidebar {
				display: none; /* Hide desktop sidebar on mobile */
			}
			#mobile-sidebar {
				display: block; /* Show mobile sidebar */
				width: 70%; /* Adjust as needed */
				max-width: 300px;
				position: fixed;
				top: 3.5rem;
				left: 0;
				bottom: 0;
				z-index: 50;
				background-color: white;
				border-right: 1px solid #ddd;
				padding-top: 1rem;
				overflow-y: auto;
				transform: translateX(-100%);
				transition: transform 0.3s ease-in-out;
			}

			#mobile-sidebar.active {
				transform: translateX(0);
			}

			#mobile-sidebar-overlay {
				display: none;
				position: fixed;
				top: 0;
				left: 0;
				width: 100%;
				height: 100%;
				background-color: rgba(0, 0, 0, 0.5);
				z-index: 40;
			}

			#mobile-sidebar-overlay.active {
				display: block;
			}
		}
    </style>
</head>
<body class="bg-gray-50">
    <!-- Admin Header -->
    <header class="bg-pmc-navy text-white shadow-md fixed top-0 left-0 right-0 z-50 h-16">
        <div class="flex items-center justify-between h-full px-4">
            <!-- Mobile menu button and logo -->
            <div class="flex items-center space-x-4">
                <button id="mobile-menu-toggle" class="lg:hidden p-2 rounded-md text-white hover:bg-white/10">
                    <i class="fas fa-bars"></i>
                </button>
                <a href="index.php" class="flex items-center space-x-2">
                    <img src="../migoriLogo.png" alt="Migori County" class="h-10 w-10">
                    <div>
                        <h1 class="text-white font-bold text-lg">PMC Portal</h1>
                        <p class="text-blue-200 text-xs">Admin Dashboard</p>
                    </div>
                </a>
            </div>

            <!-- Desktop navigation items -->
            <div class="hidden lg:flex items-center space-x-6">
                <?php if ($has_feedback_permission): ?>
                <div class="relative">
                    <a href="feedback.php" class="text-white hover:text-pmc-gold p-2 rounded-lg hover:bg-white/10">
                        <i class="fas fa-bell"></i>
                        <?php if ($pending_count > 0): ?>
                            <span class="notification-badge"><?php echo $pending_count; ?></span>
                        <?php endif; ?>
                    </a>
                </div>
                <?php endif; ?>

                <!-- User Menu -->
                <div class="relative">
                    <button class="flex items-center space-x-2 text-white hover:text-pmc-gold p-2 rounded-lg hover:bg-white/10">
                        <div class="w-8 h-8 bg-pmc-gold rounded-full flex items-center justify-center">
                            <span class="text-pmc-navy font-bold text-sm">
                                <?php echo strtoupper(substr($current_admin['name'], 0, 1)); ?>
                            </span>
                        </div>
                        <span><?php echo htmlspecialchars($current_admin['name']); ?></span>
                    </button>
                </div>
            </div>
        </div>
    </header>

    <!-- Content Container -->
    <div id="content-container" class="pt-16">
        <!-- Desktop Sidebar -->
        <aside id="sidebar" class="bg-white border-r border-gray-200 hidden lg:block">
            <nav class="py-4 px-3 h-full">
                <!-- Dashboard -->
                <a href="index.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'index.php' ? 'active' : '' ?>">
                    <i class="fas fa-home w-5 text-center"></i>
                    <span>Dashboard</span>
                </a>

                <!-- Projects Section -->
                <?php $has_project_perms = hasPagePermission('create_projects') || hasPagePermission('view_projects') || 
                                          hasPagePermission('manage_budgets') || hasPagePermission('view_reports'); ?>
                <?php if ($has_project_perms): ?>
                    <div class="px-3 py-2 mt-4 mb-2 text-xs uppercase text-gray-500 font-semibold tracking-wider">
                        Project Management
                    </div>

                    <?php if (hasPagePermission('create_projects')): ?>
                        <a href="importCsv.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'importCsv.php' ? 'active' : '' ?>">
                            <i class="fas fa-upload w-5 text-center"></i>
                            <span>Upload Projects</span>
                        </a>
                        <a href="createProject.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'createProject.php' ? 'active' : '' ?>">
                            <i class="fas fa-plus-circle w-5 text-center"></i>
                            <span>Add New Project</span>
                        </a>
                    <?php endif; ?>

                    <?php if (hasPagePermission('view_projects')): ?>
                        <a href="projects.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'projects.php' ? 'active' : '' ?>">
                            <i class="fas fa-folder w-5 text-center"></i>
                            <span>Manage Projects</span>
                        </a>
                    <?php endif; ?>

                    <?php if (hasPagePermission('manage_budgets')): ?>
                        <a href="budgetManagement.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'budgetManagement.php' ? 'active' : '' ?>">
                            <i class="fas fa-money-bill-wave w-5 text-center"></i>
                            <span>Budget Management</span>
                        </a>
                    <?php endif; ?>

                    <?php if (hasPagePermission('view_reports')): ?>
                        <a href="pmcReports.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'pmcReports.php' ? 'active' : '' ?>">
                            <i class="fas fa-chart-bar w-5 text-center"></i>
                            <span>PMC Reports</span>
                        </a>
                    <?php endif; ?>
                <?php endif; ?>

                <!-- Community & Documents -->
                <?php $has_community_perms = hasPagePermission('manage_documents') || hasPagePermission('manage_feedback'); ?>
                <?php if ($has_community_perms): ?>
                    <div class="px-3 py-2 mt-4 mb-2 text-xs uppercase text-gray-500 font-semibold tracking-wider border-t border-gray-200">
                        Community & Documents
                    </div>

                    <?php if (hasPagePermission('manage_documents')): ?>
                        <a href="documentManager.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'documentManager.php' ? 'active' : '' ?>">
                            <i class="fas fa-file-alt w-5 text-center"></i>
                            <span>PMC Documents</span>
                        </a>
                    <?php endif; ?>

                    <?php if (hasPagePermission('manage_feedback')): ?>
                        <a href="feedback.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 relative <?= basename($_SERVER['PHP_SELF']) == 'feedback.php' ? 'active' : '' ?>">
                            <i class="fas fa-comments w-5 text-center"></i>
                            <span>Community Feedback</span>
                            <?php if ($pending_count > 0): ?>
                                <span class="notification-badge"><?php echo $pending_count; ?></span>
                            <?php endif; ?>
                        </a>

                        <?php if ($current_admin['role'] === 'super_admin'): ?>
                            <a href="commentFiltering.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'commentFiltering.php' ? 'active' : '' ?>">
                                <i class="fas fa-filter w-5 text-center"></i>
                                <span>Comment Filtering</span>
                            </a>
                            <a href="subscriptionManager.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'subscriptionManager.php' ? 'active' : '' ?>">
                                <i class="fas fa-users w-5 text-center"></i>
                                <span>Manage Subscribers</span>
                            </a>
                        <?php endif; ?>
                    <?php endif; ?>

                    <?php if ($grievance_count > 0): ?>
                        <a href="grievances.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 relative <?= basename($_SERVER['PHP_SELF']) == 'grievances.php' ? 'active' : '' ?>">
                            <i class="fas fa-exclamation-triangle w-5 text-center text-red-500"></i>
                            <span class="text-red-700">Grievance Management</span>
                            <span class="notification-badge bg-red-500"><?php echo $grievance_count; ?></span>
                        </a>
                    <?php endif; ?>
                <?php endif; ?>

                <!-- System Administration -->
                <?php $has_admin_perms = hasPagePermission('manage_roles') || hasPagePermission('view_activity_logs') || hasPagePermission('system_settings'); ?>
                <?php if ($has_admin_perms): ?>
                    <div class="px-3 py-2 mt-4 mb-2 text-xs uppercase text-gray-500 font-semibold tracking-wider border-t border-gray-200">
                        System Administration
                    </div>

                    <?php if (hasPagePermission('manage_roles')): ?>
                        <a href="rolesPermissions.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'rolesPermissions.php' ? 'active' : '' ?>">
                            <i class="fas fa-user-shield w-5 text-center"></i>
                            <span>Roles & Permissions</span>
                        </a>
                    <?php endif; ?>

                    <?php if (hasPagePermission('view_activity_logs')): ?>
                        <a href="activityLogs.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'activityLogs.php' ? 'active' : '' ?>">
                            <i class="fas fa-clipboard-list w-5 text-center"></i>
                            <span>Activity Logs</span>
                        </a>
                    <?php endif; ?>

                    <?php if (hasPagePermission('system_settings')): ?>
                        <a href="systemSettings.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'systemSettings.php' ? 'active' : '' ?>">
                            <i class="fas fa-cog w-5 text-center"></i>
                            <span>System Settings</span>
                        </a>
                    <?php endif; ?>
                <?php endif; ?>

                <!-- Profile & Logout -->
                <div class="border-t border-gray-200 mt-4 pt-4">
                    <a href="profile.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'profile.php' ? 'active' : '' ?>">
                        <i class="fas fa-user w-5 text-center"></i>
                        <span>Profile Settings</span>
                    </a>
                    <a href="../logout.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 text-red-600 hover:bg-red-50">
                        <i class="fas fa-sign-out-alt w-5 text-center"></i>
                        <span>Logout</span>
                    </a>
                </div>
            </nav>
        </aside>

        <!-- Mobile Sidebar Overlay -->
        <div id="mobile-sidebar-overlay" class="fixed inset-0 bg-black/50 z-30 lg:hidden hidden"></div>

        <!-- Mobile Sidebar -->
        <aside id="mobile-sidebar" class="bg-white border-r border-gray-200 w-64 fixed top-16 bottom-0 left-0 z-40 lg:hidden">
            <nav class="py-4 px-3 h-full overflow-y-auto">
                <!-- Dashboard -->
                <a href="index.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'index.php' ? 'active' : '' ?>">
                    <i class="fas fa-home w-5 text-center"></i>
                    <span>Dashboard</span>
                </a>

                <!-- Projects Section -->
                <?php if ($has_project_perms): ?>
                    <div class="px-3 py-2 mt-4 mb-2 text-xs uppercase text-gray-500 font-semibold tracking-wider">
                        Project Management
                    </div>

                    <?php if (hasPagePermission('create_projects')): ?>
                        <a href="importCsv.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'importCsv.php' ? 'active' : '' ?>">
                            <i class="fas fa-upload w-5 text-center"></i>
                            <span>Upload Projects</span>
                        </a>
                        <a href="createProject.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'createProject.php' ? 'active' : '' ?>">
                            <i class="fas fa-plus-circle w-5 text-center"></i>
                            <span>Add New Project</span>
                        </a>
                    <?php endif; ?>

                    <?php if (hasPagePermission('view_projects')): ?>
                        <a href="projects.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'projects.php' ? 'active' : '' ?>">
                            <i class="fas fa-folder w-5 text-center"></i>
                            <span>Manage Projects</span>
                        </a>
                    <?php endif; ?>

                    <?php if (hasPagePermission('manage_budgets')): ?>
                        <a href="budgetManagement.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'budgetManagement.php' ? 'active' : '' ?>">
                            <i class="fas fa-money-bill-wave w-5 text-center"></i>
                            <span>Budget Management</span>
                        </a>
                    <?php endif; ?>

                    <?php if (hasPagePermission('view_reports')): ?>
                        <a href="pmcReports.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'pmcReports.php' ? 'active' : '' ?>">
                            <i class="fas fa-chart-bar w-5 text-center"></i>
                            <span>PMC Reports</span>
                        </a>
                    <?php endif; ?>
                <?php endif; ?>

                <!-- Community & Documents -->
                <?php if ($has_community_perms): ?>
                    <div class="px-3 py-2 mt-4 mb-2 text-xs uppercase text-gray-500 font-semibold tracking-wider border-t border-gray-200">
                        Community & Documents
                    </div>

                    <?php if (hasPagePermission('manage_documents')): ?>
                        <a href="documentManager.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'documentManager.php' ? 'active' : '' ?>">
                            <i class="fas fa-file-alt w-5 text-center"></i>
                            <span>PMC Documents</span>
                        </a>
                    <?php endif; ?>

                    <?php if (hasPagePermission('manage_feedback')): ?>
                        <a href="feedback.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 relative <?= basename($_SERVER['PHP_SELF']) == 'feedback.php' ? 'active' : '' ?>">
                            <i class="fas fa-comments w-5 text-center"></i>
                            <span>Community Feedback</span>
                            <?php if ($pending_count > 0): ?>
                                <span class="notification-badge"><?php echo $pending_count; ?></span>
                            <?php endif; ?>
                        </a>

                        <?php if ($current_admin['role'] === 'super_admin'): ?>
                            <a href="commentFiltering.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'commentFiltering.php' ? 'active' : '' ?>">
                                <i class="fas fa-filter w-5 text-center"></i>
                                <span>Comment Filtering</span>
                            </a>
                            <a href="subscriptionManager.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'subscriptionManager.php' ? 'active' : '' ?>">
                                <i class="fas fa-users w-5 text-center"></i>
                                <span>Manage Subscribers</span>
                            </a>
                        <?php endif; ?>
                    <?php endif; ?>

                    <?php if ($grievance_count > 0): ?>
                        <a href="grievances.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 relative <?= basename($_SERVER['PHP_SELF']) == 'grievances.php' ? 'active' : '' ?>">
                            <i class="fas fa-exclamation-triangle w-5 text-center text-red-500"></i>
                            <span class="text-red-700">Grievance Management</span>
                            <span class="notification-badge bg-red-500"><?php echo $grievance_count; ?></span>
                        </a>
                    <?php endif; ?>
                <?php endif; ?>

                <!-- System Administration -->
                <?php if ($has_admin_perms): ?>
                    <div class="px-3 py-2 mt-4 mb-2 text-xs uppercase text-gray-500 font-semibold tracking-wider border-t border-gray-200">
                        System Administration
                    </div>

                    <?php if (hasPagePermission('manage_roles')): ?>
                        <a href="rolesPermissions.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'rolesPermissions.php' ? 'active' : '' ?>">
                            <i class="fas fa-user-shield w-5 text-center"></i>
                            <span>Roles & Permissions</span>
                        </a>
                    <?php endif; ?>

                    <?php if (hasPagePermission('view_activity_logs')): ?>
                        <a href="activityLogs.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'activityLogs.php' ? 'active' : '' ?>">
                            <i class="fas fa-clipboard-list w-5 text-center"></i>
                            <span>Activity Logs</span>
                        </a>
                    <?php endif; ?>

                    <?php if (hasPagePermission('system_settings')): ?>
                        <a href="systemSettings.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'systemSettings.php' ? 'active' : '' ?>">
                            <i class="fas fa-cog w-5 text-center"></i>
                            <span>System Settings</span>
                        </a>
                    <?php endif; ?>
                <?php endif; ?>

                <!-- Profile & Logout -->
                <div class="border-t border-gray-200 mt-4 pt-4">
                    <a href="profile.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 <?= basename($_SERVER['PHP_SELF']) == 'profile.php' ? 'active' : '' ?>">
                        <i class="fas fa-user w-5 text-center"></i>
                        <span>Profile Settings</span>
                    </a>
                    <a href="../logout.php" class="sidebar-nav-item flex items-center space-x-3 py-2 px-3 rounded-lg mb-1 text-red-600 hover:bg-red-50">
                        <i class="fas fa-sign-out-alt w-5 text-center"></i>
                        <span>Logout</span>
                    </a>
                </div>
            </nav>
        </aside>

        <!-- Main Content Area -->
        <main id="main-content" class="flex-1 p-6">
