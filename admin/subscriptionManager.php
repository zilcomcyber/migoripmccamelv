<?php
$page_title = "Subscription Management";
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';
require_once '../includes/projectSubscriptions.php';

require_admin();
$current_admin = get_current_admin();

// Get subscription statistics
$subscription_manager = new ProjectSubscriptionManager($pdo);

// Get total subscriptions
$stmt = $pdo->prepare("
    SELECT COUNT(*) as total,
           COUNT(CASE WHEN is_active = 1 THEN 1 END) as active,
           COUNT(CASE WHEN email_verified = 1 THEN 1 END) as verified
    FROM project_subscriptions
");
$stmt->execute();
$stats = $stmt->fetch();

// Get recent subscriptions
$stmt = $pdo->prepare("
    SELECT ps.*, p.project_name 
    FROM project_subscriptions ps
    JOIN projects p ON ps.project_id = p.id
    ORDER BY ps.subscribed_at DESC 
    LIMIT 20
");
$stmt->execute();
$recent_subscriptions = $stmt->fetchAll();

// Get subscription trends (last 30 days)
$stmt = $pdo->prepare("
    SELECT DATE(subscribed_at) as date, COUNT(*) as count
    FROM project_subscriptions 
    WHERE subscribed_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    GROUP BY DATE(subscribed_at)
    ORDER BY date DESC
");
$stmt->execute();
$trends = $stmt->fetchAll();

include 'includes/adminHeader.php';
?>

<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
    <!-- Breadcrumb -->
    <div class="mb-6">
        <nav class="flex" aria-label="Breadcrumb">
            <ol class="flex items-center space-x-2 text-sm">
                <li class="text-gray-600 font-medium">
                    <i class="fas fa-home mr-1"></i> Dashboard
                </li>
                <li class="text-gray-400">/</li>
                <li class="text-gray-600 font-medium">Subscription Management</li>
            </ol>
        </nav>
    </div>

    <!-- Page Header -->
    <div class="mb-8">
        <div class="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
            <div class="flex flex-col md:flex-row items-start justify-between">
                <div class="mb-4 md:mb-0">
                    <h1 class="text-2xl font-bold text-gray-900 mb-2">Subscription Management</h1>
                    <p class="text-gray-600">Monitor and manage project subscription activity</p>
                    <p class="text-sm text-gray-500 mt-2">Track user subscriptions and email notifications</p>
                </div>
                <div class="text-center md:text-right">
                    <div class="text-3xl font-bold text-blue-600 mb-1">
                        <i class="fas fa-users"></i>
                    </div>
                    <div class="text-sm text-gray-600 mb-3">Subscriptions</div>
                    <div class="text-xs text-gray-500">Total: <?php echo number_format($stats['total']); ?></div>
                </div>
            </div>
        </div>
    </div>

    <div class="bg-white rounded-lg p-6 mb-6 shadow-sm border border-gray-200">

    <!-- Statistics Cards -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div class="bg-gradient-to-br from-blue-50 to-blue-100 p-6 rounded-xl border border-blue-200">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-blue-600 text-sm font-medium">Total Subscriptions</p>
                    <p class="text-2xl font-bold text-blue-900"><?php echo number_format($stats['total']); ?></p>
                </div>
                <div class="w-12 h-12 bg-blue-500 rounded-full flex items-center justify-center">
                    <i class="fas fa-users text-white text-xl"></i>
                </div>
            </div>
        </div>

        <div class="bg-gradient-to-br from-green-50 to-green-100 p-6 rounded-xl border border-green-200">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-green-600 text-sm font-medium">Active Subscriptions</p>
                    <p class="text-2xl font-bold text-green-900"><?php echo number_format($stats['active']); ?></p>
                </div>
                <div class="w-12 h-12 bg-green-500 rounded-full flex items-center justify-center">
                    <i class="fas fa-bell text-white text-xl"></i>
                </div>
            </div>
        </div>

        <div class="bg-gradient-to-br from-purple-50 to-purple-100 p-6 rounded-xl border border-purple-200">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-purple-600 text-sm font-medium">Verified Emails</p>
                    <p class="text-2xl font-bold text-purple-900"><?php echo number_format($stats['verified']); ?></p>
                </div>
                <div class="w-12 h-12 bg-purple-500 rounded-full flex items-center justify-center">
                    <i class="fas fa-check-circle text-white text-xl"></i>
                </div>
            </div>
        </div>
    </div>

    <!-- Recent Subscriptions -->
    <div class="bg-white rounded-lg shadow-sm border border-gray-200">
        <div class="px-6 py-4 border-b border-gray-200">
            <h3 class="text-lg font-semibold text-gray-900">Recent Subscriptions</h3>
        </div>
        <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Subscribed</th>
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
                    <?php foreach ($recent_subscriptions as $subscription): ?>
                    <tr class="hover:bg-gray-50">
                        <td class="px-6 py-4 whitespace-nowrap">
                            <div class="flex items-center">
                                <div class="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
                                    <i class="fas fa-user text-blue-600 text-sm"></i>
                                </div>
                                <div class="ml-3">
                                    <p class="text-sm font-medium text-gray-900">
                                        <?php echo htmlspecialchars($subscription['email']); ?>
                                    </p>
                                </div>
                            </div>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap">
                            <p class="text-sm text-gray-900"><?php echo htmlspecialchars($subscription['project_name']); ?></p>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap">
                            <div class="flex items-center space-x-2">
                                <?php if ($subscription['is_active']): ?>
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                        Active
                                    </span>
                                <?php else: ?>
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                                        Inactive
                                    </span>
                                <?php endif; ?>
                                
                                <?php if ($subscription['email_verified']): ?>
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                        Verified
                                    </span>
                                <?php else: ?>
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                                        Unverified
                                    </span>
                                <?php endif; ?>
                            </div>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            <?php echo date('M j, Y g:i A', strtotime($subscription['subscribed_at'])); ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<?php include 'includes/adminFooter.php'; ?>
