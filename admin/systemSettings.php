<?php
// This file includes page security and displays system settings, permission templates.
require_once 'includes/pageSecurity.php';
$current_admin = get_current_admin();

$page_title = "System Settings";

include 'includes/adminHeader.php';
?>

<div class="bg-white rounded-xl p-6 mb-6 shadow-sm border border-gray-200">
    <!-- Breadcrumbs -->
    <div class="mb-6">
        <nav class="flex" aria-label="Breadcrumb">
            <ol class="flex items-center space-x-2">
                <li><a href="index.php" class="text-gray-500 hover:text-gray-700">Dashboard</a></li>
                <li><span class="text-gray-400">/</span></li>
                <li><span class="text-gray-900">System Settings</span></li>
            </ol>
        </nav>
    </div>

    <!-- Page Header -->
    <div class="mb-8">
        <h1 class="text-2xl font-bold text-gray-900">System Settings</h1>
        <p class="text-gray-600 mt-2">Manage system configuration and user permissions</p>
    </div>

    <!-- Permission Templates -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
        <!-- Super Admin Template -->
        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <div class="flex items-center mb-4">
                <div class="w-10 h-10 bg-red-100 rounded-lg flex items-center justify-center">
                    <i class="fas fa-crown text-red-600"></i>
                </div>
                <div class="ml-3">
                    <h3 class="font-semibold text-gray-900">Super Admin</h3>
                    <p class="text-sm text-gray-500">Full system access</p>
                </div>
            </div>
            <div class="text-sm text-gray-600">
                <p>• All permissions granted</p>
                <p>• User management access</p>
                <p>• System configuration</p>
                <p>• Critical operations</p>
            </div>
        </div>

        <!-- Project Admin Template -->
        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <div class="flex items-center mb-4">
                <div class="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                    <i class="fas fa-project-diagram text-blue-600"></i>
                </div>
                <div class="ml-3">
                    <h3 class="font-semibold text-gray-900">Project Admin</h3>
                    <p class="text-sm text-gray-500">Project management</p>
                </div>
            </div>
            <div class="text-sm text-gray-600">
                <p>• Create & edit projects</p>
                <p>• Manage project documents</p>
                <p>• Handle community feedback</p>
                <p>• Generate reports</p>
            </div>
        </div>

        <!-- Viewer Template -->
        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <div class="flex items-center mb-4">
                <div class="w-10 h-10 bg-green-100 rounded-lg flex items-center justify-center">
                    <i class="fas fa-eye text-green-600"></i>
                </div>
                <div class="ml-3">
                    <h3 class="font-semibold text-gray-900">Viewer</h3>
                    <p class="text-sm text-gray-500">Read-only access</p>
                </div>
            </div>
            <div class="text-sm text-gray-600">
                <p>• View projects</p>
                <p>• View reports</p>
                <p>• View feedback</p>
                <p>• Limited administrative access</p>
            </div>
        </div>
    </div>

<?php include 'includes/adminFooter.php'; ?>