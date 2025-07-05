<?php
$page_title = "Roles & Permissions";
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';
require_once 'includes/pageSecurity.php';

// Only super admin can manage roles
require_role('super_admin');

$current_admin = get_current_admin();
$success_message = '';
$error_message = '';

// Handle permission updates
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_permissions'])) {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $admin_id = filter_input(INPUT_POST, 'admin_id', FILTER_VALIDATE_INT);
        $permissions = $_POST['permissions'] ?? [];

        if ($admin_id && $admin_id !== $current_admin['id']) {
            // Validate permissions against actual available permissions
            $valid_permissions = [];
            $all_valid_permissions = array_keys(get_available_permissions());

            foreach ($permissions as $perm) {
                if (in_array($perm, $all_valid_permissions)) {
                    $valid_permissions[] = $perm;
                }
            }

            if (updateAdminPermissions($admin_id, $valid_permissions, $current_admin['id'])) {
                $success_message = "Permissions updated successfully for admin ID: {$admin_id}";

                // Log the action
                log_activity('permissions_updated', 
                    "Updated permissions for admin ID {$admin_id}. Granted " . count($valid_permissions) . " permissions.",
                    $current_admin['id'], 'admin', $admin_id, 
                    ['permissions' => $valid_permissions]
                );

                // If updating current user's permissions, refresh their session
                if ($admin_id == $current_admin['id']) {
                    $_SESSION['permissions'] = $valid_permissions;
                }
            } else {
                $error_message = "Failed to update permissions. Please try again.";
            }
        } else {
            $error_message = "Invalid admin ID or cannot modify own permissions.";
        }
    }
}

// Handle admin creation
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['create_admin'])) {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $name = sanitize_input($_POST['name'] ?? '');
        $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
        $password = $_POST['password'] ?? '';
        $role = sanitize_input($_POST['role'] ?? '');

        // Validation
        if (empty($name) || empty($email) || empty($password) || empty($role)) {
            $error_message = "All fields are required.";
        } elseif (!in_array($role, ['admin', 'viewer'])) {
            $error_message = "Invalid role selected.";
        } elseif (strlen($password) < 8) {
            $error_message = "Password must be at least 8 characters long.";
        } else {
            try {
                // Check if email already exists
                $stmt = $pdo->prepare("SELECT id FROM admins WHERE email = ?");
                $stmt->execute([$email]);

                if ($stmt->fetchColumn()) {
                    $error_message = "Email address already exists.";
                } else {
                    // Create new admin
                    $password_hash = password_hash($password, PASSWORD_BCRYPT);
                    $stmt = $pdo->prepare("
                        INSERT INTO admins (name, email, password_hash, role, is_active, created_at) 
                        VALUES (?, ?, ?, ?, 1, NOW())
                    ");

                    if ($stmt->execute([$name, $email, $password_hash, $role])) {
                        $new_admin_id = $pdo->lastInsertId();

                        // Give basic dashboard access by default
                        updateAdminPermissions($new_admin_id, ['dashboard_access'], $current_admin['id']);

                        $success_message = "Administrator '{$name}' created successfully.";

                        // Log the action
                        log_activity('admin_created', 
                            "Created new administrator: {$name} ({$email}) with role: {$role}",
                            $current_admin['id'], 'admin', $new_admin_id,
                            ['name' => $name, 'email' => $email, 'role' => $role]
                        );
                    } else {
                        $error_message = "Failed to create administrator.";
                    }
                }
            } catch (PDOException $e) {
                error_log("Create admin error: " . $e->getMessage());
                $error_message = "Database error occurred.";
            }
        }
    }
}

// Handle admin status toggle
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['toggle_status'])) {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $admin_id = filter_input(INPUT_POST, 'admin_id', FILTER_VALIDATE_INT);
        $current_status = filter_input(INPUT_POST, 'current_status', FILTER_VALIDATE_INT);

        if ($admin_id && $admin_id !== $current_admin['id']) {
            $new_status = $current_status ? 0 : 1;
            $action = $new_status ? 'activated' : 'deactivated';

            try {
                $stmt = $pdo->prepare("UPDATE admins SET is_active = ? WHERE id = ? AND role != 'super_admin'");
                if ($stmt->execute([$new_status, $admin_id])) {
                    $success_message = "Administrator {$action} successfully.";

                    // Log the action
                    log_activity('admin_status_changed', 
                        "Administrator ID {$admin_id} {$action}",
                        $current_admin['id'], 'admin', $admin_id,
                        ['new_status' => $new_status, 'action' => $action]
                    );
                } else {
                    $error_message = "Failed to update administrator status.";
                }
            } catch (PDOException $e) {
                error_log("Toggle admin status error: " . $e->getMessage());
                $error_message = "Database error occurred.";
            }
        }
    }
}

// Get all admins except current super admin
$stmt = $pdo->prepare("
    SELECT id, name, email, role, is_active, last_login, created_at,
           (SELECT COUNT(*) FROM admin_permissions WHERE admin_id = admins.id AND is_active = 1) as permission_count
    FROM admins 
    WHERE id != ? 
    ORDER BY role DESC, name ASC
");
$stmt->execute([$current_admin['id']]);
$admins = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Function to get available permissions based on sidebar items
function get_available_permissions() {
    return [
        // Core Access
        'dashboard_access' => 'Dashboard Access',
        'profile_access' => 'Profile Management',

        // Project Management (matching actual permission keys)
        'create_projects' => 'Create New Projects',
        'view_projects' => 'View Projects',
        'edit_projects' => 'Edit Projects', 
        'manage_projects' => 'Full Project Management (Create, Edit, Delete, Manage)',
        'import_data' => 'Import CSV Data',
        'manage_project_steps' => 'Manage Project Steps & Milestones',
        'manage_budgets' => 'Budget Management',
        'view_reports' => 'PMC Reports & Analytics',

        // Community & Feedback
        'manage_feedback' => 'Community Feedback Management',
        'manage_documents' => 'PMC Document Management',

        // Administration
        'manage_users' => 'User Account Management',
        'manage_roles' => 'Roles & Permissions Management',
        'view_activity_logs' => 'Activity Logs & Audit Trail',
        'system_settings' => 'System Configuration'
    ];
}

$available_permissions = get_available_permissions();

// Get current permissions for each admin
$admin_permissions = [];
foreach ($admins as $admin) {
    $admin_permissions[$admin['id']] = getAdminPermissions($admin['id']);
}

// Get all available permissions
function get_all_available_permissions() {
    $categories = getPermissionCategories();
    $all_permissions = [];

    foreach ($categories as $category => $permissions) {
        foreach ($permissions as $key => $details) {
            $all_permissions[$key] = $details['name'];
        }
    }

    return $all_permissions;
}

include 'includes/adminHeader.php';
?>

<div class="admin-content">
    <!-- Breadcrumb -->
    <div class="mb-6">
        <nav class="flex" aria-label="Breadcrumb">
            <ol class="flex items-center space-x-2 text-sm">
                <li><a href="index.php" class="text-gray-500 hover:text-gray-700">Dashboard</a></li>
                <li><span class="text-gray-400">/</span></li>
                <li><span class="text-gray-900 font-medium">Roles & Permissions</span></li>
            </ol>
        </nav>
    </div>

    <!-- Header -->
    <div class="mb-8">
        <div class="flex items-center justify-between">
            <div>
                <h1 class="text-3xl font-bold text-gray-900">Roles & Permissions Management</h1>
                <p class="text-gray-600 mt-2">Manage system administrators and their access permissions</p>
            </div>
            <div class="flex items-center space-x-3">
                <div class="bg-blue-50 px-4 py-2 rounded-lg">
                    <div class="text-sm text-blue-800">
                        <i class="fas fa-shield-alt mr-1"></i>
                        <strong><?php echo count($admins); ?></strong> Administrators
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Alert Messages -->
    <?php if ($success_message): ?>
        <div class="mb-6 rounded-md bg-green-50 p-4 border border-green-200">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <i class="fas fa-check-circle text-green-400 text-lg"></i>
                </div>
                <div class="ml-3">
                    <p class="text-sm text-green-800"><?php echo htmlspecialchars($success_message); ?></p>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($error_message): ?>
        <div class="mb-6 rounded-md bg-red-50 p-4 border border-red-200">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <i class="fas fa-exclamation-circle text-red-400 text-lg"></i>
                </div>
                <div class="ml-3">
                    <p class="text-sm text-red-800"><?php echo htmlspecialchars($error_message); ?></p>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <!-- Tab Navigation -->
    <div class="border-b border-gray-200 mb-6">
        <nav class="-mb-px flex space-x-8">
            <button onclick="showTab('administrators')" id="administrators-tab" class="tab-button active">
                <i class="fas fa-users mr-2"></i>Administrators
            </button>
            <button onclick="showTab('create')" id="create-tab" class="tab-button">
                <i class="fas fa-user-plus mr-2"></i>Create Administrator
            </button>
        </nav>
    </div>

    <!-- Administrators Tab -->
    <div id="administrators-content" class="tab-content">
        <div class="bg-white rounded-lg shadow-sm border border-gray-200">
            <div class="px-6 py-4 border-b border-gray-200">
                <div class="flex items-center justify-between">
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900">System Administrators</h3>
                        <p class="text-sm text-gray-600 mt-1">Manage admin accounts and their permission levels</p>
                    </div>
                    <div class="text-sm text-gray-500">
                        Total: <strong><?php echo count($admins); ?></strong> administrators
                    </div>
                </div>
            </div>

            <!-- Permission Management -->
            <div class="p-6">
                <?php foreach ($admins as $admin): ?>
                    <?php $current_permissions = $admin_permissions[$admin['id']]; ?>
                    <div class="border border-gray-200 rounded-lg p-4 mb-4">
                        <div class="flex items-center justify-between mb-4">
                            <div class="flex items-center">
                                <div class="w-10 h-10 bg-gray-100 rounded-lg flex items-center justify-center">
                                    <span class="text-sm font-medium text-gray-600">
                                        <?php echo strtoupper(substr($admin['name'], 0, 2)); ?>
                                    </span>
                                </div>
                                <div class="ml-3">
                                    <h4 class="font-medium text-gray-900"><?php echo htmlspecialchars($admin['name']); ?></h4>
                                    <p class="text-sm text-gray-500"><?php echo htmlspecialchars($admin['email']); ?></p>
                                    <div class="flex items-center space-x-2 mt-1">
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium 
                                            <?php echo $admin['role'] === 'super_admin' ? 'bg-red-100 text-red-800' : 
                                                      ($admin['role'] === 'admin' ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-800'); ?>">
                                            <?php echo ucfirst(str_replace('_', ' ', $admin['role'])); ?>
                                        </span>
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium 
                                            <?php echo $admin['is_active'] ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'; ?>">
                                            <?php echo $admin['is_active'] ? 'Active' : 'Inactive'; ?>
                                        </span>
                                    </div>
                                </div>
                            </div>

                            <div class="flex items-center space-x-2">
                                <?php if ($admin['role'] !== 'super_admin'): ?>
                                    <button onclick="togglePermissions(<?php echo $admin['id']; ?>)" 
                                            class="text-blue-600 hover:text-blue-800 text-sm">
                                        <i class="fas fa-edit mr-1"></i>Edit Permissions
                                    </button>

                                    <form method="POST" class="inline" onsubmit="return confirm('Are you sure you want to <?php echo $admin['is_active'] ? 'deactivate' : 'activate'; ?> this administrator?')">
                                        <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                                        <input type="hidden" name="toggle_status" value="1">
                                        <input type="hidden" name="admin_id" value="<?php echo $admin['id']; ?>">
                                        <input type="hidden" name="current_status" value="<?php echo $admin['is_active']; ?>">
                                        <button type="submit" class="<?php echo $admin['is_active'] ? 'text-red-600 hover:text-red-800' : 'text-green-600 hover:text-green-800'; ?> text-sm">
                                            <i class="fas <?php echo $admin['is_active'] ? 'fa-ban' : 'fa-check'; ?> mr-1"></i>
                                            <?php echo $admin['is_active'] ? 'Deactivate' : 'Activate'; ?>
                                        </button>
                                    </form>
                                <?php else: ?>
                                    <span class="text-gray-400 italic text-sm">Protected Account</span>
                                <?php endif; ?>
                            </div>
                        </div>

                        <?php if ($admin['role'] !== 'super_admin'): ?>
                            <div id="permissions-<?php echo $admin['id']; ?>" class="hidden">
                                <form method="POST" class="border-t border-gray-200 pt-4">
                                    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                                    <input type="hidden" name="update_permissions" value="1">
                                    <input type="hidden" name="admin_id" value="<?php echo $admin['id']; ?>">

                                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-4">
                                        <?php foreach ($available_permissions as $perm_key => $perm_name): ?>
                                            <label class="flex items-center">
                                                <input type="checkbox" name="permissions[]" value="<?php echo $perm_key; ?>" 
                                                       <?php echo in_array($perm_key, $current_permissions) ? 'checked' : ''; ?>
                                                       class="rounded border-gray-300 text-blue-600 focus:ring-blue-500">
                                                <span class="ml-2 text-sm text-gray-700"><?php echo $perm_name; ?></span>
                                            </label>
                                        <?php endforeach; ?>
                                    </div>

                                    <div class="flex justify-end space-x-2">
                                        <button type="button" onclick="togglePermissions(<?php echo $admin['id']; ?>)" 
                                                class="px-4 py-2 text-sm text-gray-600 hover:text-gray-800">Cancel</button>
                                        <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700">
                                            Save Permissions
                                        </button>
                                    </div>
                                </form>
                            </div>
                        <?php endif; ?>

                        <!-- Current Permissions Display -->
                        <div class="flex flex-wrap gap-2 mt-2">
                            <?php if ($admin['role'] === 'super_admin'): ?>
                                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                    All Permissions
                                </span>
                            <?php else: ?>
                                <?php foreach ($current_permissions as $perm): ?>
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                        <?php echo $available_permissions[$perm] ?? $perm; ?>
                                    </span>
                                <?php endforeach; ?>
                                <?php if (empty($current_permissions)): ?>
                                    <span class="text-sm text-gray-500">No permissions assigned</span>
                                <?php endif; ?>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <!-- Create Administrator Tab -->
    <div id="create-content" class="tab-content hidden">
        <div class="bg-white rounded-lg shadow-sm border border-gray-200">
            <div class="p-6 border-b border-gray-200">
                <h3 class="text-lg font-semibold text-gray-900">Create New Administrator</h3>
                <p class="text-sm text-gray-600 mt-1">Add a new administrator to the system with appropriate permissions</p>
            </div>
            <div class="p-6">
                <form method="POST" class="space-y-6 max-w-2xl">
                    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                    <input type="hidden" name="create_admin" value="1">

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                            <label for="name" class="block text-sm font-medium text-gray-700 mb-2">
                                <i class="fas fa-user mr-1"></i>Full Name *
                            </label>
                            <input type="text" name="name" id="name" required 
                                   class="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                                   placeholder="Enter full name">
                        </div>

                        <div>
                            <label for="email" class="block text-sm font-medium text-gray-700 mb-2">
                                <i class="fas fa-envelope mr-1"></i>Email Address *
                            </label>
                            <input type="email" name="email" id="email" required 
                                   class="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                                   placeholder="Enter email address">
                        </div>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                            <label for="password" class="block text-sm font-medium text-gray-700 mb-2">
                                <i class="fas fa-lock mr-1"></i>Password *
                            </label>
                            <input type="password" name="password" id="password" required minlength="8"
                                   class="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                                   placeholder="Minimum 8 characters">
                            <p class="mt-1 text-sm text-gray-500">Must be at least 8 characters long</p>
                        </div>

                        <div>
                            <label for="role" class="block text-sm font-medium text-gray-700 mb-2">
                                <i class="fas fa-user-tag mr-1"></i>Role *
                            </label>
                            <select name="role" id="role" required 
                                    class="w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
                                <option value="">Select Role</option>
                                <option value="admin">Administrator</option>
                                <option value="viewer">Viewer</option>
                            </select>
                        </div>
                    </div>

                    <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
                        <div class="flex items-start">
                            <i class="fas fa-info-circle text-blue-600 mt-1 mr-2"></i>
                            <div class="text-sm text-blue-800">
                                <p class="font-medium mb-1">Default Permissions</p>
                                <p>New administrators will be created with dashboard access only. You can assign additional permissions after creation using the "Edit Permissions" option.</p>
                            </div>
                        </div>
                    </div>

                    <div class="flex justify-end pt-4 border-t">
                        <button type="submit" 
                                class="inline-flex items-center px-6 py-3 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                            <i class="fas fa-user-plus mr-2"></i>
                            Create Administrator
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>

<style>
.tab-button {
    border-bottom: 2px solid transparent;
    padding: 12px 16px;
    font-medium;
    color: #6b7280;
    transition: all 0.2s;
}

.tab-button.active {
    border-bottom-color: #3b82f6;
    color: #3b82f6;
}

.tab-button:hover {
    color: #3b82f6;
}

.tab-content {
    display: block;
}

.tab-content.hidden {
    display: none;
}
</style>

<script>
function showTab(tabName) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.add('hidden');
    });

    // Remove active class from all tabs
    document.querySelectorAll('.tab-button').forEach(button => {
        button.classList.remove('active');
    });

    // Show selected tab content
    document.getElementById(tabName + '-content').classList.remove('hidden');

    // Add active class to selected tab
    document.getElementById(tabName + '-tab').classList.add('active');
}

function togglePermissions(adminId) {
    const element = document.getElementById('permissions-' + adminId);
    element.classList.toggle('hidden');
}

function refreshCSRFToken() {
    fetch('../api/csrfToken.php')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Update all CSRF token inputs
                document.querySelectorAll('input[name="csrf_token"]').forEach(input => {
                    input.value = data.token;
                });
            }
        })
        .catch(error => {
            console.error('Error refreshing CSRF token:', error);
        });
}

// Refresh CSRF token every 4 minutes (before 5-minute expiry)
setInterval(refreshCSRFToken, 240000);

// Also refresh on page focus (in case user was away)
document.addEventListener('visibilitychange', function() {
    if (!document.hidden) {
        refreshCSRFToken();
    }
});
</script>

<?php include 'includes/adminFooter.php'; ?>