<?php
$page_title = "Permission Management";
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';
require_once '../includes/rbac.php';

// Only super admin can manage permissions
require_role('super_admin');
$current_admin = get_current_admin();

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token. Please refresh the page and try again.';
    } else {
        $action = $_POST['action'] ?? '';

        if ($action === 'bulk_update_permissions') {
            $admin_permissions = $_POST['admin_permissions'] ?? [];
            $updated_count = 0;
            $errors = [];

            foreach ($admin_permissions as $admin_id => $permissions) {
                $admin_id = intval($admin_id);
                if ($admin_id > 0) {
                    if (RBAC::updateAdminPermissions($admin_id, $permissions, $current_admin['id'])) {
                        $updated_count++;
                    } else {
                        $errors[] = "Failed to update permissions for admin ID: $admin_id";
                    }
                }
            }

            if ($updated_count > 0) {
                $success = "Successfully updated permissions for $updated_count administrator(s).";
                log_activity('bulk_permission_update', "Updated permissions for $updated_count admins", $current_admin['id']);
            }

            if (!empty($errors)) {
                $error = implode('<br>', $errors);
            }
        }
    }
}

// Get all non-super-admin users
$stmt = $pdo->prepare("
    SELECT id, name, email, role, is_active, created_at 
    FROM admins 
    WHERE role != 'super_admin' 
    ORDER BY role DESC, name ASC
");
$stmt->execute();
$admins = $stmt->fetchAll();

// Get current permissions for all admins
$admin_permissions = [];
foreach ($admins as $admin) {
    $admin_permissions[$admin['id']] = RBAC::getAdminPermissions($admin['id']);
}

// Get permission categories
$permission_categories = RBAC::getPermissionCategories();

include 'includes/adminHeader.php';
?>

<div class="p-6">
    <!-- Header -->
    <div class="mb-8">
        <div class="flex items-center justify-between">
            <div>
                <h1 class="text-2xl font-bold text-gray-900">Permission Management</h1>
                <p class="text-gray-600 mt-2">Manage page access permissions for all administrators</p>
            </div>
            <div class="flex space-x-3">
                <a href="rolesPermissions.php" class="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                    <i class="fas fa-arrow-left mr-2"></i>
                    Back to Roles
                </a>
            </div>
        </div>
    </div>

    <!-- Messages -->
    <?php if (isset($success)): ?>
        <div class="mb-6 rounded-md bg-green-50 p-4 border border-green-200">
            <div class="flex">
                <i class="fas fa-check-circle text-green-400 mr-3 mt-0.5"></i>
                <p class="text-sm text-green-700"><?php echo $success; ?></p>
            </div>
        </div>
    <?php endif; ?>

    <?php if (isset($error)): ?>
        <div class="mb-6 rounded-md bg-red-50 p-4 border border-red-200">
            <div class="flex">
                <i class="fas fa-exclamation-circle text-red-400 mr-3 mt-0.5"></i>
                <p class="text-sm text-red-700"><?php echo $error; ?></p>
            </div>
        </div>
    <?php endif; ?>

    <!-- Permission Matrix -->
    <form method="POST" id="permissionForm">
        <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
        <input type="hidden" name="action" value="bulk_update_permissions">

        <div class="bg-white rounded-lg shadow-sm border border-gray-200">
            <div class="px-6 py-4 border-b border-gray-200">
                <div class="flex items-center justify-between">
                    <h3 class="text-lg font-semibold text-gray-900">Permission Matrix</h3>
                    <div class="flex space-x-2">
                        <button type="button" onclick="selectAllPermissions()" class="text-sm text-blue-600 hover:text-blue-800">
                            Select All
                        </button>
                        <button type="button" onclick="clearAllPermissions()" class="text-sm text-gray-600 hover:text-gray-800">
                            Clear All
                        </button>
                    </div>
                </div>
            </div>

            <div class="overflow-x-auto">
                <table class="min-w-full">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="sticky left-0 bg-gray-50 px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider border-r border-gray-200">
                                Administrator
                            </th>
                            <?php foreach ($permission_categories as $category_name => $permissions): ?>
                                <th class="px-3 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider border-r border-gray-200" colspan="<?php echo count($permissions); ?>">
                                    <?php echo htmlspecialchars($category_name); ?>
                                </th>
                            <?php endforeach; ?>
                        </tr>
                        <tr class="bg-gray-100">
                            <th class="sticky left-0 bg-gray-100 px-6 py-2 text-left border-r border-gray-200"></th>
                            <?php foreach ($permission_categories as $category_name => $permissions): ?>
                                <?php foreach ($permissions as $permission_key => $permission_name): ?>
                                    <th class="px-2 py-2 text-xs text-gray-600 border-r border-gray-200 min-w-24" title="<?php echo htmlspecialchars($permission_name); ?>">
                                        <div class="transform -rotate-45 origin-center whitespace-nowrap">
                                            <?php echo substr($permission_name, 0, 8) . (strlen($permission_name) > 8 ? '...' : ''); ?>
                                        </div>
                                    </th>
                                <?php endforeach; ?>
                            <?php endforeach; ?>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        <?php foreach ($admins as $admin): ?>
                            <tr class="hover:bg-gray-50">
                                <td class="sticky left-0 bg-white hover:bg-gray-50 px-6 py-4 border-r border-gray-200">
                                    <div class="flex items-center">
                                        <div class="w-8 h-8 bg-gradient-to-r from-blue-500 to-purple-600 rounded-full flex items-center justify-center mr-3">
                                            <span class="text-white font-bold text-xs">
                                                <?php echo strtoupper(substr($admin['name'], 0, 1)); ?>
                                            </span>
                                        </div>
                                        <div>
                                            <div class="text-sm font-medium text-gray-900">
                                                <?php echo htmlspecialchars($admin['name']); ?>
                                            </div>
                                            <div class="text-xs text-gray-500">
                                                <?php echo htmlspecialchars($admin['email']); ?>
                                            </div>
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium <?php echo $admin['role'] === 'admin' ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-800'; ?>">
                                                <?php echo ucfirst($admin['role']); ?>
                                            </span>
                                        </div>
                                    </div>
                                </td>
                                <?php foreach ($permission_categories as $category_name => $permissions): ?>
                                    <?php foreach ($permissions as $permission_key => $permission_name): ?>
                                        <td class="px-2 py-4 text-center border-r border-gray-200">
                                            <input type="checkbox" 
                                                   name="admin_permissions[<?php echo $admin['id']; ?>][]" 
                                                   value="<?php echo $permission_key; ?>"
                                                   <?php echo in_array($permission_key, $admin_permissions[$admin['id']]) ? 'checked' : ''; ?>
                                                   class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded permission-checkbox"
                                                   data-admin="<?php echo $admin['id']; ?>"
                                                   data-permission="<?php echo $permission_key; ?>">
                                        </td>
                                    <?php endforeach; ?>
                                <?php endforeach; ?>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <?php if (empty($admins)): ?>
                <div class="text-center py-12">
                    <i class="fas fa-users text-4xl text-gray-300 mb-4"></i>
                    <p class="text-gray-500">No administrators found to manage permissions for.</p>
                </div>
            <?php endif; ?>
        </div>

        <!-- Save Button -->
        <?php if (!empty($admins)): ?>
            <div class="mt-6 flex justify-end">
                <button type="submit" class="inline-flex items-center px-6 py-3 border border-transparent text-base font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 transition-colors">
                    <i class="fas fa-save mr-2"></i>
                    Update All Permissions
                </button>
            </div>
        <?php endif; ?>
    </form>

    <!-- Permission Legend -->
    <div class="mt-8 bg-white rounded-lg shadow-sm border border-gray-200">
        <div class="px-6 py-4 border-b border-gray-200">
            <h3 class="text-lg font-semibold text-gray-900">Permission Reference</h3>
        </div>
        <div class="p-6">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <?php foreach ($permission_categories as $category_name => $permissions): ?>
                    <div class="border border-gray-200 rounded-lg p-4">
                        <h4 class="font-semibold text-gray-900 mb-3"><?php echo htmlspecialchars($category_name); ?></h4>
                        <div class="space-y-2">
                            <?php foreach ($permissions as $permission_key => $permission_name): ?>
                                <div class="flex items-start text-sm">
                                    <div class="w-2 h-2 bg-blue-400 rounded-full mr-3 mt-2 flex-shrink-0"></div>
                                    <div>
                                        <div class="font-medium text-gray-700"><?php echo htmlspecialchars($permission_name); ?></div>
                                        <div class="text-xs text-gray-500"><?php echo htmlspecialchars($permission_key); ?></div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
</div>

<script>
function selectAllPermissions() {
    document.querySelectorAll('.permission-checkbox').forEach(checkbox => {
        checkbox.checked = true;
    });
}

function clearAllPermissions() {
    document.querySelectorAll('.permission-checkbox').forEach(checkbox => {
        checkbox.checked = false;
    });
}

// Auto-save indication
let formChanged = false;
document.getElementById('permissionForm').addEventListener('change', function() {
    formChanged = true;
});

window.addEventListener('beforeunload', function(e) {
    if (formChanged) {
        e.preventDefault();
        e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
    }
});

document.getElementById('permissionForm').addEventListener('submit', function() {
    formChanged = false;
});
</script>

<?php include 'includes/adminFooter.php'; ?>
