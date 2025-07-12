<?php
require_once __DIR__ . '/../config.php';

/**
 * Enterprise-Grade Role-Based Access Control (RBAC) System
 * Government-grade security implementation with comprehensive logging and caching
 */
class SecureRBAC {
    private static $pdo;
    private static $permissions_cache = [];
    private static $cache_ttl = 300; // 5 minutes

    // Comprehensive page permission mapping
    private static $page_permissions = [
        // Dashboard (always accessible)
        'index.php' => 'dashboard_access',
        'dashboard.php' => 'dashboard_access',

        // Project Management
        'projects.php' => 'view_projects',
        'createProject.php' => 'create_projects',
        'editProject.php' => 'edit_projects',
        'manageProject.php' => 'manage_projects',
        'updateProject.php' => 'edit_projects',
        'submitProject.php' => 'create_projects',

        // Project Steps Management
        'manageSteps.php' => 'manage_project_steps',
        'editStep.php' => 'manage_project_steps',

        // Data Import/Export
        'importCsv.php' => 'import_data',
        'getTemplates.php' => 'import_data',

        // Document Management
        'documentManager.php' => 'manage_documents',

        // Budget Management
        'budgetManagement.php' => 'manage_budgets',

        // Feedback and Community
        'feedback.php' => 'manage_feedback',

        // Reports and Analytics
        'pmcReports.php' => 'view_reports',
        'activityLogs.php' => 'view_activity_logs',

        // System Administration
        'manageAdmins.php' => 'manage_users',
        'rolesPermissions.php' => 'manage_roles',
        'manageAdminPermissions.php' => 'manage_roles',
        'systemSettings.php' => 'system_settings',

        // Profile (always accessible)
        'profile.php' => 'profile_access'
    ];

    // Permission categories with detailed definitions
    private static $permission_categories = [
        'Core Access' => [
            'dashboard_access' => [
                'name' => 'Dashboard Access',
                'description' => 'Access to main administrative dashboard',
                'risk_level' => 'low'
            ],
            'profile_access' => [
                'name' => 'Profile Management',
                'description' => 'Manage own profile and settings',
                'risk_level' => 'low'
            ]
        ],
        'Project Management' => [
            'view_projects' => [
                'name' => 'View Projects',
                'description' => 'View project listings and details',
                'risk_level' => 'low'
            ],
            'create_projects' => [
                'name' => 'Create Projects',
                'description' => 'Create new projects in the system',
                'risk_level' => 'medium'
            ],
            'edit_projects' => [
                'name' => 'Edit Projects',
                'description' => 'Modify existing project information',
                'risk_level' => 'medium'
            ],
            'manage_projects' => [
                'name' => 'Full Project Management',
                'description' => 'Complete project lifecycle management',
                'risk_level' => 'high'
            ],
            'manage_project_steps' => [
                'name' => 'Project Steps Management',
                'description' => 'Manage project milestones and workflow steps',
                'risk_level' => 'medium'
            ]
        ],
        'Data Management' => [
            'import_data' => [
                'name' => 'Data Import/Export',
                'description' => 'Import and export project data via CSV/Excel',
                'risk_level' => 'high'
            ],
            'manage_documents' => [
                'name' => 'Document Management',
                'description' => 'Upload, organize, and manage project documents',
                'risk_level' => 'medium'
            ],
            'manage_budgets' => [
                'name' => 'Budget Management',
                'description' => 'Manage project budgets and financial tracking',
                'risk_level' => 'high'
            ]
        ],
        'Community & Feedback' => [
            'manage_feedback' => [
                'name' => 'Community Feedback Management',
                'description' => 'Moderate and respond to citizen feedback',
                'risk_level' => 'medium'
            ]
        ],
        'Reports & Analytics' => [
            'view_reports' => [
                'name' => 'Generate Reports',
                'description' => 'Generate and view system reports and analytics',
                'risk_level' => 'low'
            ],
            'view_activity_logs' => [
                'name' => 'Activity Logs',
                'description' => 'View system activity and audit logs',
                'risk_level' => 'medium'
            ]
        ],
        'System Administration' => [
            'manage_users' => [
                'name' => 'User Management',
                'description' => 'Create, modify, and manage administrative users',
                'risk_level' => 'critical'
            ],
            'manage_roles' => [
                'name' => 'Role & Permission Management',
                'description' => 'Assign and manage user roles and permissions',
                'risk_level' => 'critical'
            ],
            'system_settings' => [
                'name' => 'System Configuration',
                'description' => 'Configure system-wide settings and parameters',
                'risk_level' => 'critical'
            ]
        ]
    ];

    /**
     * Initialize RBAC system with database connection
     */
    public static function init($pdo_connection) {
        self::$pdo = $pdo_connection;
        self::createRequiredTables();
    }

    /**
     * Create required tables if they don't exist
     */
    private static function createRequiredTables() {
        try {
            // Add email_verified column to admins table if it doesn't exist
            $stmt = self::$pdo->query("SHOW COLUMNS FROM admins LIKE 'email_verified'");
            if ($stmt->rowCount() == 0) {
                self::$pdo->exec("ALTER TABLE admins ADD COLUMN email_verified TINYINT(1) DEFAULT 0 AFTER is_active");
            }

            // Check if admin_permissions table exists
            $stmt = self::$pdo->query("SHOW TABLES LIKE 'admin_permissions'");
            if ($stmt->rowCount() == 0) {
                self::$pdo->exec("
                    CREATE TABLE admin_permissions (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        admin_id INT NOT NULL,
                        permission_key VARCHAR(100) NOT NULL,
                        granted_by INT NOT NULL,
                        is_active TINYINT(1) DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        UNIQUE KEY unique_admin_permission (admin_id, permission_key),
                        FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE,
                        FOREIGN KEY (granted_by) REFERENCES admins(id) ON DELETE CASCADE,
                        INDEX idx_admin_id (admin_id),
                        INDEX idx_permission_key (permission_key),
                        INDEX idx_is_active (is_active)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                ");
            }

            // Check if security_logs table exists
            $stmt = self::$pdo->query("SHOW TABLES LIKE 'security_logs'");
            if ($stmt->rowCount() == 0) {
                self::$pdo->exec("
                    CREATE TABLE security_logs (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        event_type VARCHAR(50) NOT NULL,
                        admin_id INT NULL,
                        ip_address VARCHAR(45) NULL,
                        user_agent TEXT NULL,
                        details JSON NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL,
                        INDEX idx_event_type (event_type),
                        INDEX idx_admin_id (admin_id),
                        INDEX idx_created_at (created_at)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                ");
            }
        } catch (PDOException $e) {
            error_log("RBAC table creation error: " . $e->getMessage());
        }
    }

    /**
     * Check if current admin has permission for a specific page
     */
    public static function checkPagePermission($page_filename) {
        if (!self::isAuthenticated()) {
            return false;
        }

        $current_admin = self::getCurrentAdmin();

        // Super admin bypasses all permission checks
        if ($current_admin['role'] === 'super_admin') {
            return true;
        }

        // Always allow dashboard and profile access
        if (in_array($page_filename, ['index.php', 'dashboard.php', 'profile.php'])) {
            return true;
        }

        // Get required permission for this page
        $required_permission = self::getPagePermission($page_filename);

        if (!$required_permission) {
            // If no permission defined, deny access
            self::logSecurityEvent('undefined_page_access', $current_admin['id'], [
                'page' => $page_filename,
                'url' => $_SERVER['REQUEST_URI'] ?? null
            ]);
            return false;
        }

        // Check if admin has this permission
        return self::hasPermission($current_admin['id'], $required_permission);
    }

    /**
     * Get required permission for a page
     */
    private static function getPagePermission($page_filename) {
        return self::$page_permissions[$page_filename] ?? null;
    }

    /**
     * Check if admin has specific permission with caching
     */
    public static function hasPermission($admin_id, $permission_key) {
        // Check cache first
        $cache_key = "perm_{$admin_id}_{$permission_key}";
        $cached_result = self::getCachedPermission($cache_key);

        if ($cached_result !== null) {
            return $cached_result;
        }

        try {
            $stmt = self::$pdo->prepare("
                SELECT COUNT(*) 
                FROM admin_permissions 
                WHERE admin_id = ? AND permission_key = ? AND is_active = 1
            ");
            $stmt->execute([$admin_id, $permission_key]);
            $has_permission = $stmt->fetchColumn() > 0;

            // Cache result
            self::setCachedPermission($cache_key, $has_permission);

            return $has_permission;
        } catch (PDOException $e) {
            self::logSecurityEvent('permission_check_error', $admin_id, [
                'permission' => $permission_key,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    /**
     * Get all permissions for an admin
     */
    public static function getAdminPermissions($admin_id) {
        try {
            $stmt = self::$pdo->prepare("
                SELECT permission_key 
                FROM admin_permissions 
                WHERE admin_id = ? AND is_active = 1
            ");
            $stmt->execute([$admin_id]);
            $permissions = $stmt->fetchAll(PDO::FETCH_COLUMN);

            return $permissions;
        } catch (PDOException $e) {
            self::logSecurityEvent('get_permissions_error', $admin_id, [
                'error' => $e->getMessage()
            ]);
            return [];
        }
    }

    /**
     * Get allowed pages for current admin (for sidebar generation)
     */
    public static function getAllowedPages() {
        if (!self::isAuthenticated()) {
            return [];
        }

        $current_admin = self::getCurrentAdmin();

        // Super admin gets all pages
        if ($current_admin['role'] === 'super_admin') {
            return array_keys(self::$page_permissions);
        }

        $admin_permissions = self::getAdminPermissions($current_admin['id']);
        $allowed_pages = ['index.php', 'dashboard.php', 'profile.php']; // Always allowed

        foreach (self::$page_permissions as $page => $permission) {
            if (in_array($permission, $admin_permissions)) {
                $allowed_pages[] = $page;
            }
        }

        return $allowed_pages;
    }

    /**
     * Update admin permissions with complete role management
     */
    public static function updateAdminPermissions($admin_id, $permissions, $granted_by) {
        if (!is_array($permissions)) {
            $permissions = [];
        }

        // Validate permissions
        $valid_permissions = [];
        foreach ($permissions as $permission) {
            if (self::isValidPermission($permission)) {
                $valid_permissions[] = $permission;
            }
        }

        try {
            self::$pdo->beginTransaction();

            // Get current permissions for comparison
            $stmt = self::$pdo->prepare("
                SELECT permission_key 
                FROM admin_permissions 
                WHERE admin_id = ? AND is_active = 1
            ");
            $stmt->execute([$admin_id]);
            $current_permissions = $stmt->fetchAll(PDO::FETCH_COLUMN);

            // Permissions to add (new permissions not currently held)
            $permissions_to_add = array_diff($valid_permissions, $current_permissions);

            // Permissions to remove (current permissions not in new list)
            $permissions_to_remove = array_diff($current_permissions, $valid_permissions);

            // Remove permissions by deleting records completely
            if (!empty($permissions_to_remove)) {
                $placeholders = str_repeat('?,', count($permissions_to_remove) - 1) . '?';
                $stmt = self::$pdo->prepare("
                    DELETE FROM admin_permissions 
                    WHERE admin_id = ? AND permission_key IN ($placeholders)
                ");
                $stmt->execute(array_merge([$admin_id], $permissions_to_remove));
            }

            // Add new permissions
            if (!empty($permissions_to_add)) {
                $stmt = self::$pdo->prepare("
                    INSERT INTO admin_permissions (admin_id, permission_key, granted_by, is_active, created_at, updated_at)
                    VALUES (?, ?, ?, 1, NOW(), NOW())
                ");

                foreach ($permissions_to_add as $permission) {
                    $stmt->execute([$admin_id, $permission, $granted_by]);
                }
            }

            // Update granted_by for existing permissions that remain
            $existing_permissions = array_intersect($valid_permissions, $current_permissions);
            if (!empty($existing_permissions)) {
                $placeholders = str_repeat('?,', count($existing_permissions) - 1) . '?';
                $stmt = self::$pdo->prepare("
                    UPDATE admin_permissions 
                    SET granted_by = ?, updated_at = NOW() 
                    WHERE admin_id = ? AND permission_key IN ($placeholders) AND is_active = 1
                ");
                $stmt->execute(array_merge([$granted_by, $admin_id], $existing_permissions));
            }

            self::$pdo->commit();

            // Clear ALL cache for this admin
            self::clearPermissionCache($admin_id);

            // Force immediate session refresh if it's the current user
            if (isset($_SESSION['admin_id']) && $_SESSION['admin_id'] == $admin_id) {
                $_SESSION['permissions'] = $valid_permissions;
                unset($_SESSION['sidebar_permissions']);
                unset($_SESSION['allowed_pages']);
            }

            // Log the change
            self::logSecurityEvent('permissions_updated', $granted_by, [
                'target_admin' => $admin_id,
                'final_permissions' => $valid_permissions,
                'permissions_added' => $permissions_to_add,
                'permissions_removed' => $permissions_to_remove,
                'total_permissions' => count($valid_permissions)
            ]);

            return [
                'success' => true, 
                'message' => 'Permissions updated successfully',
                'added' => count($permissions_to_add),
                'removed' => count($permissions_to_remove),
                'total' => count($valid_permissions)
            ];

        } catch (PDOException $e) {
            self::$pdo->rollBack();
            self::logSecurityEvent('permission_update_error', $granted_by, [
                'target_admin' => $admin_id,
                'error' => $e->getMessage()
            ]);
            return [
                'success' => false, 
                'message' => 'Failed to update permissions: ' . $e->getMessage()
            ];
        }
    }

    /**
     * Validate permission key
     */
    private static function isValidPermission($permission_key) {
        $all_permissions = [];
        foreach (self::$permission_categories as $category => $permissions) {
            $all_permissions = array_merge($all_permissions, array_keys($permissions));
        }
        return in_array($permission_key, $all_permissions);
    }

    /**
     * Get permission categories for management interface
     */
    public static function getPermissionCategories() {
        return self::$permission_categories;
    }

    /**
     * Clear permission cache for admin
     */
    private static function clearPermissionCache($admin_id) {
        $keys_to_remove = [];
        foreach (self::$permissions_cache as $key => $value) {
            if (strpos($key, "perm_{$admin_id}_") === 0 || 
                strpos($key, "admin_perms_{$admin_id}") === 0 ||
                $key === "admin_perms_{$admin_id}") {
                $keys_to_remove[] = $key;
            }
        }
        
        foreach ($keys_to_remove as $key) {
            unset(self::$permissions_cache[$key]);
        }
    }

    /**
     * Cache management methods
     */
    private static function getCachedPermission($key) {
        if (isset(self::$permissions_cache[$key])) {
            $cached = self::$permissions_cache[$key];
            if (time() - $cached['timestamp'] < self::$cache_ttl) {
                return $cached['value'];
            }
            unset(self::$permissions_cache[$key]);
        }
        return null;
    }

    private static function setCachedPermission($key, $value) {
        self::$permissions_cache[$key] = [
            'value' => $value,
            'timestamp' => time()
        ];
    }

    /**
     * Enhanced security logging
     */
    private static function logSecurityEvent($event_type, $admin_id, $details = []) {
        try {
            $stmt = self::$pdo->prepare("
                INSERT INTO security_logs (event_type, admin_id, ip_address, user_agent, details, created_at)
                VALUES (?, ?, ?, ?, ?, NOW())
            ");
            $stmt->execute([
                $event_type,
                $admin_id,
                $_SERVER['REMOTE_ADDR'] ?? null,
                $_SERVER['HTTP_USER_AGENT'] ?? null,
                json_encode($details)
            ]);
        } catch (PDOException $e) {
            error_log("RBAC Security Log Error: " . $e->getMessage());
        }
    }

    /**
     * Require page permission or redirect to 404
     */
    public static function requirePagePermission($page_filename) {
        if (!self::checkPagePermission($page_filename)) {
            $current_admin = self::getCurrentAdmin();
            self::logSecurityEvent('unauthorized_access_attempt', $current_admin['id'] ?? null, [
                'page' => $page_filename,
                'url' => $_SERVER['REQUEST_URI'] ?? null,
                'referrer' => $_SERVER['HTTP_REFERER'] ?? null
            ]);

            header('Location: ../404.php');
            exit;
        }
    }

    /**
     * Authentication helpers
     */
    private static function isAuthenticated() {
        return isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;
    }

    public static function getCurrentAdmin() {
        if (!self::isAuthenticated()) {
            return null;
        }

        return [
            'id' => $_SESSION['admin_id'],
            'email' => $_SESSION['admin_email'],
            'name' => $_SESSION['admin_name'],
            'role' => $_SESSION['admin_role']
        ];
    }

    /**
     * Get permission risk level for security assessment
     */
    public static function getPermissionRiskLevel($permission_key) {
        foreach (self::$permission_categories as $category => $permissions) {
            if (isset($permissions[$permission_key])) {
                return $permissions[$permission_key]['risk_level'] ?? 'medium';
            }
        }
        return 'unknown';
    }

    /**
     * Get admin permission summary for reporting
     */
    public static function getAdminPermissionSummary($admin_id) {
        $permissions = self::getAdminPermissions($admin_id);
        $summary = [
            'total_permissions' => count($permissions),
            'risk_levels' => [
                'low' => 0,
                'medium' => 0,
                'high' => 0,
                'critical' => 0
            ],
            'categories' => []
        ];

        foreach ($permissions as $permission) {
            $risk_level = self::getPermissionRiskLevel($permission);
            if (isset($summary['risk_levels'][$risk_level])) {
                $summary['risk_levels'][$risk_level]++;
            }

            // Find category
            foreach (self::$permission_categories as $category => $perms) {
                if (isset($perms[$permission])) {
                    if (!isset($summary['categories'][$category])) {
                        $summary['categories'][$category] = 0;
                    }
                    $summary['categories'][$category]++;
                    break;
                }
            }
        }

        return $summary;
    }

    /**
     * Get all available permissions in the system
     */
    public static function getAllPermissions() {
        $all_permissions = [];
        foreach (self::$permission_categories as $category => $permissions) {
            foreach ($permissions as $key => $details) {
                $all_permissions[] = [
                    'name' => $key,
                    'category' => $category,
                    'description' => $details['description'],
                    'risk_level' => $details['risk_level']
                ];
            }
        }
        return $all_permissions;
    }

    /**
     * Grant a specific permission to an admin
     */
    public static function grantPermission($admin_id, $permission_key, $granted_by = null) {
        try {
            // Check if permission already exists
            $stmt = self::$pdo->prepare("
                SELECT id FROM admin_permissions 
                WHERE admin_id = ? AND permission_key = ?
            ");
            $stmt->execute([$admin_id, $permission_key]);

            if ($stmt->fetch()) {
                // Update existing permission to active
                $stmt = self::$pdo->prepare("
                    UPDATE admin_permissions 
                    SET is_active = 1, granted_by = ?, updated_at = NOW() 
                    WHERE admin_id = ? AND permission_key = ?
                ");
                $stmt->execute([$granted_by, $admin_id, $permission_key]);
            } else {
                // Insert new permission
                $stmt = self::$pdo->prepare("
                    INSERT INTO admin_permissions 
                    (admin_id, permission_key, is_active, granted_by, created_at, updated_at)
                    VALUES (?, ?, 1, ?, NOW(), NOW())
                ");
                $stmt->execute([$admin_id, $permission_key, $granted_by]);
            }

            self::logSecurityEvent('permission_granted', $granted_by, [
                'admin_id' => $admin_id,
                'permission_key' => $permission_key
            ]);

            // Clear cache
            self::clearPermissionCache($admin_id);

            return ['success' => true, 'message' => 'Permission granted successfully'];

        } catch (PDOException $e) {
            error_log("Grant permission error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to grant permission'];
        }
    }

    /**
     * Revoke a specific permission from an admin
     */
    public static function revokePermission($admin_id, $permission_key, $revoked_by = null) {
        try {
            $stmt = self::$pdo->prepare("
                DELETE FROM admin_permissions 
                WHERE admin_id = ? AND permission_key = ?
            ");
            $result = $stmt->execute([$admin_id, $permission_key]);

            if ($result && $stmt->rowCount() > 0) {
                self::logSecurityEvent('permission_revoked', $revoked_by, [
                    'admin_id' => $admin_id,
                    'permission_key' => $permission_key
                ]);

                // Clear cache
                self::clearPermissionCache($admin_id);

                return ['success' => true, 'message' => 'Permission revoked successfully'];
            } else {
                return ['success' => false, 'message' => 'Permission not found or already revoked'];
            }

        } catch (PDOException $e) {
            error_log("Revoke permission error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to revoke permission'];
        }
    }

    /**
     * Force session refresh for specific admin
     */
    public static function forceSessionRefresh($admin_id) {
        try {
            // If it's the current user, refresh their session immediately
            if (isset($_SESSION['admin_id']) && $_SESSION['admin_id'] == $admin_id) {
                // Get fresh permissions from database
                $permissions = self::getAdminPermissions($admin_id);
                $_SESSION['permissions'] = $permissions;

                // Clear any cached sidebar data
                unset($_SESSION['sidebar_permissions']);
                unset($_SESSION['allowed_pages']);
                unset($_SESSION['permission_cache']);

                // Also refresh role information
                $stmt = self::$pdo->prepare("SELECT role FROM admins WHERE id = ?");
                $stmt->execute([$admin_id]);
                $role = $stmt->fetchColumn();
                if ($role) {
                    $_SESSION['admin_role'] = $role;
                }

                return true;
            }

            return false;
        } catch (Exception $e) {
            error_log("Force session refresh error: " . $e->getMessage());
            return false;
        }
    }
}

// Initialize RBAC system
if (isset($pdo)) {
    SecureRBAC::init($pdo);
}

/**
 * Convenience functions for backward compatibility and ease of use
 */
function checkPagePermission($page_filename) {
    return SecureRBAC::checkPagePermission($page_filename);
}

function has_permission($permission_key) {
    return hasPagePermission($permission_key);
}

function requirePagePermission($page_filename) {
    SecureRBAC::requirePagePermission($page_filename);
}

function getAllowedPages() {
    return SecureRBAC::getAllowedPages();
}

function hasPagePermission($permission_key) {
    if (!isset($_SESSION['admin_id'])) {
        return false;
    }

    $admin = SecureRBAC::getCurrentAdmin();
    if ($admin && $admin['role'] === 'super_admin') {
        return true;
    }

    // First try session permissions (faster)
    if (isset($_SESSION['permissions']) && in_array($permission_key, $_SESSION['permissions'])) {
        return true;
    }

    // Fallback to database check
    $result = SecureRBAC::hasPermission($_SESSION['admin_id'], $permission_key);

    // If permission found in DB but not in session, update session
    if ($result && isset($_SESSION['permissions']) && !in_array($permission_key, $_SESSION['permissions'])) {
        $_SESSION['permissions'][] = $permission_key;
    }

    return $result;
}

function getPermissionCategories() {
    return SecureRBAC::getPermissionCategories();
}

function updateAdminPermissions($admin_id, $permissions, $granted_by) {
    return SecureRBAC::updateAdminPermissions($admin_id, $permissions, $granted_by);
}

function getAdminPermissions($admin_id) {
    return SecureRBAC::getAdminPermissions($admin_id);
}

function getAdminPermissionSummary($admin_id) {
    return SecureRBAC::getAdminPermissionSummary($admin_id);
}

function refresh_admin_permissions($admin_id) {
    // Update session if it's the current user
    if (isset($_SESSION['admin_id']) && $_SESSION['admin_id'] == $admin_id) {
        $_SESSION['permissions'] = SecureRBAC::getAdminPermissions($admin_id);
    }

    return SecureRBAC::getAdminPermissions($admin_id);
}

function force_session_refresh($admin_id) {
    return SecureRBAC::forceSessionRefresh($admin_id);
}