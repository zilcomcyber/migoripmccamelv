<?php
require_once 'includes/pageSecurity.php';
require_once '../includes/functions.php';
require_once '../includes/rbac.php';
$page_title = "Project Management";
require_once '../config.php';
require_once '../includes/auth.php';

// Authentication and permission checking
$current_admin = get_current_admin();
log_activity('projects_page_access', 'Accessed projects management page', $current_admin['id']);

// Handle AJAX requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax'])) {
    header('Content-Type: application/json');
    
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        echo json_encode(['success' => false, 'message' => 'Invalid security token']);
        exit;
    }

    $action = $_POST['action'] ?? '';
    $result = ['success' => false, 'message' => 'Invalid action'];

    try {
        switch ($action) {
            case 'search_projects':
                $search_term = $_POST['search'] ?? '';
                $result = search_projects($search_term);
                break;
                
            // Maintain all existing action cases
            case 'update_status':
                // Existing status update logic
                break;
            case 'update_visibility':
                // Existing visibility update logic
                break;
            case 'delete_project':
                // Existing delete logic
                break;
            // Other cases...
        }
    } catch (Exception $e) {
        error_log("Action $action failed: " . $e->getMessage());
        $result = ['success' => false, 'message' => 'Action failed'];
    }

    echo json_encode($result);
    exit;
}

function search_projects($search_term) {
    global $pdo, $current_admin;
    
    $sql = "SELECT id, project_name, status, project_year 
            FROM projects 
            WHERE (project_name LIKE :search OR description LIKE :search)";
    
    $params = [':search' => '%' . $search_term . '%'];
    
    if ($current_admin['role'] !== 'super_admin') {
        $sql .= " AND created_by = :admin_id";
        $params[':admin_id'] = $current_admin['id'];
    }
    
    $sql .= " ORDER BY project_name LIMIT 10";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    
    return [
        'success' => true,
        'projects' => $stmt->fetchAll(PDO::FETCH_ASSOC)
    ];
}

// Maintain all existing filter and pagination logic
$status = $_GET['status'] ?? '';
$department = $_GET['department'] ?? '';
$search = $_GET['search'] ?? '';
$visibility = $_GET['visibility'] ?? '';
$year = $_GET['year'] ?? '';
$page = max(1, intval($_GET['page'] ?? 1));
$per_page = 20;

$filters = array_filter([
    'status' => $status,
    'department' => $department,
    'search' => $search,
    'visibility' => $visibility,
    'year' => $year,
    'page' => $page,
    'per_page' => $per_page
]);

// Role-based filtering
if ($current_admin['role'] !== 'super_admin') {
    $filters['created_by'] = $current_admin['id'];
}

// Get projects data (maintain existing function)
$projects_data = get_all_projects($filters, true, $per_page);
$projects = $projects_data['projects'] ?? [];
$total_projects = $projects_data['total'] ?? 0;
$total_pages = $projects_data['total_pages'] ?? 1;

// Get filter options (maintain existing)
$departments = get_departments();
$years = get_project_years();

include 'includes/adminHeader.php';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="<?php echo generate_csrf_token(); ?>">
    <title><?php echo htmlspecialchars($page_title); ?></title>
    <!-- Your existing CSS includes -->
</head>
<body>
<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
    <!-- Maintain existing header content -->
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Projects</h1>
            <p class="mt-1 text-sm text-gray-600">
                <?php if ($current_admin['role'] === 'super_admin'): ?>
                    Manage all system projects
                <?php else: ?>
                    Manage your projects
                <?php endif; ?>
            </p>
        </div>
        <div class="mt-4 sm:mt-0 flex space-x-3">
            <?php if (has_permission('create_projects')): ?>
                <a href="createProject.php" class="inline-flex items-center px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700">
                    <i class="fas fa-plus mr-2"></i>New Project
                </a>
            <?php endif; ?>
        </div>
    </div>

    <!-- Enhanced search and filters -->
    <div class="bg-white rounded-lg shadow-sm border border-gray-200 mb-6">
        <div class="p-4">
            <form method="GET" class="space-y-4">
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div class="relative">
                        <input type="text" id="live_search" placeholder="Search projects..." 
                               class="w-full px-4 py-2 border rounded-lg focus:ring-blue-500 focus:border-blue-500"
                               autocomplete="off"
                               value="<?php echo htmlspecialchars($search); ?>">
                        <input type="hidden" name="search" id="search_input" value="<?php echo htmlspecialchars($search); ?>">
                        <div id="search_results" class="absolute z-10 w-full mt-1 bg-white border border-gray-300 rounded-lg shadow-lg hidden overflow-auto max-h-60">
                            <!-- Results will appear here -->
                        </div>
                    </div>

                    <!-- Maintain existing filter controls -->
                    <select name="status" class="px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-blue-500 focus:border-blue-500">
                        <option value="">All Statuses</option>
                        <option value="planning" <?php echo $status === 'planning' ? 'selected' : ''; ?>>Planning</option>
                        <option value="ongoing" <?php echo $status === 'ongoing' ? 'selected' : ''; ?>>Ongoing</option>
                        <option value="completed" <?php echo $status === 'completed' ? 'selected' : ''; ?>>Completed</option>
                        <option value="suspended" <?php echo $status === 'suspended' ? 'selected' : ''; ?>>Suspended</option>
                        <option value="cancelled" <?php echo $status === 'cancelled' ? 'selected' : ''; ?>>Cancelled</option>
                    </select>

                    <select name="visibility" class="px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-blue-500 focus:border-blue-500">
                        <option value="">All Visibility</option>
                        <option value="private" <?php echo $visibility === 'private' ? 'selected' : ''; ?>>Private</option>
                        <option value="published" <?php echo $visibility === 'published' ? 'selected' : ''; ?>>Published</option>
                    </select>

                    <div class="flex space-x-2">
                        <button type="submit" class="flex-1 px-3 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700">
                            Filter
                        </button>
                        <a href="projects.php" class="px-3 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 hover:bg-gray-50">
                            Clear
                        </a>
                    </div>
                </div>
            </form>
        </div>
    </div>

    <!-- Maintain existing projects list -->
    <div class="bg-white rounded-lg shadow-sm border border-gray-200">
        <div class="p-4 border-b border-gray-200">
            <h3 class="text-lg font-semibold text-gray-900">
                <?php echo number_format($total_projects); ?> Project<?php echo $total_projects !== 1 ? 's' : ''; ?>
            </h3>
        </div>

        <?php if (empty($projects)): ?>
            <div class="p-12 text-center">
                <i class="fas fa-project-diagram text-4xl text-gray-400 mb-4"></i>
                <h3 class="text-lg font-medium text-gray-900 mb-2">No Projects Found</h3>
                <p class="text-gray-600 mb-4">
                    <?php if ($current_admin['role'] === 'super_admin'): ?>
                        No projects match your current filters.
                    <?php else: ?>
                        You haven't created any projects yet.
                    <?php endif; ?>
                </p>
                <?php if (has_permission('create_projects')): ?>
                    <a href="createProject.php" class="inline-flex items-center px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700">
                        <i class="fas fa-plus mr-2"></i>Create Your First Project
                    </a>
                <?php endif; ?>
            </div>
        <?php else: ?>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Progress</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Visibility</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        <?php foreach ($projects as $project): ?>
                            <tr class="hover:bg-gray-50">
                                <td class="px-4 py-4">
                                    <div class="flex items-center">
                                        <div>
                                            <div class="text-sm font-medium text-gray-900">
                                                <?php echo htmlspecialchars($project['project_name']); ?>
                                            </div>
                                            <div class="text-sm text-gray-500">
                                                Year: <?php echo $project['project_year']; ?>
                                            </div>
                                        </div>
                                    </div>
                                </td>
                                <td class="px-4 py-4 whitespace-nowrap">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?php echo get_status_badge_class($project['status']); ?>">
                                        <?php echo ucfirst($project['status']); ?>
                                    </span>
                                </td>
                                <td class="px-4 py-4 whitespace-nowrap">
                                    <div class="flex items-center">
                                        <div class="w-16 bg-gray-200 rounded-full h-2 mr-3">
                                            <div class="h-2 rounded-full <?php echo get_progress_color_class($project['progress_percentage']); ?>" 
                                                 style="width: <?php echo $project['progress_percentage']; ?>%"></div>
                                        </div>
                                        <span class="text-sm text-gray-900"><?php echo $project['progress_percentage']; ?>%</span>
                                    </div>
                                </td>
                                <td class="px-4 py-4 whitespace-nowrap">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?php echo $project['visibility'] === 'published' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'; ?>">
                                        <?php echo $project['visibility'] === 'published' ? 'Public' : 'Private'; ?>
                                    </span>
                                </td>
                                <td class="px-4 py-4 whitespace-nowrap text-sm font-medium">
                                    <a href="manageProject.php?id=<?php echo $project['id']; ?>" 
                                       class="inline-flex items-center px-3 py-1 border border-transparent text-sm leading-5 font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                                        Manage
                                    </a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <!-- Maintain existing pagination -->
            <?php if ($total_pages > 1): ?>
                <div class="px-4 py-3 border-t border-gray-200 bg-gray-50">
                    <div class="flex flex-col sm:flex-row items-center justify-between">
                        <div class="text-sm text-gray-700 mb-2 sm:mb-0">
                            Showing <?php echo (($page - 1) * $per_page) + 1; ?> to 
                            <?php echo min($page * $per_page, $total_projects); ?> of 
                            <?php echo number_format($total_projects); ?> results
                        </div>
                        <nav class="flex items-center space-x-1">
                            <?php if ($page > 1): ?>
                                <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => $page - 1])); ?>" 
                                   class="px-3 py-1 border border-gray-300 rounded text-sm text-gray-700 hover:bg-gray-50">
                                    ‹
                                </a>
                            <?php endif; ?>

                            <?php 
                            $start_page = max(1, $page - 2);
                            $end_page = min($total_pages, $page + 2);
                            for ($i = $start_page; $i <= $end_page; $i++): 
                            ?>
                                <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => $i])); ?>" 
                                   class="px-3 py-1 border <?php echo $i === $page ? 'border-blue-500 bg-blue-50 text-blue-600' : 'border-gray-300 text-gray-700 hover:bg-gray-50'; ?> rounded text-sm">
                                    <?php echo $i; ?>
                                </a>
                            <?php endfor; ?>

                            <?php if ($page < $total_pages): ?>
                                <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => $page + 1])); ?>" 
                                   class="px-3 py-1 border border-gray-300 rounded text-sm text-gray-700 hover:bg-gray-50">
                                    ›
                                </a>
                            <?php endif; ?>
                        </nav>
                    </div>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('live_search');
    const searchResults = document.getElementById('search_results');
    const hiddenSearchInput = document.getElementById('search_input');
    let abortController = null;
    let searchTimeout = null;

    // Initialize search field
    if (searchInput && hiddenSearchInput) {
        searchInput.value = hiddenSearchInput.value;
    }

    // Perform the search
    async function performSearch(term) {
        if (abortController) {
            abortController.abort();
        }
        
        abortController = new AbortController();
        
        try {
            const formData = new FormData();
            formData.append('action', 'search_projects');
            formData.append('search', term);
            formData.append('csrf_token', document.querySelector('meta[name="csrf-token"]').content);
            formData.append('ajax', '1');

            const response = await fetch('projects.php', {
                method: 'POST',
                body: formData,
                signal: abortController.signal
            });

            if (!response.ok) throw new Error('Network response was not ok');
            
            const data = await response.json();
            
            if (!data.success) throw new Error(data.message || 'Search failed');
            
            return data.projects || [];
        } catch (error) {
            if (error.name !== 'AbortError') {
                console.error('Search error:', error);
                return null; // Indicates error
            }
            return []; // Request was aborted
        }
    }

    // Display search results
    function displayResults(projects) {
        if (!searchResults) return;
        
        if (projects === null) {
            searchResults.innerHTML = `
                <div class="p-3 text-red-600">
                    <i class="fas fa-exclamation-triangle mr-2"></i>
                    Search service unavailable. Please try again.
                </div>`;
            searchResults.classList.remove('hidden');
            return;
        }

        if (projects.length === 0) {
            searchResults.innerHTML = `
                <div class="p-3 text-gray-500">
                    <i class="fas fa-info-circle mr-2"></i>
                    No matching projects found
                </div>`;
            searchResults.classList.remove('hidden');
            return;
        }

        searchResults.innerHTML = projects.map(project => `
            <div class="p-3 hover:bg-blue-50 cursor-pointer border-b border-gray-100 search-result"
                 data-id="${project.id}" 
                 data-name="${escapeHtml(project.project_name)}">
                <div class="font-semibold">${escapeHtml(project.project_name)}</div>
                <div class="text-sm text-gray-600">
                    ${escapeHtml(project.status)} • ${escapeHtml(project.project_year)}
                </div>
            </div>
        `).join('');

        // Add click handlers
        document.querySelectorAll('.search-result').forEach(result => {
            result.addEventListener('click', function() {
                if (searchInput) searchInput.value = this.dataset.name;
                if (hiddenSearchInput) hiddenSearchInput.value = this.dataset.name;
                if (searchResults) searchResults.classList.add('hidden');
                
                // Submit the form to apply the filter
                const form = document.querySelector('form[method="GET"]');
                if (form) form.submit();
            });
        });

        searchResults.classList.remove('hidden');
    }

    // Helper function to escape HTML
    function escapeHtml(text) {
        return text?.toString()
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;') || '';
    }

    // Handle input events
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            const term = this.value.trim();
            
            clearTimeout(searchTimeout);
            
            if (!searchResults) return;
            
            if (term.length < 2) {
                searchResults.classList.add('hidden');
                return;
            }
            
            searchTimeout = setTimeout(async () => {
                searchResults.innerHTML = `
                    <div class="p-3 text-gray-500">
                        <i class="fas fa-spinner fa-spin mr-2"></i>
                        Searching...
                    </div>`;
                searchResults.classList.remove('hidden');
                
                const results = await performSearch(term);
                displayResults(results);
            }, 300);
        });
    }

    // Close results when clicking outside
    document.addEventListener('click', function(e) {
        if (searchResults && searchInput &&
            !searchInput.contains(e.target) && 
            !searchResults.contains(e.target)) {
            searchResults.classList.add('hidden');
        }
    });
});
</script>

<?php include 'includes/adminFooter.php'; ?>