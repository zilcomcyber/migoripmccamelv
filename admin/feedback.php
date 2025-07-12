<?php
require_once 'includes/pageSecurity.php';
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';
require_once '../includes/rbac.php';

require_role('admin');
$current_admin = get_current_admin();

$page_title = "Feedback Management";

// Check if user has permission to manage feedback
if (!hasPagePermission('manage_feedback')) {
    header('Location: index.php');
    exit;
}

// Handle AJAX requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax'])) {
    header('Content-Type: application/json');
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        echo json_encode(['success' => false, 'message' => 'Invalid security token']);
        exit;
    }
    $action = $_POST['action'] ?? '';
    $result = ['success' => false, 'message' => 'Invalid action'];
    switch ($action) {
        case 'respond':
            $result = respond_to_feedback($_POST);
            break;
        case 'approve':
            $result = approve_feedback($_POST['feedback_id']);
            break;
        case 'reject':
            $result = reject_feedback($_POST['feedback_id']);
            break;
        case 'delete':
            $result = delete_feedback($_POST['feedback_id']);
            break;
        case 'grievance':
            $result = mark_as_grievance($_POST['feedback_id']);
            break;
        case 'bulk_action':
            $result = handle_bulk_action($_POST);
            break;
    }
    echo json_encode($result);
    exit;
}

// Get filter parameters with pagination
$status = $_GET['status'] ?? '';
$project_id = $_GET['project_id'] ?? '';
$search = $_GET['search'] ?? '';
$page = max(1, intval($_GET['page'] ?? 1));
$per_page = 20;

$filters = array_filter([
    'status' => $status,
    'project_id' => $project_id,
    'search' => $search,
    'page' => $page,
    'per_page' => $per_page
]);

// Get comments with pagination
function get_comments_with_pagination($filters = []) {
    global $pdo, $current_admin;
    $page = $filters['page'] ?? 1;
    $per_page = $filters['per_page'] ?? 20;
    $offset = ($page - 1) * $per_page;

    $sql = "SELECT f.*, p.project_name, p.department_id, d.name as department_name,
                   a.name as responded_by_name,
                   parent.citizen_name as parent_author
            FROM feedback f
            JOIN projects p ON f.project_id = p.id
            JOIN departments d ON p.department_id = d.id
            LEFT JOIN admins a ON f.responded_by = a.id
            LEFT JOIN feedback parent ON f.parent_comment_id = parent.id
            WHERE 1=1";

    $count_sql = "SELECT COUNT(DISTINCT f.id) FROM feedback f
                  JOIN projects p ON f.project_id = p.id
                  JOIN departments d ON p.department_id = d.id
                  WHERE 1=1";

    $params = [];

    if (!empty($filters['status'])) {
        $sql .= " AND f.status = ?";
        $count_sql .= " AND f.status = ?";
        $params[] = $filters['status'];
    }

    if (!empty($filters['project_id'])) {
        $sql .= " AND f.project_id = ?";
        $count_sql .= " AND f.project_id = ?";
        $params[] = $filters['project_id'];
    }

    if (!empty($filters['search'])) {
        $sql .= " AND (f.subject LIKE ? OR f.message LIKE ? OR f.citizen_name LIKE ?)";
        $count_sql .= " AND (f.subject LIKE ? OR f.message LIKE ? OR f.citizen_name LIKE ?)";
        $search_param = '%' . $filters['search'] . '%';
        $params[] = $search_param;
        $params[] = $search_param;
        $params[] = $search_param;
    }

    // Non-super admins can only see feedback for their own projects
    if ($current_admin['role'] !== 'super_admin') {
        $sql .= " AND p.created_by = ?";
        $count_sql .= " AND p.created_by = ?";
        $params[] = $current_admin['id'];
    }

    $count_stmt = $pdo->prepare($count_sql);
    $count_stmt->execute($params);
    $total = $count_stmt->fetchColumn();

    $sql .= " ORDER BY f.created_at DESC LIMIT ? OFFSET ?";
    $params[] = $per_page;
    $params[] = $offset;

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $data = $stmt->fetchAll();

    return [
        'data' => $data,
        'total' => $total,
        'page' => $page,
        'per_page' => $per_page,
        'total_pages' => ceil($total / $per_page)
    ];
}

// Get prepared responses
function get_prepared_responses() {
    global $pdo;
    $stmt = $pdo->query("SELECT * FROM prepared_responses WHERE is_active = 1 ORDER BY category, name");
    return $stmt->fetchAll();
}

// Response functions
function respond_to_feedback($data) {
    global $pdo, $current_admin;
    try {
        $feedback_id = intval($data['feedback_id']);
        $response = sanitize_input($data['admin_response']);
        if (empty($response)) {
            return ['success' => false, 'message' => 'Response cannot be empty'];
        }
        $sql = "UPDATE feedback SET 
                admin_response = ?, 
                status = 'responded', 
                responded_by = ?, 
                updated_at = NOW() 
                WHERE id = ?";
        $stmt = $pdo->prepare($sql);
        if ($stmt->execute([$response, $current_admin['id'], $feedback_id])) {
            return ['success' => true, 'message' => 'Response sent successfully'];
        }
        return ['success' => false, 'message' => 'Failed to save response'];
    } catch (Exception $e) {
        error_log("Feedback response error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred while saving the response'];
    }
}

function approve_feedback($feedback_id) {
    global $pdo;
    try {
        $stmt = $pdo->prepare("UPDATE feedback SET status = 'approved', updated_at = NOW() WHERE id = ?");
        if ($stmt->execute([intval($feedback_id)])) {
            return ['success' => true, 'message' => 'Comment approved'];
        }
        return ['success' => false, 'message' => 'Failed to approve comment'];
    } catch (Exception $e) {
        return ['success' => false, 'message' => 'Error approving comment'];
    }
}

function reject_feedback($feedback_id) {
    global $pdo;
    try {
        $stmt = $pdo->prepare("UPDATE feedback SET status = 'rejected', updated_at = NOW() WHERE id = ?");
        if ($stmt->execute([intval($feedback_id)])) {
            return ['success' => true, 'message' => 'Comment rejected'];
        }
        return ['success' => false, 'message' => 'Failed to reject comment'];
    } catch (Exception $e) {
        return ['success' => false, 'message' => 'Error rejecting comment'];
    }
}

function delete_feedback($feedback_id) {
    global $pdo;
    try {
        $stmt = $pdo->prepare("DELETE FROM feedback WHERE id = ?");
        if ($stmt->execute([intval($feedback_id)])) {
            return ['success' => true, 'message' => 'Comment deleted'];
        }
        return ['success' => false, 'message' => 'Failed to delete comment'];
    } catch (Exception $e) {
        return ['success' => false, 'message' => 'Error deleting comment'];
    }
}

function mark_as_grievance($feedback_id) {
    global $pdo;
    try {
        $stmt = $pdo->prepare("UPDATE feedback SET status = 'grievance', updated_at = NOW() WHERE id = ?");
        if ($stmt->execute([intval($feedback_id)])) {
            return ['success' => true, 'message' => 'Marked as grievance'];
        }
        return ['success' => false, 'message' => 'Failed to mark as grievance'];
    } catch (Exception $e) {
        return ['success' => false, 'message' => 'Error marking as grievance'];
    }
}

function handle_bulk_action($data) {
    $action = $data['bulk_action'] ?? '';
    $selected_ids = $data['selected_comments'] ?? [];

    if (empty($action) || empty($selected_ids)) {
        return ['success' => false, 'message' => 'No action or comments selected'];
    }

    $success_count = 0;
    foreach ($selected_ids as $id) {
        $result = false;
        switch ($action) {
            case 'approve':
                $result = approve_feedback($id);
                break;
            case 'reject':
                $result = reject_feedback($id);
                break;
            case 'delete':
                $result = delete_feedback($id);
                break;
            case 'grievance':
                $result = mark_as_grievance($id);
                break;
        }
        if ($result['success']) $success_count++;
    }

    return ['success' => true, 'message' => "$success_count comments processed"];
}

// Get feedback statistics
try {
    $stmt = $pdo->query("SELECT COUNT(*) FROM feedback");
    $total_feedback = $stmt->fetchColumn();

    $stmt = $pdo->query("SELECT COUNT(*) FROM feedback WHERE status = 'pending'");
    $pending_feedback = $stmt->fetchColumn();
} catch (Exception $e) {
    error_log("Feedback page error: " . $e->getMessage());
    $total_feedback = 0;
    $pending_feedback = 0;
}

// Get comments with pagination
$feedback_data = get_comments_with_pagination($filters);
$feedback_list = $feedback_data['data'];
$total_feedback = $feedback_data['total'];
$total_pages = $feedback_data['total_pages'];
$projects = get_projects();
$prepared_responses = get_prepared_responses();

include 'includes/adminHeader.php';
?>

<style>
/* Mobile-first responsive design */
.feedback-container {
    background: #f8f9fa;
}

.main-card {
    background: #fffef7 !important;
    border-radius: 8px;
    border: 1px solid #e5e7eb;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    margin: 0;
    padding: 0;
}

.card-header {
    background: #fffef7 !important;
    padding: 1rem;
    border-bottom: 1px solid #e5e7eb;
    border-radius: 8px 8px 0 0;
}

.card-content {
    background: #fffef7 !important;
    padding: 1rem;
}

.stats-header {
    background: #fffef7 !important;
    border-radius: 8px;
    border: 1px solid #e5e7eb;
    padding: 1rem;
    margin-bottom: 1rem;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 0.75rem;
    margin-bottom: 1rem;
}

.stat-card {
    background: #f8f9fa;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    padding: 0.75rem;
    text-align: center;
}

.filter-section {
    background: white;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    padding: 0.75rem;
    margin-bottom: 1rem;
}

.comment-item {
    background: #f8f9fa;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    padding: 0.75rem;
    margin-bottom: 0.75rem;
}

.comment-avatar {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    background: #e5e7eb;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #374151;
    font-weight: bold;
    font-size: 0.875rem;
}

.status-badge {
    padding: 0.25rem 0.5rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 500;
}

.status-pending { background: #fef3c7; color: #92400e; }
.status-approved { background: #d1fae5; color: #065f46; }
.status-rejected { background: #fee2e2; color: #991b1b; }
.status-responded { background: #dbeafe; color: #1e40af; }
.status-grievance { background: #f3f4f6; color: #374151; }

.quick-action-btn {
    padding: 0.25rem 0.5rem;
    font-size: 0.75rem;
    border-radius: 4px;
    border: 1px solid;
    cursor: pointer;
    margin-right: 0.25rem;
    margin-bottom: 0.25rem;
}

.btn-approve { background: #ecfdf5; color: #065f46; border-color: #a7f3d0; }
.btn-reject { background: #fef2f2; color: #991b1b; border-color: #fecaca; }
.btn-reply { background: #eff6ff; color: #1e40af; border-color: #bfdbfe; }
.btn-grievance { background: #f3f4f6; color: #374151; border-color: #d1d5db; }
.btn-delete { background: #fef2f2; color: #991b1b; border-color: #fecaca; }

.bulk-actions {
    background: #eff6ff;
    border: 1px solid #bfdbfe;
    border-radius: 6px;
    padding: 0.75rem;
    margin-bottom: 1rem;
}

@media (max-width: 768px) {
    .feedback-container {
        padding: 0.5rem;
    }
    
    .card-header, .card-content {
        padding: 0.75rem;
    }
    
    .stats-grid {
        grid-template-columns: repeat(2, 1fr);
        gap: 0.5rem;
    }
    
    .stat-card {
        padding: 0.5rem;
    }
    
    .comment-item {
        padding: 0.5rem;
    }
    
    .filter-section {
        padding: 0.5rem;
    }
}
</style>

<div class="feedback-container">
    <!-- Breadcrumb -->
    <div class="mb-6">
        <nav class="flex text-sm" aria-label="Breadcrumb">
            <ol class="flex items-center space-x-2">
                <li>
                    <a href="index.php" class="text-blue-600 hover:text-blue-800 font-medium">
                        <i class="fas fa-home mr-1"></i> Dashboard
                    </a>
                </li>
                <li class="text-gray-400">/</li>
                <li class="text-gray-600 font-medium">Feedback Management</li>
            </ol>
        </nav>
    </div>

    <!-- Page Header -->
    <div class="stats-header">
        <div class="flex flex-col md:flex-row items-start justify-between">
            <div>
                <h1 class="text-xl font-bold text-gray-900 mb-1">Feedback Management</h1>
                <p class="text-sm text-gray-600">Monitor and respond to community feedback</p>
                <?php if ($current_admin['role'] !== 'super_admin'): ?>
                    <p class="text-xs text-blue-600 mt-1">
                        <i class="fas fa-info-circle mr-1"></i>
                        You can only manage comments on projects you created
                    </p>
                <?php endif; ?>
            </div>
            <div class="text-center mt-2 md:mt-0">
                <div class="text-2xl font-bold text-blue-600"><?php echo number_format($total_feedback); ?></div>
                <div class="text-xs text-gray-600"><?php echo $pending_feedback; ?> pending</div>
            </div>
        </div>
    </div>

    <!-- Main Card -->
    <div class="main-card">
        <!-- Status Overview -->
        <div class="card-content">
            <?php
            // Get status counts
            try {
                $status_counts = [];
                $where_clause = "WHERE 1=1";
                $params = [];
                
                if ($current_admin['role'] !== 'super_admin') {
                    $where_clause .= " AND p.created_by = ?";
                    $params[] = $current_admin['id'];
                }
                
                $stmt = $pdo->prepare("
                    SELECT f.status, COUNT(*) as count
                    FROM feedback f
                    JOIN projects p ON f.project_id = p.id
                    $where_clause
                    GROUP BY f.status
                ");
                $stmt->execute($params);
                $status_counts = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);
            } catch (Exception $e) {
                error_log("Status counts error: " . $e->getMessage());
                $status_counts = [];
            }
            ?>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="text-lg font-bold text-yellow-600"><?php echo $status_counts['pending'] ?? 0; ?></div>
                    <div class="text-xs text-yellow-700">Pending</div>
                </div>
                <div class="stat-card">
                    <div class="text-lg font-bold text-green-600"><?php echo $status_counts['approved'] ?? 0; ?></div>
                    <div class="text-xs text-green-700">Approved</div>
                </div>
                <div class="stat-card">
                    <div class="text-lg font-bold text-blue-600"><?php echo $status_counts['responded'] ?? 0; ?></div>
                    <div class="text-xs text-blue-700">Responded</div>
                </div>
                <div class="stat-card">
                    <div class="text-lg font-bold text-red-600"><?php echo $status_counts['rejected'] ?? 0; ?></div>
                    <div class="text-xs text-red-700">Rejected</div>
                </div>
                <div class="stat-card">
                    <div class="text-lg font-bold text-gray-600"><?php echo $status_counts['grievance'] ?? 0; ?></div>
                    <div class="text-xs text-gray-700">Grievances</div>
                </div>
            </div>

            <!-- Filters -->
            <div class="filter-section">
                <form method="GET" class="space-y-3">
                    <div class="grid grid-cols-1 md:grid-cols-4 gap-3">
                        <input type="text" name="search" value="<?php echo htmlspecialchars($search); ?>" 
                               placeholder="Search comments..." 
                               class="px-3 py-2 border border-gray-300 rounded text-sm focus:ring-blue-500 focus:border-blue-500">

                        <select name="status" class="px-3 py-2 border border-gray-300 rounded text-sm focus:ring-blue-500 focus:border-blue-500">
                            <option value="">All Statuses</option>
                            <option value="pending" <?php echo $status === 'pending' ? 'selected' : ''; ?>>Pending</option>
                            <option value="approved" <?php echo $status === 'approved' ? 'selected' : ''; ?>>Approved</option>
                            <option value="rejected" <?php echo $status === 'rejected' ? 'selected' : ''; ?>>Rejected</option>
                            <option value="responded" <?php echo $status === 'responded' ? 'selected' : ''; ?>>Responded</option>
                            <option value="grievance" <?php echo $status === 'grievance' ? 'selected' : ''; ?>>Grievance</option>
                        </select>

                        <select name="project_id" class="px-3 py-2 border border-gray-300 rounded text-sm focus:ring-blue-500 focus:border-blue-500">
                            <option value="">All Projects</option>
                            <?php foreach ($projects as $proj): ?>
                                <option value="<?php echo $proj['id']; ?>" <?php echo $project_id == $proj['id'] ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($proj['project_name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>

                        <div class="flex space-x-2">
                            <button type="submit" class="flex-1 px-3 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700">
                                Filter
                            </button>
                            <a href="feedback.php" class="px-3 py-2 border border-gray-300 text-sm rounded text-gray-700 hover:bg-gray-50">
                                Clear
                            </a>
                        </div>
                    </div>
                </form>
            </div>

            <!-- Bulk Actions -->
            <div id="bulkActionsBar" class="hidden bulk-actions">
                <form id="bulkActionForm">
                    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                        <div class="flex items-center space-x-3">
                            <label class="flex items-center">
                                <input type="checkbox" id="selectAll" class="mr-2">
                                <span class="text-sm font-medium">Select All</span>
                            </label>
                            <span id="selectedCount" class="text-sm text-gray-600">0 selected</span>
                        </div>
                        <div class="flex items-center space-x-2">
                            <select name="bulk_action" id="bulkActionSelect" class="px-3 py-2 border border-gray-300 rounded text-sm">
                                <option value="">Choose Action</option>
                                <option value="approve">Approve</option>
                                <option value="reject">Reject</option>
                                <option value="grievance">Mark as Grievance</option>
                                <option value="delete">Delete</option>
                            </select>
                            <button type="submit" class="px-3 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700">
                                Apply
                            </button>
                            <button type="button" onclick="toggleBulkActions()" class="px-3 py-2 border border-gray-300 text-sm rounded text-gray-700 hover:bg-gray-50">
                                Cancel
                            </button>
                        </div>
                    </div>
                </form>
            </div>

            <!-- Actions Header -->
            <div class="flex justify-between items-center mb-3">
                <h3 class="font-semibold text-gray-900">
                    <?php echo number_format($total_feedback); ?> Comment<?php echo $total_feedback !== 1 ? 's' : ''; ?>
                </h3>
                <button onclick="toggleBulkActions()" class="px-3 py-2 border border-gray-300 text-sm rounded text-gray-700 hover:bg-gray-50">
                    <i class="fas fa-tasks mr-1"></i>Bulk Actions
                </button>
            </div>

            <!-- Comments List -->
            <?php if (empty($feedback_list)): ?>
                <div class="comment-item text-center py-8">
                    <i class="fas fa-comments text-3xl text-gray-400 mb-2"></i>
                    <h3 class="text-lg font-medium text-gray-900 mb-1">No Comments Found</h3>
                    <p class="text-gray-600">No comments match your current filters.</p>
                </div>
            <?php else: ?>
                <?php foreach ($feedback_list as $comment): ?>
                    <div class="comment-item" data-comment-id="<?php echo $comment['id']; ?>">
                        <div class="flex items-start space-x-3">
                            <!-- Checkbox -->
                            <label class="bulk-checkbox hidden">
                                <input type="checkbox" name="comment_ids[]" value="<?php echo $comment['id']; ?>" class="comment-checkbox">
                            </label>

                            <!-- Avatar -->
                            <div class="comment-avatar">
                                <?php echo strtoupper(substr($comment['citizen_name'] ?: 'A', 0, 1)); ?>
                            </div>

                            <!-- Content -->
                            <div class="flex-1 min-w-0">
                                <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-2">
                                    <div>
                                        <span class="font-medium text-gray-900 text-sm">
                                            <?php echo htmlspecialchars($comment['citizen_name'] ?: 'Anonymous'); ?>
                                        </span>
                                        <?php if ($comment['parent_comment_id']): ?>
                                            <span class="text-xs text-gray-500 ml-2">
                                                → replying to <?php echo htmlspecialchars($comment['parent_author'] ?: 'comment'); ?>
                                            </span>
                                        <?php endif; ?>
                                    </div>
                                    <div class="flex items-center space-x-2 mt-1 sm:mt-0">
                                        <span class="status-badge status-<?php echo $comment['status']; ?>">
                                            <?php echo ucfirst($comment['status']); ?>
                                        </span>
                                        <span class="text-xs text-gray-500">
                                            <?php echo date('M j', strtotime($comment['created_at'])); ?>
                                        </span>
                                    </div>
                                </div>

                                <div class="mb-2">
                                    <div class="text-sm text-gray-600 mb-1">
                                        <strong>Project:</strong> <?php echo htmlspecialchars($comment['project_name']); ?>
                                    </div>
                                    <button onclick="toggleCommentContent(<?php echo $comment['id']; ?>)" 
                                            class="text-sm text-blue-600 hover:text-blue-800">
                                        View Comment
                                    </button>
                                    <div id="content-<?php echo $comment['id']; ?>" class="hidden mt-2 p-3 bg-gray-50 rounded">
                                        <div class="text-sm text-gray-900">
                                            <?php echo nl2br(htmlspecialchars($comment['message'])); ?>
                                        </div>
                                        <?php if (!empty($comment['admin_response'])): ?>
                                            <div class="mt-3 p-3 bg-green-50 border border-green-200 rounded">
                                                <div class="flex items-center mb-1">
                                                    <i class="fas fa-user-shield text-green-600 mr-1"></i>
                                                    <span class="text-sm font-medium text-green-800">Admin Response</span>
                                                </div>
                                                <div class="text-sm text-green-900">
                                                    <?php echo nl2br(htmlspecialchars($comment['admin_response'])); ?>
                                                </div>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                </div>

                                <!-- Quick Actions -->
                                <div class="flex flex-wrap gap-1">
                                    <?php if ($comment['status'] === 'pending'): ?>
                                        <button onclick="quickAction('approve', <?php echo $comment['id']; ?>)" class="quick-action-btn btn-approve">
                                            Approve
                                        </button>
                                        <button onclick="quickAction('reject', <?php echo $comment['id']; ?>)" class="quick-action-btn btn-reject">
                                            Reject
                                        </button>
                                    <?php endif; ?>
                                    <button onclick="showResponseModal(<?php echo $comment['id']; ?>, '<?php echo htmlspecialchars($comment['citizen_name'], ENT_QUOTES); ?>')" 
                                            class="quick-action-btn btn-reply">
                                        Reply
                                    </button>
                                    <button onclick="quickAction('grievance', <?php echo $comment['id']; ?>)" class="quick-action-btn btn-grievance">
                                        Grievance
                                    </button>
                                    <button onclick="quickAction('delete', <?php echo $comment['id']; ?>)" class="quick-action-btn btn-delete">
                                        Delete
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>

                <!-- Pagination -->
                <?php if ($total_pages > 1): ?>
                    <div class="flex items-center justify-between mt-4 pt-3 border-t border-gray-200">
                        <div class="text-sm text-gray-700">
                            Showing <?php echo (($page - 1) * $per_page) + 1; ?> to 
                            <?php echo min($page * $per_page, $total_feedback); ?> of 
                            <?php echo number_format($total_feedback); ?> results
                        </div>
                        <nav class="flex items-center space-x-1">
                            <?php if ($page > 1): ?>
                                <a href="?<?php echo http_build_query(array_merge($_GET, ['page' => $page - 1])); ?>" 
                                   class="px-3 py-1 border border-gray-300 rounded text-sm text-gray-700 hover:bg-gray-50">‹</a>
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
                                   class="px-3 py-1 border border-gray-300 rounded text-sm text-gray-700 hover:bg-gray-50">›</a>
                            <?php endif; ?>
                        </nav>
                    </div>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Response Modal -->
<div id="responseModal" class="hidden fixed inset-0 bg-gray-600 bg-opacity-50 z-50 overflow-y-auto">
    <div class="flex items-center justify-center min-h-screen px-4">
        <div class="bg-white rounded-lg shadow-xl max-w-md w-full">
            <div class="p-4">
                <div class="flex items-center justify-between mb-3">
                    <h3 class="text-lg font-semibold text-gray-900">Reply to Comment</h3>
                    <button onclick="closeResponseModal()" class="text-gray-400 hover:text-gray-600">
                        <i class="fas fa-times"></i>
                    </button>
                </div>

                <form id="responseForm">
                    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                    <input type="hidden" name="action" value="respond">
                    <input type="hidden" name="feedback_id" id="responseCommentId">
                    <input type="hidden" name="ajax" value="1">

                    <div class="mb-3">
                        <p class="text-sm text-gray-600">
                            Replying to: <span id="responseCommentAuthor" class="font-medium"></span>
                        </p>
                    </div>

                    <!-- Quick Responses -->
                    <div class="mb-3">
                        <label class="block text-sm font-medium text-gray-700 mb-2">Quick Responses</label>
                        <div class="space-y-1 max-h-24 overflow-y-auto">
                            <?php foreach ($prepared_responses as $template): ?>
                                <div class="p-2 border border-gray-300 rounded text-xs cursor-pointer hover:bg-blue-50" 
                                     onclick="selectTemplate('<?php echo htmlspecialchars($template['content'], ENT_QUOTES); ?>')">
                                    <div class="font-medium"><?php echo htmlspecialchars($template['name']); ?></div>
                                    <div class="text-gray-500"><?php echo substr(htmlspecialchars($template['content']), 0, 50); ?>...</div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>

                    <div class="mb-3">
                        <label for="adminResponse" class="block text-sm font-medium text-gray-700 mb-1">Your Response</label>
                        <textarea name="admin_response" id="adminResponse" rows="3" required
                                  class="w-full px-3 py-2 border border-gray-300 rounded text-sm focus:ring-blue-500 focus:border-blue-500"
                                  placeholder="Type your response here..."></textarea>
                    </div>

                    <div class="flex justify-end space-x-2">
                        <button type="button" onclick="closeResponseModal()" 
                                class="px-3 py-2 border border-gray-300 rounded text-sm text-gray-700 hover:bg-gray-50">
                            Cancel
                        </button>
                        <button type="submit" 
                                class="px-3 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700">
                            Send Reply
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>

<script>
let bulkMode = false;

function toggleBulkActions() {
    bulkMode = !bulkMode;
    const bulkBar = document.getElementById('bulkActionsBar');
    const checkboxes = document.querySelectorAll('.bulk-checkbox');

    if (bulkMode) {
        bulkBar.classList.remove('hidden');
        checkboxes.forEach(cb => cb.classList.remove('hidden'));
    } else {
        bulkBar.classList.add('hidden');
        checkboxes.forEach(cb => cb.classList.add('hidden'));
        document.getElementById('selectAll').checked = false;
        document.querySelectorAll('.comment-checkbox').forEach(cb => cb.checked = false);
        updateSelectedCount();
    }
}

function toggleCommentContent(commentId) {
    const content = document.getElementById(`content-${commentId}`);
    content.classList.toggle('hidden');
}

function quickAction(action, commentId) {
    if (confirm(`Are you sure you want to ${action} this comment?`)) {
        const formData = new FormData();
        formData.append('action', action);
        formData.append('feedback_id', commentId);
        formData.append('csrf_token', '<?php echo generate_csrf_token(); ?>');
        formData.append('ajax', '1');

        fetch('feedback.php', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Error: ' + data.message);
            }
        });
    }
}

function showResponseModal(commentId, authorName) {
    document.getElementById('responseCommentId').value = commentId;
    document.getElementById('responseCommentAuthor').textContent = authorName;
    document.getElementById('adminResponse').value = '';
    document.getElementById('responseModal').classList.remove('hidden');
}

function closeResponseModal() {
    document.getElementById('responseModal').classList.add('hidden');
}

function selectTemplate(content) {
    document.getElementById('adminResponse').value = content;
}

// Select all functionality
document.getElementById('selectAll').addEventListener('change', function() {
    const checkboxes = document.querySelectorAll('.comment-checkbox');
    checkboxes.forEach(cb => cb.checked = this.checked);
    updateSelectedCount();
});

document.addEventListener('change', function(e) {
    if (e.target.classList.contains('comment-checkbox')) {
        updateSelectedCount();
    }
});

function updateSelectedCount() {
    const selected = document.querySelectorAll('.comment-checkbox:checked').length;
    document.getElementById('selectedCount').textContent = `${selected} selected`;
}

// Bulk actions form
document.getElementById('bulkActionForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const action = document.getElementById('bulkActionSelect').value;
    const selected = Array.from(document.querySelectorAll('.comment-checkbox:checked')).map(cb => cb.value);

    if (!action || selected.length === 0) {
        alert('Please select an action and at least one comment');
        return;
    }

    if (confirm(`Are you sure you want to ${action} ${selected.length} comment(s)?`)) {
        const formData = new FormData();
        formData.append('action', 'bulk_action');
        formData.append('bulk_action', action);
        formData.append('csrf_token', '<?php echo generate_csrf_token(); ?>');
        formData.append('ajax', '1');
        selected.forEach(id => formData.append('selected_comments[]', id));

        fetch('feedback.php', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Error: ' + data.message);
            }
        });
    }
});

// Response form submission
document.getElementById('responseForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const formData = new FormData(this);

    fetch('feedback.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            closeResponseModal();
            location.reload();
        } else {
            alert('Error: ' + data.message);
        }
    });
});
</script>

<?php include 'includes/adminFooter.php'; ?>
