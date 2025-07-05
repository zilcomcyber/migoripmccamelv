<?php
require_once 'includes/pageSecurity.php';
$page_title = "Community Feedback Management";
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

// Check if user has permission to manage feedback
if (!hasPagePermission('manage_feedback')) {
    header('Location: index.php');
    exit;
}

$current_admin = get_current_admin();

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
    global $pdo;
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
    if (!has_role('super_admin') && !has_permission('view_all_projects')) {
        $sql .= " AND p.created_by = " . (int)$current_admin['id'];
        $count_sql .= " AND p.created_by = " . (int)$current_admin['id'];
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

// Pagination settings
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$per_page = 20;
$offset = ($page - 1) * $per_page;

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
.comment-row { border-bottom: 1px solid #e5e7eb; transition: background-color 0.2s; }
.comment-row:hover { background-color: #f9fafb; }
.comment-avatar { width: 32px; height: 32px; border-radius: 50%; background: #6b7280; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 14px; }
.status-badge { font-size: 11px; padding: 2px 8px; border-radius: 12px; font-weight: 500; }
.status-pending { background: #fef3c7; color: #92400e; }
.status-approved { background: #d1fae5; color: #065f46; }
.status-rejected { background: #fee2e2; color: #991b1b; }
.status-responded { background: #dbeafe; color: #1e40af; }
.status-grievance { background: #f3f4f6; color: #374151; }
.quick-actions { display: none; }
.comment-row:hover .quick-actions { display: flex; }
.response-template { border: 1px solid #d1d5db; border-radius: 6px; padding: 8px; margin: 4px 0; cursor: pointer; transition: all 0.2s; }
.response-template:hover { border-color: #3b82f6; background: #eff6ff; }
.response-template.selected { border-color: #3b82f6; background: #dbeafe; }
@media (max-width: 768px) {
    .desktop-only { display: none !important; }
    .mobile-stack { flex-direction: column !important; gap: 8px !important; }
    .comment-content { font-size: 14px; }
    .quick-actions { display: flex !important; }
}
</style>

<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
    <!-- Header -->
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Community Feedback</h1>
            <p class="mt-1 text-sm text-gray-600">Manage citizen feedback and comments</p>
        </div>
        <div class="mt-4 sm:mt-0 flex space-x-3">
            <button onclick="toggleBulkActions()" class="inline-flex items-center px-3 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                <i class="fas fa-tasks mr-2"></i>Bulk Actions
            </button>
        </div>
    </div>

    <!-- Filters -->
    <div class="bg-white rounded-lg shadow-sm border border-gray-200 mb-6">
        <div class="p-4">
            <form method="GET" class="space-y-4">
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <input type="text" name="search" value="<?php echo htmlspecialchars($search); ?>" 
                           placeholder="Search comments..." 
                           class="px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-blue-500 focus:border-blue-500">

                    <select name="status" class="px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-blue-500 focus:border-blue-500">
                        <option value="">All Statuses</option>
                        <option value="pending" <?php echo $status === 'pending' ? 'selected' : ''; ?>>Pending</option>
                        <option value="approved" <?php echo $status === 'approved' ? 'selected' : ''; ?>>Approved</option>
                        <option value="rejected" <?php echo $status === 'rejected' ? 'selected' : ''; ?>>Rejected</option>
                        <option value="responded" <?php echo $status === 'responded' ? 'selected' : ''; ?>>Responded</option>
                        <option value="grievance" <?php echo $status === 'grievance' ? 'selected' : ''; ?>>Grievance</option>
                    </select>

                    <select name="project_id" class="px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-blue-500 focus:border-blue-500">
                        <option value="">All Projects</option>
                        <?php foreach ($projects as $proj): ?>
                            <option value="<?php echo $proj['id']; ?>" <?php echo $project_id == $proj['id'] ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($proj['project_name']); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>

                    <div class="flex space-x-2">
                        <button type="submit" class="flex-1 px-3 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700">
                            Filter
                        </button>
                        <a href="feedback.php" class="px-3 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 hover:bg-gray-50">
                            Clear
                        </a>
                    </div>
                </div>
            </form>
        </div>
    </div>

    <!-- Bulk Actions Bar (Hidden by default) -->
    <div id="bulkActionsBar" class="hidden bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
        <form id="bulkActionForm">
            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div class="flex items-center space-x-4">
                    <label class="flex items-center">
                        <input type="checkbox" id="selectAll" class="mr-2">
                        <span class="text-sm font-medium">Select All</span>
                    </label>
                    <span id="selectedCount" class="text-sm text-gray-600">0 selected</span>
                </div>
                <div class="flex items-center space-x-2">
                    <select name="bulk_action" id="bulkActionSelect" class="px-3 py-2 border border-gray-300 rounded-md text-sm">
                        <option value="">Choose Action</option>
                        <option value="approve">Approve</option>
                        <option value="reject">Reject</option>
                        <option value="grievance">Mark as Grievance</option>
                        <option value="delete">Delete</option>
                    </select>
                    <button type="submit" class="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700">
                        Apply
                    </button>
                </div>
            </div>
        </form>
    </div>

    <!-- Comments List -->
    <div class="bg-white rounded-lg shadow-sm border border-gray-200">
        <div class="p-4 border-b border-gray-200">
            <h3 class="text-lg font-semibold text-gray-900">
                <?php echo number_format($total_feedback); ?> Comment<?php echo $total_feedback !== 1 ? 's' : ''; ?>
            </h3>
        </div>

        <?php if (empty($feedback_list)): ?>
            <div class="p-12 text-center">
                <i class="fas fa-comments text-4xl text-gray-400 mb-4"></i>
                <h3 class="text-lg font-medium text-gray-900 mb-2">No Comments Found</h3>
                <p class="text-gray-600">No comments match your current filters.</p>
            </div>
        <?php else: ?>
            <div class="divide-y divide-gray-200">
                <?php foreach ($feedback_list as $comment): ?>
                    <div class="comment-row p-4" data-comment-id="<?php echo $comment['id']; ?>">
                        <div class="flex items-start space-x-3">
                            <!-- Checkbox for bulk actions -->
                            <label class="bulk-checkbox hidden">
                                <input type="checkbox" name="comment_ids[]" value="<?php echo $comment['id']; ?>" class="comment-checkbox">
                            </label>

                            <!-- Avatar -->
                            <div class="comment-avatar">
                                <?php echo strtoupper(substr($comment['citizen_name'] ?: 'A', 0, 1)); ?>
                            </div>

                            <!-- Comment Content -->
                            <div class="flex-1 min-w-0">
                                <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mobile-stack">
                                    <div class="flex items-center space-x-2">
                                        <span class="font-medium text-gray-900">
                                            <?php echo htmlspecialchars($comment['citizen_name'] ?: 'Anonymous'); ?>
                                        </span>
                                        <?php if ($comment['parent_comment_id']): ?>
                                            <span class="text-xs text-gray-500">
                                                → replying to <?php echo htmlspecialchars($comment['parent_author'] ?: 'comment'); ?>
                                            </span>
                                        <?php endif; ?>
                                    </div>

                                    <div class="flex items-center space-x-2">
                                        <span class="status-badge status-<?php echo $comment['status']; ?>">
                                            <?php echo ucfirst($comment['status']); ?>
                                        </span>
                                        <span class="text-xs text-gray-500 desktop-only">
                                            <?php echo date('M j, Y', strtotime($comment['created_at'])); ?>
                                        </span>
                                    </div>
                                </div>

                                <div class="mt-2">
                                    <div class="text-sm text-gray-600 mb-2">
                                        <strong>Project:</strong> <?php echo htmlspecialchars($comment['project_name']); ?>
                                    </div>

                                    <button onclick="toggleCommentContent(<?php echo $comment['id']; ?>)" 
                                            class="text-sm text-blue-600 hover:text-blue-800 font-medium">
                                        View Comment
                                    </button>

                                    <div id="content-<?php echo $comment['id']; ?>" class="hidden mt-2 p-3 bg-gray-50 rounded-md">
                                        <div class="text-sm text-gray-900 comment-content">
                                            <?php echo nl2br(htmlspecialchars($comment['message'])); ?>
                                        </div>

                                        <?php if (!empty($comment['admin_response'])): ?>
                                            <div class="mt-3 p-3 bg-green-50 border border-green-200 rounded-md">
                                                <div class="flex items-center mb-2">
                                                    <i class="fas fa-user-shield text-green-600 mr-2"></i>
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
                                <div class="quick-actions flex items-center space-x-2 mt-3">
                                    <?php if ($comment['status'] === 'pending'): ?>
                                        <button onclick="quickAction('approve', <?php echo $comment['id']; ?>)" 
                                                class="text-xs px-2 py-1 bg-green-100 text-green-700 rounded hover:bg-green-200">
                                            Approve
                                        </button>
                                        <button onclick="quickAction('reject', <?php echo $comment['id']; ?>)" 
                                                class="text-xs px-2 py-1 bg-red-100 text-red-700 rounded hover:bg-red-200">
                                            Reject
                                        </button>
                                    <?php endif; ?>

                                    <button onclick="showResponseModal(<?php echo $comment['id']; ?>, '<?php echo htmlspecialchars($comment['citizen_name'], ENT_QUOTES); ?>')" 
                                            class="text-xs px-2 py-1 bg-blue-100 text-blue-700 rounded hover:bg-blue-200">
                                        Reply
                                    </button>

                                    <button onclick="quickAction('grievance', <?php echo $comment['id']; ?>)" 
                                            class="text-xs px-2 py-1 bg-gray-100 text-gray-700 rounded hover:bg-gray-200">
                                        Grievance
                                    </button>

                                    <button onclick="quickAction('delete', <?php echo $comment['id']; ?>)" 
                                            class="text-xs px-2 py-1 bg-red-100 text-red-700 rounded hover:bg-red-200">
                                        Delete
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>

            <!-- Pagination -->
            <?php if ($total_pages > 1): ?>
                <div class="px-4 py-3 border-t border-gray-200 bg-gray-50">
                    <div class="flex items-center justify-between">
                        <div class="text-sm text-gray-700">
                            Showing <?php echo (($page - 1) * $per_page) + 1; ?> to 
                            <?php echo min($page * $per_page, $total_feedback); ?> of 
                            <?php echo number_format($total_feedback); ?> results
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

<!-- Response Modal -->
<div id="responseModal" class="hidden fixed inset-0 bg-gray-600 bg-opacity-50 z-50 overflow-y-auto">
    <div class="flex items-center justify-center min-h-screen px-4">
        <div class="bg-white rounded-lg shadow-xl max-w-md w-full max-h-[90vh] overflow-y-auto">
            <div class="p-6">
                <div class="flex items-center justify-between mb-4">
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

                    <div class="mb-4">
                        <p class="text-sm text-gray-600">
                            Replying to: <span id="responseCommentAuthor" class="font-medium"></span>
                        </p>
                    </div>

                    <!-- Quick Response Templates -->
                    <div class="mb-4">
                        <label class="block text-sm font-medium text-gray-700 mb-2">Quick Responses</label>
                        <div class="space-y-2 max-h-32 overflow-y-auto">
                            <?php foreach ($prepared_responses as $template): ?>
                                <div class="response-template" onclick="selectTemplate(this, '<?php echo htmlspecialchars($template['content'], ENT_QUOTES); ?>')">
                                    <input type="radio" name="template" value="<?php echo $template['id']; ?>" class="hidden">
                                    <div class="text-sm font-medium"><?php echo htmlspecialchars($template['name']); ?></div>
                                    <div class="text-xs text-gray-500 mt-1"><?php echo substr(htmlspecialchars($template['content']), 0, 80); ?>...</div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>

                    <div class="mb-4">
                        <label for="adminResponse" class="block text-sm font-medium text-gray-700 mb-2">Your Response</label>
                        <textarea name="admin_response" id="adminResponse" rows="4" required
                                  class="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                                  placeholder="Type your response here..."></textarea>
                    </div>

                    <div class="flex justify-end space-x-3">
                        <button type="button" onclick="closeResponseModal()" 
                                class="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50">
                            Cancel
                        </button>
                        <button type="submit" 
                                class="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700">
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

// Change the grievance action to grievance
function quickAction(action, commentId) {
    // Map the UI action to server action
    const serverAction = action === 'grievance' ? 'grievance' : action;

    if (confirm(`Are you sure you want to ${action} this comment?`)) {
        const formData = new FormData();
        formData.append('action', serverAction);  // Use the mapped action
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
    document.querySelectorAll('.response-template').forEach(t => t.classList.remove('selected'));
    document.getElementById('responseModal').classList.remove('hidden');
}

function closeResponseModal() {
    document.getElementById('responseModal').classList.add('hidden');
}

function selectTemplate(element, content) {
    document.querySelectorAll('.response-template').forEach(t => t.classList.remove('selected'));
    element.classList.add('selected');
    document.getElementById('adminResponse').value = content;
}

// Select all functionality
document.getElementById('selectAll').addEventListener('change', function() {
    const checkboxes = document.querySelectorAll('.comment-checkbox');
    checkboxes.forEach(cb => cb.checked = this.checked);
    updateSelectedCount();
});

// Individual checkbox functionality
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