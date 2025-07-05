<?php
require_once 'includes/pageSecurity.php';
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';
require_once '../includes/rbac.php';

// Require authentication and permission to manage documents
require_admin();
if (!has_permission('manage_documents')) {
    header('Location: index.php?error=access_denied');
    exit;
}

$current_admin = get_current_admin();

// Log access to document manager
log_activity('document_manager_access', 'Accessed document manager', $current_admin['id']);

// Document types for PMC Documents
$document_types = [
    "Project Approval Letter",
    "Tender Notice", 
    "Signed Contract Agreement",
    "Award Notification",
    "Site Visit Report",
    "Completion Certificate",
    "Tender Opening Minutes",
    "PMC Appointment Letter",
    "Budget Approval Form",
    "PMC Workplan",
    "Supervision Report",
    "Final Joint Inspection Report",
    "Other"
];

// Handle file upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'upload') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token';
    } else {
        $project_id = intval($_POST['project_id'] ?? 0);
        $document_type = sanitize_input($_POST['document_type'] ?? 'Other');
        $document_title = sanitize_input($_POST['document_title'] ?? '');
        $description = sanitize_input($_POST['description'] ?? '');
        
        // Check if admin can manage this project
        if ($project_id && ($current_admin['role'] === 'super_admin' || owns_project($project_id, $current_admin['id']))) {
            if (isset($_FILES['document']) && $_FILES['document']['error'] === UPLOAD_ERR_OK) {
                $upload_result = secure_file_upload($_FILES['document']);
                if ($upload_result['success']) {
                    // Save document info to database
                    try {
                        $stmt = $pdo->prepare("
                            INSERT INTO project_documents (project_id, document_type, document_title, description, filename, original_name, file_size, mime_type, uploaded_by, document_status, version_number, is_public)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 1, 1)
                        ");
                        $stmt->execute([
                            $project_id,
                            $document_type,
                            $document_title,
                            $description,
                            $upload_result['filename'],
                            $upload_result['original_name'],
                            $upload_result['file_size'],
                            $upload_result['mime_type'],
                            $current_admin['id']
                        ]);
                        
                        log_activity('document_uploaded', "Uploaded PMC document: $document_title ($document_type) for project #$project_id", $current_admin['id']);
                        $success = 'Document uploaded successfully';
                    } catch (Exception $e) {
                        error_log("Document upload error: " . $e->getMessage());
                        $error = 'Failed to save document information';
                    }
                } else {
                    $error = $upload_result['message'];
                }
            } else {
                $error = 'No file selected or upload failed';
            }
        } else {
            $error = 'Access denied or invalid project';
        }
    }
}

// Handle file deletion with history tracking
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token';
    } else {
        $document_id = intval($_POST['document_id'] ?? 0);
        $deletion_reason = sanitize_input($_POST['deletion_reason'] ?? 'Deleted via document manager');
        
        try {
            // Get document info and check permissions
            $stmt = $pdo->prepare("
                SELECT pd.*, p.created_by, p.project_name 
                FROM project_documents pd
                JOIN projects p ON pd.project_id = p.id
                WHERE pd.id = ? AND pd.document_status = 'active'
            ");
            $stmt->execute([$document_id]);
            $document = $stmt->fetch();
            
            if ($document && ($current_admin['role'] === 'super_admin' || $document['created_by'] == $current_admin['id'])) {
                $pdo->beginTransaction();
                
                // Create history entry
                $stmt = $pdo->prepare("
                    INSERT INTO project_documents (project_id, document_type, document_title, description, filename, original_name, file_size, mime_type, uploaded_by, created_at, document_status, original_document_id, deletion_reason, modified_by, modified_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'deleted', ?, ?, ?, NOW())
                ");
                $stmt->execute([
                    $document['project_id'], $document['document_type'], $document['document_title'],
                    $document['description'], $document['filename'], $document['original_name'],
                    $document['file_size'], $document['mime_type'], $document['uploaded_by'],
                    $document['created_at'], $document_id, $deletion_reason, $current_admin['id']
                ]);
                
                // Update original document status
                $stmt = $pdo->prepare("UPDATE project_documents SET document_status = 'deleted', deletion_reason = ?, modified_by = ?, modified_at = NOW() WHERE id = ?");
                $stmt->execute([$deletion_reason, $current_admin['id'], $document_id]);
                
                $pdo->commit();
                
                log_activity('document_deleted', "Deleted document: {$document['document_title']} from project: {$document['project_name']}", $current_admin['id']);
                $success = 'Document deleted successfully';
            } else {
                $error = 'Document not found or access denied';
            }
        } catch (Exception $e) {
            $pdo->rollBack();
            error_log("Document deletion error: " . $e->getMessage());
            $error = 'Failed to delete document';
        }
    }
}

// Get filter parameters and pagination
$selected_project = intval($_GET['project_id'] ?? 0);
$search = $_GET['search'] ?? '';
$page = max(1, intval($_GET['page'] ?? 1));
$per_page = 20;
$offset = ($page - 1) * $per_page;

// Get projects for search functionality (role-based)
$projects_sql = "SELECT id, project_name FROM projects";
$project_params = [];
if ($current_admin['role'] !== 'super_admin') {
    $projects_sql .= " WHERE created_by = ?";
    $project_params[] = $current_admin['id'];
}
$projects_sql .= " ORDER BY project_name";

$stmt = $pdo->prepare($projects_sql);
$stmt->execute($project_params);
$projects = $stmt->fetchAll();

// Get documents with pagination and role-based filtering
$documents_sql = "
    SELECT pd.*, p.project_name, a.name as uploader_name
    FROM project_documents pd
    JOIN projects p ON pd.project_id = p.id
    LEFT JOIN admins a ON pd.uploaded_by = a.id
    WHERE pd.document_status = 'active'
";

$count_sql = "
    SELECT COUNT(*) 
    FROM project_documents pd
    JOIN projects p ON pd.project_id = p.id
    WHERE 1=1
";

$doc_params = [];
$count_params = [];

// Role-based filtering
if ($current_admin['role'] !== 'super_admin') {
    $documents_sql .= " AND p.created_by = ?";
    $count_sql .= " AND p.created_by = ?";
    $doc_params[] = $current_admin['id'];
    $count_params[] = $current_admin['id'];
}

// Project filter
if ($selected_project) {
    $documents_sql .= " AND pd.project_id = ?";
    $count_sql .= " AND pd.project_id = ?";
    $doc_params[] = $selected_project;
    $count_params[] = $selected_project;
}

// Search filter
if (!empty($search)) {
    $search_term = '%' . $search . '%';
    $documents_sql .= " AND (pd.original_name LIKE ? OR p.project_name LIKE ?)";
    $count_sql .= " AND (pd.original_name LIKE ? OR p.project_name LIKE ?)";
    $doc_params[] = $search_term;
    $doc_params[] = $search_term;
    $count_params[] = $search_term;
    $count_params[] = $search_term;
}

// Get total count
$count_stmt = $pdo->prepare($count_sql);
$count_stmt->execute($count_params);
$total_documents = $count_stmt->fetchColumn();
$total_pages = ceil($total_documents / $per_page);

// Add ordering and pagination
$documents_sql .= " ORDER BY pd.created_at DESC LIMIT ? OFFSET ?";
$doc_params[] = $per_page;
$doc_params[] = $offset;

$stmt = $pdo->prepare($documents_sql);
$stmt->execute($doc_params);
$documents = $stmt->fetchAll();

$page_title = "Document Manager";
include 'includes/adminHeader.php';
?>

<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
    <!-- Header -->
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Document Manager</h1>
            <p class="mt-1 text-sm text-gray-600">
                <?php if ($current_admin['role'] === 'super_admin'): ?>
                    Upload and manage all project documents
                <?php else: ?>
                    Upload and manage documents for your projects
                <?php endif; ?>
            </p>
        </div>
    </div>

    <!-- Messages -->
    <?php if (isset($success)): ?>
        <div class="mb-6 bg-green-50 border-l-4 border-green-400 p-4">
            <p class="text-green-700"><?php echo htmlspecialchars($success); ?></p>
        </div>
    <?php endif; ?>

    <?php if (isset($error)): ?>
        <div class="mb-6 bg-red-50 border-l-4 border-red-400 p-4">
            <p class="text-red-700"><?php echo htmlspecialchars($error); ?></p>
        </div>
    <?php endif; ?>

    <!-- Upload Form -->
    <div class="bg-white rounded-lg shadow-sm border border-gray-200 mb-6">
        <div class="p-6 border-b border-gray-200">
            <h3 class="text-lg font-semibold text-gray-900">Upload Document</h3>
        </div>
        <div class="p-6">
            <form method="POST" enctype="multipart/form-data" class="space-y-4">
                <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                <input type="hidden" name="action" value="upload">
                <input type="hidden" name="project_id" id="project_id" value="">
                
                <!-- Project Search -->
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Project *</label>
                    <div class="relative">
                        <input type="text" id="project_search" placeholder="Search for a project..." 
                               class="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                               autocomplete="off">
                        <div id="project_results" class="absolute z-10 w-full bg-white border border-gray-300 rounded-md shadow-lg mt-1 max-h-60 overflow-y-auto hidden">
                            <!-- Search results will appear here -->
                        </div>
                    </div>
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Document Type *</label>
                    <select name="document_type" required class="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500">
                        <option value="">Select Document Type</option>
                        <?php foreach ($document_types as $type): ?>
                            <option value="<?php echo htmlspecialchars($type); ?>">
                                <?php echo htmlspecialchars($type); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Document Title *</label>
                    <input type="text" name="document_title" required 
                           class="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500">
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Description</label>
                    <textarea name="description" rows="3" 
                              class="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"></textarea>
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Document File *</label>
                    <input type="file" name="document" required 
                           accept=".pdf,.doc,.docx,.xls,.xlsx,.jpg,.jpeg,.png"
                           class="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500">
                    <p class="text-xs text-gray-500 mt-1">Supported formats: PDF, DOC, DOCX, XLS, XLSX, JPG, PNG (Max: 20MB)</p>
                </div>
                
                <button type="submit" class="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700">
                    <i class="fas fa-upload mr-2"></i>Upload Document
                </button>
            </form>
        </div>
    </div>

    <!-- Filter and Search -->
    <div class="bg-white rounded-lg shadow-sm border border-gray-200 mb-6">
        <div class="p-4">
            <form method="GET" class="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <input type="text" name="search" value="<?php echo htmlspecialchars($search); ?>" 
                       placeholder="Search documents..." 
                       class="px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-blue-500 focus:border-blue-500">
                
                <select name="project_id" class="px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-blue-500 focus:border-blue-500">
                    <option value="">All Projects</option>
                    <?php foreach ($projects as $project): ?>
                        <option value="<?php echo $project['id']; ?>" <?php echo $selected_project == $project['id'] ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($project['project_name']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
                
                <div class="flex space-x-2">
                    <button type="submit" class="flex-1 bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 text-sm">
                        Filter
                    </button>
                    <a href="documentManager.php" class="px-4 py-2 border border-gray-300 rounded-md text-sm text-gray-700 hover:bg-gray-50">
                        Clear
                    </a>
                </div>
            </form>
        </div>
    </div>

    <!-- Documents List -->
    <div class="bg-white rounded-lg shadow-sm border border-gray-200">
        <div class="p-4 border-b border-gray-200">
            <h3 class="text-lg font-semibold text-gray-900">
                Documents (<?php echo number_format($total_documents); ?>)
            </h3>
        </div>

        <?php if (empty($documents)): ?>
            <div class="p-12 text-center">
                <i class="fas fa-file-alt text-4xl text-gray-400 mb-4"></i>
                <h3 class="text-lg font-medium text-gray-900 mb-2">No Documents Found</h3>
                <p class="text-gray-600">
                    <?php if ($current_admin['role'] === 'super_admin'): ?>
                        No documents match your current filters.
                    <?php else: ?>
                        Upload your first document to get started.
                    <?php endif; ?>
                </p>
            </div>
        <?php else: ?>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Document</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Size</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Uploaded By</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        <?php foreach ($documents as $doc): ?>
                            <tr>
                                <td class="px-6 py-4">
                                    <div class="flex items-center">
                                        <i class="fas fa-file text-gray-400 mr-3"></i>
                                        <div>
                                            <div class="text-sm font-medium text-gray-900">
                                                <?php echo htmlspecialchars($doc['document_title'] ?? $doc['original_name']); ?>
                                            </div>
                                            <?php if ($doc['description']): ?>
                                                <div class="text-xs text-gray-500 mt-1">
                                                    <?php echo htmlspecialchars($doc['description']); ?>
                                                </div>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                </td>
                                <td class="px-6 py-4">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                        <?php echo htmlspecialchars($doc['document_type'] ?? 'Other'); ?>
                                    </span>
                                </td>
                                <td class="px-6 py-4 text-sm text-gray-900">
                                    <?php echo htmlspecialchars($doc['project_name']); ?>
                                </td>
                                <td class="px-6 py-4 text-sm text-gray-900">
                                    <?php echo format_bytes($doc['file_size']); ?>
                                </td>
                                <td class="px-6 py-4 text-sm text-gray-900">
                                    <?php echo htmlspecialchars($doc['uploader_name'] ?? 'Unknown'); ?>
                                </td>
                                <td class="px-6 py-4 text-sm text-gray-900">
                                    <?php echo date('M j, Y', strtotime($doc['created_at'])); ?>
                                </td>
                                <td class="px-6 py-4 text-sm font-medium">
                                    <div class="flex items-center space-x-2">
                                        <a href="../uploads/<?php echo $doc['filename']; ?>" 
                                           target="_blank" 
                                           class="text-blue-600 hover:text-blue-900">
                                            <i class="fas fa-download"></i>
                                        </a>
                                        <form method="POST" class="inline" onsubmit="return confirm('Are you sure you want to delete this document?')">
                                            <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                                            <input type="hidden" name="action" value="delete">
                                            <input type="hidden" name="document_id" value="<?php echo $doc['id']; ?>">
                                            <button type="submit" class="text-red-600 hover:text-red-900">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            <?php if ($total_pages > 1): ?>
                <div class="px-4 py-3 border-t border-gray-200 bg-gray-50">
                    <div class="flex items-center justify-between">
                        <div class="text-sm text-gray-700">
                            Showing <?php echo $offset + 1; ?> to 
                            <?php echo min($offset + $per_page, $total_documents); ?> of 
                            <?php echo number_format($total_documents); ?> results
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
    const projectSearch = document.getElementById('project_search');
    const projectResults = document.getElementById('project_results');
    const projectIdInput = document.getElementById('project_id');
    
    // Get projects from PHP
    const projects = <?php echo json_encode($projects); ?>;
    
    projectSearch.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase();
        
        if (searchTerm.length < 2) {
            projectResults.classList.add('hidden');
            projectIdInput.value = '';
            return;
        }
        
        const filteredProjects = projects.filter(project => 
            project.project_name.toLowerCase().includes(searchTerm)
        );
        
        if (filteredProjects.length === 0) {
            projectResults.innerHTML = '<div class="px-4 py-2 text-gray-500">No projects found</div>';
            projectResults.classList.remove('hidden');
            projectIdInput.value = '';
            return;
        }
        
        const resultsHTML = filteredProjects.map(project => `
            <div class="px-4 py-2 hover:bg-gray-100 cursor-pointer project-option" 
                 data-id="${project.id}" data-name="${project.project_name}">
                ${project.project_name}
            </div>
        `).join('');
        
        projectResults.innerHTML = resultsHTML;
        projectResults.classList.remove('hidden');
        
        // Add click handlers
        projectResults.querySelectorAll('.project-option').forEach(option => {
            option.addEventListener('click', function() {
                projectSearch.value = this.dataset.name;
                projectIdInput.value = this.dataset.id;
                projectResults.classList.add('hidden');
            });
        });
    });
    
    // Hide results when clicking outside
    document.addEventListener('click', function(e) {
        if (!projectSearch.contains(e.target) && !projectResults.contains(e.target)) {
            projectResults.classList.add('hidden');
        }
    });
});
</script>

<?php include 'includes/adminFooter.php'; ?>