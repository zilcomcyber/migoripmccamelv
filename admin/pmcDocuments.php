<?php
$page_title = "PMC Documents";
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

require_admin();

$current_admin = get_current_admin();

// Get projects accessible to current admin
$accessible_projects = [];
if ($current_admin['role'] === 'super_admin') {
    $stmt = $pdo->query("SELECT id, project_name FROM projects ORDER BY project_name");
    $accessible_projects = $stmt->fetchAll();
} else {
    $stmt = $pdo->prepare("SELECT id, project_name FROM projects WHERE created_by = ? ORDER BY project_name");
    $stmt->execute([$current_admin['id']]);
    $accessible_projects = $stmt->fetchAll();
}

// Document types dropdown
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
    "Final Joint Inspection Report"
];

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token';
    } else {
        $action = $_POST['action'] ?? '';
        
        switch ($action) {
            case 'upload_document':
                $result = upload_pmc_document($_POST, $_FILES);
                break;
            case 'edit_document':
                $result = edit_pmc_document($_POST);
                break;
            case 'delete_document':
                $result = delete_pmc_document($_POST);
                break;
            default:
                $result = ['success' => false, 'message' => 'Invalid action'];
        }
        
        if (isset($result)) {
            if ($result['success']) {
                $success = $result['message'];
            } else {
                $error = $result['message'];
            }
        }
    }
}

// Get filters
$project_filter = intval($_GET['project'] ?? 0);
$type_filter = $_GET['type'] ?? '';

// Build query for documents
$where_conditions = ["d.status = 'active'"];
$params = [];

if ($project_filter > 0) {
    $where_conditions[] = "d.project_id = ?";
    $params[] = $project_filter;
}

if (!empty($type_filter)) {
    $where_conditions[] = "d.document_type = ?";
    $params[] = $type_filter;
}

// Admin access control
if ($current_admin['role'] !== 'super_admin') {
    $accessible_project_ids = array_column($accessible_projects, 'id');
    if (!empty($accessible_project_ids)) {
        $placeholders = str_repeat('?,', count($accessible_project_ids) - 1) . '?';
        $where_conditions[] = "d.project_id IN ($placeholders)";
        $params = array_merge($params, $accessible_project_ids);
    } else {
        $where_conditions[] = "1 = 0"; // No accessible projects
    }
}

$where_clause = implode(' AND ', $where_conditions);

$stmt = $pdo->prepare("
    SELECT d.*, p.project_name, a.name as uploaded_by_name
    FROM pmc_documents d
    JOIN projects p ON d.project_id = p.id
    LEFT JOIN admins a ON d.uploaded_by = a.id
    WHERE $where_clause
    ORDER BY d.created_at DESC
");
$stmt->execute($params);
$documents = $stmt->fetchAll();

function upload_pmc_document($data, $files) {
    global $pdo, $current_admin;
    
    try {
        $project_id = intval($data['project_id'] ?? 0);
        $document_type = sanitize_input($data['document_type'] ?? '');
        $document_title = sanitize_input($data['document_title'] ?? '');
        $description = sanitize_input($data['description'] ?? '');
        
        // Validate project access
        if ($current_admin['role'] !== 'super_admin') {
            $stmt = $pdo->prepare("SELECT id FROM projects WHERE id = ? AND created_by = ?");
            $stmt->execute([$project_id, $current_admin['id']]);
            if (!$stmt->fetch()) {
                return ['success' => false, 'message' => 'No permission to upload to this project'];
            }
        }
        
        // Handle file upload
        if (!isset($files['document_file']) || $files['document_file']['error'] !== UPLOAD_ERR_OK) {
            return ['success' => false, 'message' => 'File upload failed'];
        }
        
        $file = $files['document_file'];
        $allowed_types = ['pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png'];
        $file_extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        
        if (!in_array($file_extension, $allowed_types)) {
            return ['success' => false, 'message' => 'Invalid file type'];
        }
        
        // Generate unique filename
        $filename = 'doc_' . uniqid() . '.' . $file_extension;
        $upload_path = '../uploads/' . $filename;
        
        if (!move_uploaded_file($file['tmp_name'], $upload_path)) {
            return ['success' => false, 'message' => 'Failed to save file'];
        }
        
        // Insert document record
        $stmt = $pdo->prepare("
            INSERT INTO pmc_documents (project_id, document_type, document_title, description, file_name, original_name, uploaded_by, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
        ");
        
        $stmt->execute([
            $project_id,
            $document_type,
            $document_title,
            $description,
            $filename,
            $file['name'],
            $current_admin['id']
        ]);
        
        log_activity("Uploaded PMC document: $document_title for project ID: $project_id", $current_admin['id']);
        
        return ['success' => true, 'message' => 'Document uploaded successfully'];
        
    } catch (Exception $e) {
        error_log("Upload PMC document error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred while uploading the document'];
    }
}

function edit_pmc_document($data) {
    global $pdo, $current_admin;
    
    try {
        $document_id = intval($data['document_id'] ?? 0);
        $document_title = sanitize_input($data['document_title'] ?? '');
        $description = sanitize_input($data['description'] ?? '');
        
        // Get original document
        $stmt = $pdo->prepare("SELECT * FROM pmc_documents WHERE id = ?");
        $stmt->execute([$document_id]);
        $original_doc = $stmt->fetch();
        
        if (!$original_doc) {
            return ['success' => false, 'message' => 'Document not found'];
        }
        
        // Check permissions
        if ($current_admin['role'] !== 'super_admin' && $original_doc['uploaded_by'] != $current_admin['id']) {
            return ['success' => false, 'message' => 'No permission to edit this document'];
        }
        
        $pdo->beginTransaction();
        
        // Duplicate entry with 'edited' status for original
        $stmt = $pdo->prepare("
            INSERT INTO pmc_documents (project_id, document_type, document_title, description, file_name, original_name, uploaded_by, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'edited', ?)
        ");
        $stmt->execute([
            $original_doc['project_id'],
            $original_doc['document_type'],
            $original_doc['document_title'],
            $original_doc['description'],
            $original_doc['file_name'],
            $original_doc['original_name'],
            $original_doc['uploaded_by'],
            $original_doc['created_at']
        ]);
        
        // Update current document
        $stmt = $pdo->prepare("UPDATE pmc_documents SET document_title = ?, description = ?, updated_at = NOW() WHERE id = ?");
        $stmt->execute([$document_title, $description, $document_id]);
        
        $pdo->commit();
        
        log_activity("Edited PMC document: $document_title", $current_admin['id']);
        
        return ['success' => true, 'message' => 'Document updated successfully'];
        
    } catch (Exception $e) {
        $pdo->rollBack();
        error_log("Edit PMC document error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred while updating the document'];
    }
}

function delete_pmc_document($data) {
    global $pdo, $current_admin;
    
    try {
        $document_id = intval($data['document_id'] ?? 0);
        
        // Get original document
        $stmt = $pdo->prepare("SELECT * FROM pmc_documents WHERE id = ?");
        $stmt->execute([$document_id]);
        $original_doc = $stmt->fetch();
        
        if (!$original_doc) {
            return ['success' => false, 'message' => 'Document not found'];
        }
        
        // Check permissions
        if ($current_admin['role'] !== 'super_admin' && $original_doc['uploaded_by'] != $current_admin['id']) {
            return ['success' => false, 'message' => 'No permission to delete this document'];
        }
        
        $pdo->beginTransaction();
        
        // Duplicate entry with 'deleted' status
        $stmt = $pdo->prepare("
            INSERT INTO pmc_documents (project_id, document_type, document_title, description, file_name, original_name, uploaded_by, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'deleted', ?)
        ");
        $stmt->execute([
            $original_doc['project_id'],
            $original_doc['document_type'],
            $original_doc['document_title'],
            $original_doc['description'],
            $original_doc['file_name'],
            $original_doc['original_name'],
            $original_doc['uploaded_by'],
            $original_doc['created_at']
        ]);
        
        // Update current document status
        $stmt = $pdo->prepare("UPDATE pmc_documents SET status = 'deleted', updated_at = NOW() WHERE id = ?");
        $stmt->execute([$document_id]);
        
        $pdo->commit();
        
        log_activity("Deleted PMC document: " . $original_doc['document_title'], $current_admin['id']);
        
        return ['success' => true, 'message' => 'Document deleted successfully'];
        
    } catch (Exception $e) {
        $pdo->rollBack();
        error_log("Delete PMC document error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred while deleting the document'];
    }
}

include 'includes/adminHeader.php';

ob_start();
?>
<div class="bg-white rounded-xl p-6 mb-6 shadow-sm border border-gray-200">
<!-- Messages -->
<?php if (isset($success)): ?>
    <div class="mb-6 rounded-md bg-green-50 p-4">
        <div class="flex">
            <div class="flex-shrink-0">
                <i class="fas fa-check-circle text-green-400"></i>
            </div>
            <div class="ml-3">
                <p class="text-sm text-green-700"><?php echo htmlspecialchars($success); ?></p>
            </div>
        </div>
    </div>
<?php endif; ?>

<?php if (isset($error)): ?>
    <div class="mb-6 rounded-md bg-red-50 p-4">
        <div class="flex">
            <div class="flex-shrink-0">
                <i class="fas fa-exclamation-circle text-red-400"></i>
            </div>
            <div class="ml-3">
                <p class="text-sm text-red-700"><?php echo htmlspecialchars($error); ?></p>
            </div>
        </div>
    </div>
<?php endif; ?>

<!-- Page Header -->
<div class="bg-white rounded-xl p-6 mb-6 shadow-sm border border-gray-200">
    <div>
        <h2 class="text-2xl font-bold text-gray-900">PMC Documents</h2>
        <p class="text-gray-600">Manage project management committee documents</p>
    </div>
    <button onclick="showUploadModal()" class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 transition-colors">
        <i class="fas fa-upload mr-2"></i>
        Upload Document
    </button>
</div>

<!-- Filters -->
<div class="bg-white rounded-lg shadow-sm border border-gray-200 mb-6">
    <div class="p-6">
        <form method="GET" class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">Project</label>
                <select name="project" class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                    <option value="">All Projects</option>
                    <?php foreach ($accessible_projects as $project): ?>
                        <option value="<?php echo $project['id']; ?>" <?php echo $project_filter == $project['id'] ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($project['project_name']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">Document Type</label>
                <select name="type" class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                    <option value="">All Types</option>
                    <?php foreach ($document_types as $type): ?>
                        <option value="<?php echo htmlspecialchars($type); ?>" <?php echo $type_filter === $type ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($type); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="flex items-end">
                <button type="submit" class="w-full px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-gray-600 hover:bg-gray-700 transition-colors">
                    Apply Filters
                </button>
            </div>
        </form>
    </div>
</div>

<!-- Documents List -->
<div class="bg-white rounded-lg shadow-sm border border-gray-200">
    <div class="p-6 border-b border-gray-200">
        <h3 class="text-lg font-semibold text-gray-900">Documents (<?php echo count($documents); ?>)</h3>
    </div>

    <?php if (empty($documents)): ?>
        <div class="p-12 text-center">
            <i class="fas fa-file-alt text-4xl text-gray-400 mb-4"></i>
            <h3 class="text-lg font-medium text-gray-900 mb-2">No Documents Found</h3>
            <p class="text-gray-600 mb-4">No documents match your current filters.</p>
            <button onclick="showUploadModal()" class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 transition-colors">
                <i class="fas fa-upload mr-2"></i>
                Upload First Document
            </button>
        </div>
    <?php else: ?>
        <div class="divide-y divide-gray-200">
            <?php foreach ($documents as $doc): ?>
                <div class="p-6">
                    <div class="flex items-start justify-between">
                        <div class="flex-1">
                            <div class="flex items-center mb-2">
                                <h4 class="text-lg font-medium text-gray-900">
                                    <?php echo htmlspecialchars($doc['document_title']); ?>
                                </h4>
                                <span class="ml-3 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                    <?php echo htmlspecialchars($doc['document_type']); ?>
                                </span>
                            </div>
                            
                            <p class="text-sm text-gray-600 mb-2">
                                Project: <?php echo htmlspecialchars($doc['project_name']); ?>
                            </p>
                            
                            <?php if ($doc['description']): ?>
                                <p class="text-sm text-gray-600 mb-3">
                                    <?php echo htmlspecialchars($doc['description']); ?>
                                </p>
                            <?php endif; ?>
                            
                            <div class="flex items-center text-xs text-gray-500 space-x-4">
                                <span>Uploaded by: <?php echo htmlspecialchars($doc['uploaded_by_name']); ?></span>
                                <span>•</span>
                                <span><?php echo format_date($doc['created_at']); ?></span>
                                <span>•</span>
                                <span><?php echo htmlspecialchars($doc['original_name']); ?></span>
                            </div>
                        </div>
                        
                        <div class="flex items-center space-x-2 ml-4">
                            <a href="../uploads/<?php echo htmlspecialchars($doc['file_name']); ?>" target="_blank" 
                               class="text-blue-600 hover:text-blue-500" title="View Document">
                                <i class="fas fa-eye"></i>
                            </a>
                            
                            <?php if ($current_admin['role'] === 'super_admin' || $doc['uploaded_by'] == $current_admin['id']): ?>
                                <button onclick="editDocument(<?php echo htmlspecialchars(json_encode($doc)); ?>)" 
                                        class="text-green-600 hover:text-green-500" title="Edit Document">
                                    <i class="fas fa-edit"></i>
                                </button>
                                
                                <form method="POST" class="inline" onsubmit="return confirm('Are you sure you want to delete this document?')">
                                    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                                    <input type="hidden" name="action" value="delete_document">
                                    <input type="hidden" name="document_id" value="<?php echo $doc['id']; ?>">
                                    <button type="submit" class="text-red-600 hover:text-red-500" title="Delete Document">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </form>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>

<!-- Upload Modal -->
<div id="uploadModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 hidden z-50">
    <div class="flex items-center justify-center min-h-screen p-4">
        <div class="bg-white rounded-lg shadow-xl max-w-md w-full">
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                <input type="hidden" name="action" value="upload_document">

                <div class="p-6">
                    <h3 class="text-lg font-semibold text-gray-900 mb-4">Upload Document</h3>

                    <div class="space-y-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Project *</label>
                            <select name="project_id" required class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                                <option value="">Select Project</option>
                                <?php foreach ($accessible_projects as $project): ?>
                                    <option value="<?php echo $project['id']; ?>">
                                        <?php echo htmlspecialchars($project['project_name']); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Document Type *</label>
                            <select name="document_type" required class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                                <option value="">Select Type</option>
                                <?php foreach ($document_types as $type): ?>
                                    <option value="<?php echo htmlspecialchars($type); ?>">
                                        <?php echo htmlspecialchars($type); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Document Title *</label>
                            <input type="text" name="document_title" required 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Description</label>
                            <textarea name="description" rows="3" 
                                      class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"></textarea>
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Document File *</label>
                            <input type="file" name="document_file" required 
                                   accept=".pdf,.doc,.docx,.jpg,.jpeg,.png"
                                   class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                            <p class="text-xs text-gray-500 mt-1">Supported formats: PDF, DOC, DOCX, JPG, PNG</p>
                        </div>
                    </div>
                </div>

                <div class="flex justify-end space-x-3 p-6 border-t border-gray-200">
                    <button type="button" onclick="closeUploadModal()" 
                            class="px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 transition-colors">
                        Cancel
                    </button>
                    <button type="submit" 
                            class="px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 transition-colors">
                        Upload Document
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Edit Modal -->
<div id="editModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 hidden z-50">
    <div class="flex items-center justify-center min-h-screen p-4">
        <div class="bg-white rounded-lg shadow-xl max-w-md w-full">
            <form method="POST" id="editForm">
                <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                <input type="hidden" name="action" value="edit_document">
                <input type="hidden" name="document_id" id="editDocumentId">

                <div class="p-6">
                    <h3 class="text-lg font-semibold text-gray-900 mb-4">Edit Document</h3>

                    <div class="space-y-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Document Title *</label>
                            <input type="text" name="document_title" id="editDocumentTitle" required 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Description</label>
                            <textarea name="description" id="editDescription" rows="3" 
                                      class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"></textarea>
                        </div>
                    </div>
                </div>

                <div class="flex justify-end space-x-3 p-6 border-t border-gray-200">
                    <button type="button" onclick="closeEditModal()" 
                            class="px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 transition-colors">
                        Cancel
                    </button>
                    <button type="submit" 
                            class="px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 transition-colors">
                        Update Document
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>
</div>

<script>
    function showUploadModal() {
        document.getElementById('uploadModal').classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }

    function closeUploadModal() {
        document.getElementById('uploadModal').classList.add('hidden');
        document.body.style.overflow = 'auto';
    }

    function editDocument(doc) {
        document.getElementById('editDocumentId').value = doc.id;
        document.getElementById('editDocumentTitle').value = doc.document_title;
        document.getElementById('editDescription').value = doc.description || '';
        document.getElementById('editModal').classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }

    function closeEditModal() {
        document.getElementById('editModal').classList.add('hidden');
        document.body.style.overflow = 'auto';
    }
</script>

<?php
include 'includes/adminFooter.php';
?>
