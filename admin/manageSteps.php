<?php
$page_title = "Manage Project";
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

require_admin();

$current_admin = get_current_admin();

// Get project ID
$project_id = intval($_GET['id'] ?? 0);
if ($project_id <= 0) {
    header('Location: projects.php');
    exit();
}

// Get project details
$project = get_project_by_id($project_id);
if (!$project) {
    header('Location: projects.php');
    exit();
}

// Check if user can manage this specific project
if (!can_manage_project($project_id)) {
    header('Location: projects.php?error=You do not have permission to manage this project');
    exit();
}

// Get project steps
$stmt = $pdo->prepare("SELECT * FROM project_steps WHERE project_id = ? ORDER BY step_number");
$stmt->execute([$project_id]);
$steps = $stmt->fetchAll();

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token';
    } else {
        $action = $_POST['action'] ?? '';

        switch ($action) {
            case 'update_step':
                $result = update_project_step($_POST);
                break;
            case 'add_step':
                $result = add_project_step($_POST);
                break;
            case 'delete_step':
                $result = delete_project_step($_POST);
                break;
            case 'reorder_steps':
                $result = reorder_project_steps($_POST);
                break;
            case 'update_visibility':
                $result = update_project_visibility($_POST);
                break;
            default:
                $result = ['success' => false, 'message' => 'Invalid action'];
        }

        if (isset($result)) {
            if ($result['success']) {
                $success = $result['message'];
                // Refresh project data
                $project = get_project_by_id($project_id);
                $stmt = $pdo->prepare("SELECT * FROM project_steps WHERE project_id = ? ORDER BY step_number");
                $stmt->execute([$project_id]);
                $steps = $stmt->fetchAll();
            } else {
                $error = $result['message'];
            }
        }
    }
}

function update_project_step($data) {
    global $pdo, $project_id, $current_admin;

    try {
        $step_id = intval($data['step_id'] ?? 0);
        $status = $data['status'] ?? '';
        $notes = sanitize_input($data['notes'] ?? '');

        if (!in_array($status, ['pending', 'in_progress', 'completed', 'skipped'])) {
            return ['success' => false, 'message' => 'Invalid step status'];
        }

        $pdo->beginTransaction();

        // Update step
        $sql = "UPDATE project_steps SET status = ?, notes = ?";
        $params = [$status, $notes];

        if ($status === 'completed') {
            $sql .= ", actual_end_date = CURDATE()";
        } elseif ($status === 'in_progress') {
            $sql .= ", start_date = COALESCE(start_date, CURDATE())";
        }

        $sql .= " WHERE id = ? AND project_id = ?";
        $params[] = $step_id;
        $params[] = $project_id;

        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);

        // Update project progress
        $progress_result = update_project_progress($project_id);
        if ($progress_result === false) {
            error_log("Failed to update project progress for project ID: $project_id");
        }

        $pdo->commit();
        log_activity("Updated project step for project ID: $project_id", $current_admin['id']);

        return ['success' => true, 'message' => 'Step updated successfully'];

    } catch (Exception $e) {
        $pdo->rollBack();
        error_log("Update step error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred while updating the step'];
    }
}

function add_project_step($data) {
    global $pdo, $project_id, $current_admin;

    try {
        $step_name = sanitize_input($data['step_name'] ?? '');
        $description = sanitize_input($data['description'] ?? '');
        $expected_end_date = !empty($data['expected_end_date']) ? $data['expected_end_date'] : null;

        if (empty($step_name)) {
            return ['success' => false, 'message' => 'Step name is required'];
        }

        $pdo->beginTransaction();

        // Get next step number
        $stmt = $pdo->prepare("SELECT COALESCE(MAX(step_number), 0) + 1 FROM project_steps WHERE project_id = ?");
        $stmt->execute([$project_id]);
        $step_number = $stmt->fetchColumn();

        // Insert new step
        $stmt = $pdo->prepare("INSERT INTO project_steps (project_id, step_number, step_name, description, expected_end_date) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute([$project_id, $step_number, $step_name, $description, $expected_end_date]);

        // Update total steps count
        $stmt = $pdo->prepare("UPDATE projects SET total_steps = (SELECT COUNT(*) FROM project_steps WHERE project_id = ?) WHERE id = ?");
        $stmt->execute([$project_id, $project_id]);

        $pdo->commit();
        log_activity("Added project step for project ID: $project_id", $current_admin['id']);

        return ['success' => true, 'message' => 'Step added successfully'];

    } catch (Exception $e) {
        $pdo->rollBack();
        error_log("Add step error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred while adding the step'];
    }
}

function delete_project_step($data) {
    global $pdo, $project_id, $current_admin;

    try {
        $step_id = intval($data['step_id'] ?? 0);

        $pdo->beginTransaction();

        // Delete step
        $stmt = $pdo->prepare("DELETE FROM project_steps WHERE id = ? AND project_id = ?");
        $stmt->execute([$step_id, $project_id]);

        // Renumber remaining steps
        $stmt = $pdo->prepare("SELECT id FROM project_steps WHERE project_id = ? ORDER BY step_number");
        $stmt->execute([$project_id]);
        $remaining_steps = $stmt->fetchAll(PDO::FETCH_COLUMN);

        foreach ($remaining_steps as $index => $step_id) {
            $stmt = $pdo->prepare("UPDATE project_steps SET step_number = ? WHERE id = ?");
            $stmt->execute([$index + 1, $step_id]);
        }

        // Update total steps count
        $stmt = $pdo->prepare("UPDATE projects SET total_steps = (SELECT COUNT(*) FROM project_steps WHERE project_id = ?) WHERE id = ?");
        $stmt->execute([$project_id, $project_id]);

        // Update project progress
        update_project_progress($project_id);

        $pdo->commit();
        log_activity("Deleted project step for project ID: $project_id", $current_admin['id']);

        return ['success' => true, 'message' => 'Step deleted successfully'];

    } catch (Exception $e) {
        $pdo->rollBack();
        error_log("Delete step error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred while deleting the step'];
    }
}

function update_project_visibility($data) {
    global $pdo, $project_id, $current_admin;

    try {
        $visibility = $data['visibility'] ?? '';

        if (!in_array($visibility, ['private', 'published'])) {
            return ['success' => false, 'message' => 'Invalid visibility option'];
        }

        $stmt = $pdo->prepare("UPDATE projects SET visibility = ? WHERE id = ?");
        $stmt->execute([$visibility, $project_id]);

        log_activity("Updated project visibility to: $visibility for project ID: $project_id", $current_admin['id']);

        return ['success' => true, 'message' => 'Project visibility updated successfully'];

    } catch (Exception $e) {
        error_log("Update visibility error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred while updating visibility'];
    }
}

include 'includes/adminHeader.php';

ob_start();
?>

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
<div class="flex justify-between items-center mb-6">
    <div>
        <h2 class="text-2xl font-bold text-gray-900">Manage Project</h2>
        <p class="text-gray-600">Project: <?php echo htmlspecialchars($project['project_name']); ?></p>
    </div>
    <div class="flex space-x-2">
        <a href="editProject.php?id=<?php echo $project['id']; ?>" class="inline-flex items-center px-3 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 transition-colors">
            <i class="fas fa-edit mr-2"></i>
            Edit Project
        </a>
        <button onclick="deleteProject()" class="inline-flex items-center px-3 py-2 border border-red-600 text-sm font-medium rounded-md text-red-600 hover:bg-red-50 transition-colors">
            <i class="fas fa-trash mr-2"></i>
            Delete Project
        </button>
    </div>
</div>

<!-- Project Overview -->
<div class="bg-white rounded-lg shadow-sm border border-gray-200 mb-6">
    <div class="p-6">
        <div class="flex justify-between items-start mb-4">
            <div>
                <h3 class="text-xl font-bold text-gray-900 mb-2">
                    <?php echo htmlspecialchars($project['project_name']); ?>
                </h3>
                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?php echo get_status_badge_class($project['status']); ?>">
                    <?php echo ucfirst($project['status']); ?>
                </span>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div>
                <dt class="text-sm font-medium text-gray-500">Department</dt>
                <dd class="text-sm text-gray-900"><?php echo htmlspecialchars($project['department_name']); ?></dd>
            </div>
            <div>
                <dt class="text-sm font-medium text-gray-500">Location</dt>
                <dd class="text-sm text-gray-900"><?php echo htmlspecialchars($project['ward_name'] . ', ' . $project['sub_county_name']); ?></dd>
            </div>

            <div>
                <dt class="text-sm font-medium text-gray-500">Progress</dt>
                <dd class="text-sm text-gray-900">
                    <div class="flex items-center">
                        <div class="flex-1">
                            <div class="w-full bg-gray-200 rounded-full h-2">
                                <div class="h-2 rounded-full <?php echo get_progress_color_class($project['progress_percentage']); ?>" 
                                     style="width: <?php echo $project['progress_percentage']; ?>%"></div>
                            </div>
                        </div>
                        <span class="ml-3 text-sm"><?php echo $project['progress_percentage']; ?>%</span>
                    </div>
                </dd>
            </div>
        </div>
    </div>
</div>

<!-- Project Visibility Control -->
<div class="bg-white rounded-lg shadow-sm border border-gray-200 mb-6">
    <div class="p-6 border-b border-gray-200">
        <h3 class="text-lg font-semibold text-gray-900">Project Visibility</h3>
        <p class="text-sm text-gray-600 mt-1">Control public access to this project</p>
    </div>
    <div class="p-6">
        <form method="POST" class="flex items-center justify-between">
            <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
            <input type="hidden" name="action" value="update_visibility">
            <input type="hidden" name="project_id" value="<?php echo $project['id']; ?>">

            <div class="flex items-center space-x-4">
                <div class="flex items-center space-x-2">
                    <i class="fas fa-eye-slash text-gray-500"></i>
                    <span class="text-sm font-medium text-gray-700">Current Status:</span>
                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?php echo $project['visibility'] === 'published' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'; ?>">
                        <?php echo $project['visibility'] === 'published' ? 'Public' : 'Private'; ?>
                    </span>
                </div>
            </div>

            <div class="flex items-center space-x-3">
                <select name="visibility" class="px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-blue-500 focus:border-blue-500">
                    <option value="private" <?php echo $project['visibility'] === 'private' ? 'selected' : ''; ?>>Private (Admin Only)</option>
                    <option value="published" <?php echo $project['visibility'] === 'published' ? 'selected' : ''; ?>>Published (Public)</option>
                </select>
                <button type="submit" class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 transition-colors">
                    Update Visibility
                </button>
            </div>
        </form>
        <div class="mt-3 text-xs text-gray-500">
            <p><strong>Private:</strong> Only administrators can view this project</p>
            <p><strong>Published:</strong> Project appears on the public website for all visitors</p>
        </div>
    </div>
</div>

<!-- Project Steps Management -->
<div class="bg-white rounded-lg shadow-sm border border-gray-200">
    <div class="p-6 border-b border-gray-200">
        <div class="flex justify-between items-center">
            <h3 class="text-lg font-semibold text-gray-900">Project Steps</h3>
            <button onclick="showAddStepModal()" class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 transition-colors">
                <i class="fas fa-plus mr-2"></i>
                Add Step
            </button>
        </div>
    </div>

    <?php if (empty($steps)): ?>
        <div class="p-12 text-center">
            <i class="fas fa-list-ol text-4xl text-gray-400 mb-4"></i>
            <h3 class="text-lg font-medium text-gray-900 mb-2">No Steps Defined</h3>
            <p class="text-gray-600 mb-4">This project doesn't have any steps yet.</p>
            <button onclick="showAddStepModal()" class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 transition-colors">
                <i class="fas fa-plus mr-2"></i>
                Add First Step
            </button>
        </div>
    <?php else: ?>
        <div class="divide-y divide-gray-200">
            <?php foreach ($steps as $step): ?>
                <div class="p-6">
                    <div class="flex items-start justify-between">
                        <div class="flex-1">
                            <div class="flex items-center mb-2">
                                <span class="inline-flex items-center justify-center w-8 h-8 rounded-full text-sm font-medium text-white
                                    <?php 
                                    echo $step['status'] === 'completed' ? 'bg-green-500' : 
                                        ($step['status'] === 'in_progress' ? 'bg-blue-500' : 
                                        ($step['status'] === 'skipped' ? 'bg-gray-500' : 'bg-yellow-500'));
                                    ?>">
                                    <?php echo $step['step_number']; ?>
                                </span>
                                <h4 class="ml-3 text-lg font-medium text-gray-900">
                                    <?php echo htmlspecialchars($step['step_name']); ?>
                                </h4>
                                <span class="ml-3 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
                                    <?php 
                                    echo $step['status'] === 'completed' ? 'bg-green-100 text-green-800' : 
                                        ($step['status'] === 'in_progress' ? 'bg-blue-100 text-blue-800' : 
                                        ($step['status'] === 'skipped' ? 'bg-gray-100 text-gray-800' : 'bg-yellow-100 text-yellow-800'));
                                    ?>">
                                    <?php echo ucfirst(str_replace('_', ' ', $step['status'])); ?>
                                </span>
                            </div>

                            <?php if ($step['description']): ?>
                                <p class="text-sm text-gray-600 mb-3 ml-11">
                                    <?php echo htmlspecialchars($step['description']); ?>
                                </p>
                            <?php endif; ?>

                            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm ml-11">
                                <?php if ($step['start_date']): ?>
                                    <div>
                                        <span class="font-medium text-gray-500">Started:</span>
                                        <span class="text-gray-900"><?php echo format_date($step['start_date']); ?></span>
                                    </div>
                                <?php endif; ?>

                                <?php if ($step['expected_end_date']): ?>
                                    <div>
                                        <span class="font-medium text-gray-500">Expected:</span>
                                        <span class="text-gray-900"><?php echo format_date($step['expected_end_date']); ?></span>
                                    </div>
                                <?php endif; ?>

                                <?php if ($step['actual_end_date']): ?>
                                    <div>
                                        <span class="font-medium text-gray-500">Completed:</span>
                                        <span class="text-gray-900"><?php echo format_date($step['actual_end_date']); ?></span>
                                    </div>
                                <?php endif; ?>
                            </div>

                            <?php if ($step['notes']): ?>
                                <div class="mt-3 ml-11">
                                    <span class="font-medium text-gray-500 text-sm">Notes:</span>
                                    <p class="text-sm text-gray-900 mt-1"><?php echo htmlspecialchars($step['notes']); ?></p>
                                </div>
                            <?php endif; ?>
                        </div>

                        <div class="flex items-center space-x-2 ml-4">
                            <form method="POST" class="inline">
                                <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                                <input type="hidden" name="action" value="update_step">
                                <input type="hidden" name="step_id" value="<?php echo $step['id']; ?>">

                                <select name="status" onchange="this.form.submit()" class="text-sm border border-gray-300 rounded-md px-2 py-1">
                                    <option value="pending" <?php echo $step['status'] === 'pending' ? 'selected' : ''; ?>>Pending</option>
                                    <option value="in_progress" <?php echo $step['status'] === 'in_progress' ? 'selected' : ''; ?>>In Progress</option>
                                    <option value="completed" <?php echo $step['status'] === 'completed' ? 'selected' : ''; ?>>Completed</option>
                                    <option value="skipped" <?php echo $step['status'] === 'skipped' ? 'selected' : ''; ?>>Skipped</option>
                                </select>
                            </form>

                            <button onclick="editStep(<?php echo htmlspecialchars(json_encode($step)); ?>)" class="text-blue-600 hover:text-blue-500" title="Edit Step">
                                <i class="fas fa-edit"></i>
                            </button>

                            <form method="POST" class="inline" onsubmit="return confirm('Are you sure you want to delete this step?')">
                                <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                                <input type="hidden" name="action" value="delete_step">
                                <input type="hidden" name="step_id" value="<?php echo $step['id']; ?>">
                                <button type="submit" class="text-red-600 hover:text-red-500" title="Delete Step">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>

<!-- Add Step Modal -->
<div id="addStepModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 hidden z-50">
    <div class="flex items-center justify-center min-h-screen p-4">
        <div class="bg-white rounded-lg shadow-xl max-w-md w-full">
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                <input type="hidden" name="action" value="add_step">

                <div class="p-6">
                    <h3 class="text-lg font-semibold text-gray-900 mb-4">Add New Step</h3>

                    <div class="space-y-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Step Name *</label>
                            <input type="text" name="step_name" required 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Description</label>
                            <textarea name="description" rows="3" 
                                      class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"></textarea>
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Expected End Date</label>
                            <input type="date" name="expected_end_date" 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                        </div>
                    </div>
                </div>

                <div class="flex justify-end space-x-3 p-6 border-t border-gray-200">
                    <button type="button" onclick="closeAddStepModal()" 
                            class="px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 transition-colors">
                        Cancel
                    </button>
                    <button type="submit" 
                            class="px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 transition-colors">
                        Add Step
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
    function showAddStepModal() {
        document.getElementById('addStepModal').classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }

    function closeAddStepModal() {
        document.getElementById('addStepModal').classList.add('hidden');
        document.body.style.overflow = 'auto';
    }

    function deleteProject() {
        if (confirm('Are you sure you want to delete this project? This action cannot be undone and will also delete all associated steps and feedback.')) {
            // Create form to delete project
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = 'projects.php';

            const csrfInput = document.createElement('input');
            csrfInput.type = 'hidden';
            csrfInput.name = 'csrf_token';
            csrfInput.value = '<?php echo generate_csrf_token(); ?>';

            const actionInput = document.createElement('input');
            actionInput.type = 'hidden';
            actionInput.name = 'action';
            actionInput.value = 'delete';

            const projectIdInput = document.createElement('input');
            projectIdInput.type = 'hidden';
            projectIdInput.name = 'project_id';
            projectIdInput.value = '<?php echo $project_id; ?>';

            form.appendChild(csrfInput);
            form.appendChild(actionInput);
            form.appendChild(projectIdInput);

            document.body.appendChild(form);
            form.submit();
        }
    }
</script>

<?php
$content = ob_get_clean();
echo '<div class="admin-content">' . $content . '</div>';
include 'includes/adminFooter.php';
?>