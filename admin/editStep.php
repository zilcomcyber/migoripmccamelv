<?php
$page_title = "Manage Project Steps";
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

require_admin();

require_once 'includes/pageSecurity.php';

$current_admin = get_current_admin();

// Get step ID and project ID
$step_id = (int)($_GET['id'] ?? 0);
$project_id = (int)($_GET['project_id'] ?? 0);

// Validate project ownership
if (!$project_id) {
    header('Location: projects.php?error=invalid_project');
    exit;
}

require_project_ownership($project_id, 'manage_project_steps');

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'update_step') {
        $result = update_project_step($_POST);
        if ($result['success']) {
            $success = $result['message'];
        } else {
            $error = $result['message'];
        }
    } elseif ($action === 'reorder_steps') {
        $result = reorder_project_steps($_POST);
        if ($result['success']) {
            $success = $result['message'];
        } else {
            $error = $result['message'];
        }
    }
}

$project_id = $_GET['project_id'] ?? 0;
$step_id = $_GET['step_id'] ?? 0;

if (!$project_id) {
    header('Location: projects.php');
    exit;
}

// Get project details
$project = get_project_by_id($project_id);
if (!$project) {
    header('Location: projects.php?error=Project not found');
    exit;
}

// Get specific step if editing
$step = null;
if ($step_id) {
    $stmt = $pdo->prepare("SELECT * FROM project_steps WHERE id = ? AND project_id = ?");
    $stmt->execute([$step_id, $project_id]);
    $step = $stmt->fetch();
}

// Get all steps for reordering
$stmt = $pdo->prepare("SELECT * FROM project_steps WHERE project_id = ? ORDER BY step_number");
$stmt->execute([$project_id]);
$all_steps = $stmt->fetchAll();

function update_project_step($data) {
    global $pdo, $current_admin;

    try {
        $step_id = intval($data['step_id']);
        $step_name = sanitize_input($data['step_name']);
        $description = sanitize_input($data['description']);
        $expected_end_date = $data['expected_end_date'] ?: null;
        $status = $data['status'];

        $valid_statuses = ['pending', 'in_progress', 'completed'];
        if (!in_array($status, $valid_statuses)) {
            return ['success' => false, 'message' => 'Invalid status'];
        }

        $sql = "UPDATE project_steps SET 
                step_name = ?, 
                description = ?, 
                expected_end_date = ?, 
                status = ?,
                updated_at = NOW()
                WHERE id = ?";

        $stmt = $pdo->prepare($sql);
        if ($stmt->execute([$step_name, $description, $expected_end_date, $status, $step_id])) {
            // Update actual_end_date if marking as completed
            if ($status === 'completed') {
                $pdo->prepare("UPDATE project_steps SET actual_end_date = NOW() WHERE id = ?")->execute([$step_id]);
            } elseif ($status !== 'completed') {
                $pdo->prepare("UPDATE project_steps SET actual_end_date = NULL WHERE id = ?")->execute([$step_id]);
            }

            // Recalculate project progress using new system
            require_once '../includes/projectProgressCalculator.php';
            $project_id = $data['project_id'];
            update_project_progress_and_status($project_id);

            log_activity("Updated project step: " . $step_name, $current_admin['id']);
            return ['success' => true, 'message' => 'Step updated successfully'];
        }

        return ['success' => false, 'message' => 'Failed to update step'];

    } catch (Exception $e) {
        error_log("Step update error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred while updating the step'];
    }
}

function reorder_project_steps($data) {
    global $pdo, $current_admin;

    try {
        $project_id = intval($data['project_id']);
        $step_orders = json_decode($data['step_orders'], true);

        if (!$step_orders) {
            return ['success' => false, 'message' => 'Invalid step order data'];
        }

        $pdo->beginTransaction();

        foreach ($step_orders as $step_id => $new_order) {
            $stmt = $pdo->prepare("UPDATE project_steps SET step_number = ? WHERE id = ? AND project_id = ?");
            $stmt->execute([intval($new_order), intval($step_id), $project_id]);
        }

        $pdo->commit();

        log_activity("Reordered project steps for project ID: " . $project_id, $current_admin['id']);
        return ['success' => true, 'message' => 'Steps reordered successfully'];

    } catch (Exception $e) {
        $pdo->rollBack();
        error_log("Reorder steps error: " . $e->getMessage());
        return ['success' => false, 'message' => 'An error occurred while reordering steps'];
    }
}

include 'includes/adminHeader.php';
?>
<div class="bg-white rounded-xl p-6 mb-6 shadow-sm border border-gray-200">
    <!-- Professional Header -->
    <div class="bg-gradient-to-r from-indigo-600 to-purple-600 rounded-lg shadow-lg mb-8 overflow-hidden">
        <div class="px-8 py-6 text-white">
            <div class="flex flex-col md:flex-row md:items-center md:justify-between">
                <div>
                    <h1 class="text-3xl font-bold mb-2"><?php echo $step ? 'Edit Project Step' : 'Manage Project Steps'; ?></h1>
                    <p class="text-indigo-100 text-lg">Project: <?php echo htmlspecialchars($project['project_name']); ?></p>
                </div>
                <div class="mt-4 md:mt-0">
                    <a href="manageProject.php?id=<?php echo $project_id; ?>" class="inline-flex items-center px-6 py-3 bg-white bg-opacity-20 backdrop-blur-sm rounded-lg text-white hover:bg-opacity-30 transition-all duration-200 font-medium">
                        <i class="fas fa-arrow-left mr-2"></i>Back to Project
                    </a>
                </div>
            </div>
        </div>
    </div>

    <!-- Messages -->
    <?php if (isset($success)): ?>
        <div class="mb-6 bg-green-50 border-l-4 border-green-400 p-4 rounded-r-lg shadow-sm">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <i class="fas fa-check-circle text-green-500 text-xl"></i>
                </div>
                <div class="ml-3">
                    <p class="text-green-800 font-medium"><?php echo htmlspecialchars($success); ?></p>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <?php if (isset($error)): ?>
        <div class="mb-6 bg-red-50 border-l-4 border-red-400 p-4 rounded-r-lg shadow-sm">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <i class="fas fa-exclamation-circle text-red-500 text-xl"></i>
                </div>
                <div class="ml-3">
                    <p class="text-red-800 font-medium"><?php echo htmlspecialchars($error); ?></p>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <div class="grid grid-cols-1 xl:grid-cols-2 gap-8">
        <!-- Edit Step Form -->
        <?php if ($step): ?>
        <div class="bg-white rounded-xl shadow-lg border border-gray-200 overflow-hidden">
            <div class="bg-gradient-to-r from-blue-50 to-indigo-50 px-6 py-4 border-b border-gray-200">
                <h3 class="text-xl font-bold text-gray-900 flex items-center">
                    <i class="fas fa-edit text-blue-600 mr-3"></i>Edit Step Details
                </h3>
                <p class="text-sm text-gray-600 mt-1">Modify step information and status</p>
            </div>

            <form method="POST" class="p-6">
                <input type="hidden" name="action" value="update_step">
                <input type="hidden" name="step_id" value="<?php echo $step['id']; ?>">
                <input type="hidden" name="project_id" value="<?php echo $project_id; ?>">

                <div class="space-y-6">
                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">Step Name</label>
                        <input type="text" name="step_name" value="<?php echo htmlspecialchars($step['step_name']); ?>" required
                               class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200">
                    </div>

                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">Description</label>
                        <textarea name="description" rows="4"
                                  class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200 resize-none"><?php echo htmlspecialchars($step['description']); ?></textarea>
                    </div>

                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">Expected End Date</label>
                        <input type="date" name="expected_end_date" value="<?php echo $step['expected_end_date']; ?>"
                               class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200">
                    </div>

                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">Status</label>
                        <select name="status" required
                                class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200">
                            <option value="pending" <?php echo $step['status'] === 'pending' ? 'selected' : ''; ?>>Pending</option>
                            <option value="in_progress" <?php echo $step['status'] === 'in_progress' ? 'selected' : ''; ?>>In Progress</option>
                            <option value="completed" <?php echo $step['status'] === 'completed' ? 'selected' : ''; ?>>Completed</option>
                        </select>
                    </div>
                </div>

                <div class="flex flex-col sm:flex-row gap-3 mt-8">
                    <button type="submit" class="flex-1 sm:flex-none inline-flex items-center justify-center px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-all duration-200 font-medium shadow-lg">
                        <i class="fas fa-save mr-2"></i>Update Step
                    </button>
                    <a href="editStep.php?project_id=<?php echo $project_id; ?>" class="flex-1 sm:flex-none inline-flex items-center justify-center px-6 py-3 bg-gray-300 text-gray-700 rounded-lg hover:bg-gray-400 transition-all duration-200 font-medium">
                        Cancel
                    </a>
                </div>
            </form>
        </div>
        <?php endif; ?>

        <!-- Steps List and Reordering -->
        <div class="bg-white rounded-xl shadow-lg border border-gray-200 overflow-hidden">
            <div class="bg-gradient-to-r from-green-50 to-blue-50 px-6 py-4 border-b border-gray-200">
                <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                    <div>
                        <h3 class="text-xl font-bold text-gray-900 flex items-center">
                            <i class="fas fa-list-ol text-green-600 mr-3"></i>Project Steps
                        </h3>
                        <p class="text-sm text-gray-600 mt-1">Drag to reorder • Click to edit</p>
                    </div>
                    <button onclick="saveStepOrder()" class="hidden inline-flex items-center px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-all duration-200 font-medium shadow-lg" id="saveOrderBtn">
                        <i class="fas fa-save mr-2"></i>Save Order
                    </button>
                </div>
            </div>

            <div class="p-6">
                <div id="stepsList" class="space-y-4 max-h-96 overflow-y-auto">
                    <?php foreach ($all_steps as $index => $s): ?>
                    <div class="flex items-center justify-between p-4 border border-gray-200 rounded-lg cursor-move hover:shadow-md transition-all duration-200 bg-gray-50 hover:bg-white" data-step-id="<?php echo $s['id']; ?>" data-step-order="<?php echo $s['step_number']; ?>">
                        <div class="flex items-center space-x-4 flex-1">
                            <div class="flex-shrink-0">
                                <i class="fas fa-grip-vertical text-gray-400 text-lg"></i>
                            </div>
                            <div class="w-10 h-10 bg-gradient-to-r from-blue-500 to-purple-600 rounded-full flex items-center justify-center shadow-lg">
                                <span class="text-sm font-bold text-white"><?php echo $s['step_number']; ?></span>
                            </div>
                            <div class="flex-1 min-w-0">
                                <h4 class="font-semibold text-gray-900 truncate"><?php echo htmlspecialchars($s['step_name']); ?></h4>
                                <p class="text-sm text-gray-600 line-clamp-2"><?php echo htmlspecialchars($s['description']); ?></p>
                            </div>
                        </div>
                        <div class="flex items-center space-x-3 flex-shrink-0">
                            <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold
                                <?php echo $s['status'] === 'completed' ? 'bg-green-100 text-green-800' : 
                                          ($s['status'] === 'in_progress' ? 'bg-blue-100 text-blue-800' : 
                                           'bg-gray-100 text-gray-800'); ?>">
                                <?php echo ucfirst(str_replace('_', ' ', $s['status'])); ?>
                            </span>
                            <a href="editStep.php?project_id=<?php echo $project_id; ?>&step_id=<?php echo $s['id']; ?>" 
                               class="p-2 text-blue-600 hover:text-blue-800 hover:bg-blue-50 rounded-lg transition-all duration-200">
                                <i class="fas fa-edit"></i>
                            </a>
                        </div>
                    </div>
                    <?php endforeach; ?>

                    <?php if (empty($all_steps)): ?>
                    <div class="text-center py-12">
                        <div class="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                            <i class="fas fa-tasks text-gray-400 text-2xl"></i>
                        </div>
                        <h3 class="text-lg font-medium text-gray-900 mb-2">No Steps Found</h3>
                        <p class="text-gray-600">This project doesn't have any steps yet.</p>
                        <a href="manageProject.php?id=<?php echo $project_id; ?>" class="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors mt-4">
                            <i class="fas fa-plus mr-2"></i>Add Steps
                        </a>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Professional Modal for Adding Steps -->
<div id="addStepModal" class="fixed inset-0 bg-black bg-opacity-50 hidden z-50 overflow-y-auto">
    <div class="flex items-center justify-center min-h-screen p-4">
        <div class="bg-white rounded-xl shadow-2xl max-w-2xl w-full mx-4 max-h-screen overflow-y-auto">
            <div class="bg-gradient-to-r from-blue-600 to-purple-600 px-6 py-4">
                <div class="flex justify-between items-center">
                    <h3 class="text-xl font-bold text-white flex items-center">
                        <i class="fas fa-plus-circle mr-3"></i>Add New Step
                    </h3>
                    <button onclick="closeAddStepModal()" class="text-white hover:text-gray-200 transition-colors">
                        <i class="fas fa-times text-xl"></i>
                    </button>
                </div>
            </div>
            <form id="addStepForm" method="POST" class="p-6">
                <input type="hidden" name="action" value="add_step">
                <input type="hidden" name="project_id" value="<?php echo $project_id; ?>">

                <div class="space-y-6">
                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">Step Name *</label>
                        <input type="text" name="step_name" required
                               class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200"
                               placeholder="Enter step name">
                    </div>

                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">Description</label>
                        <textarea name="description" rows="4"
                                  class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200 resize-none"
                                  placeholder="Describe what needs to be accomplished in this step"></textarea>
                    </div>

                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">Expected End Date</label>
                        <input type="date" name="expected_end_date"
                               class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200">
                    </div>
                </div>

                <div class="flex flex-col sm:flex-row gap-3 mt-8 pt-6 border-t border-gray-200">
                    <button type="button" onclick="closeAddStepModal()" class="flex-1 sm:flex-none px-6 py-3 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-all duration-200 font-medium">
                        Cancel
                    </button>
                    <button type="submit" class="flex-1 sm:flex-none px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-all duration-200 font-medium shadow-lg">
                        <i class="fas fa-plus mr-2"></i>Add Step
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<script src="../assets/js/sortable.min.js"></script>
<script>
// Initialize sortable list
const stepsList = document.getElementById('stepsList');
const saveOrderBtn = document.getElementById('saveOrderBtn');

if (stepsList && stepsList.children.length > 0) {
    new Sortable(stepsList, {
        animation: 150,
        ghostClass: 'sortable-ghost',
        onEnd: function() {
            saveOrderBtn.classList.remove('hidden');
        }
    });
}

function saveStepOrder() {
    const stepItems = stepsList.querySelectorAll('[data-step-id]');
    const stepOrders = {};

    stepItems.forEach((item, index) => {
        const stepId = item.getAttribute('data-step-id');
        stepOrders[stepId] = index + 1;
    });

    const form = document.createElement('form');
    form.method = 'POST';
    form.innerHTML = `
        <input type="hidden" name="action" value="reorder_steps">
        <input type="hidden" name="project_id" value="<?php echo $project_id; ?>">
        <input type="hidden" name="step_orders" value='${JSON.stringify(stepOrders)}'>
    `;

    document.body.appendChild(form);
    form.submit();
}

function showAddStepModal() {
    document.getElementById('addStepModal').classList.remove('hidden');
}

function closeAddStepModal() {
    document.getElementById('addStepModal').classList.add('hidden');
    document.getElementById('addStepForm').reset();
}

// Close modal when clicking outside
document.getElementById('addStepModal').addEventListener('click', function(e) {
    if (e.target === this) {
        closeAddStepModal();
    }
});

// Escape key to close modal
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeAddStepModal();
    }
});
</script>

<style>
.sortable-ghost {
    opacity: 0.4;
    transform: scale(0.98);
}

.line-clamp-2 {
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
}

/* Ensure modal content doesn't overflow */
.modal-content {
    max-height: calc(100vh - 2rem);
    overflow-y: auto;
}

/* Smooth transitions for all interactive elements */
* {
    transition: all 0.2s ease;
}

/* Custom scrollbar for better UX */
.overflow-y-auto::-webkit-scrollbar {
    width: 8px;
}

.overflow-y-auto::-webkit-scrollbar-track {
    background: #f1f1f1;
    border-radius: 4px;
}

.overflow-y-auto::-webkit-scrollbar-thumb {
    background: #c1c1c1;
    border-radius: 4px;
}

.overflow-y-auto::-webkit-scrollbar-thumb:hover {
    background: #a1a1a1;
}

/* Responsive improvements */
@media (max-width: 768px) {
    .grid {
        grid-template-columns: 1fr !important;
    }

    .modal-content {
        margin: 1rem;
        max-height: calc(100vh - 2rem);
    }
}
</style>

<?php include 'includes/adminFooter.php'; ?>