<?php
require_once 'includes/pageSecurity.php';
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';
require_once '../includes/rbac.php';

// Require authentication and permission to manage feedback
require_admin();
if (!has_permission('manage_feedback')) {
    header('Location: index.php?error=access_denied');
    exit;
}

$current_admin = get_current_admin();

// Check if admin has any grievances to manage
if (!has_admin_grievances($current_admin['id'])) {
    header('Location: feedback.php?info=no_grievances');
    exit;
}

// Log access to grievances
log_activity('grievances_access', 'Accessed grievance management page', $current_admin['id']);

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
        case 'respond_grievance':
            $feedback_id = intval($_POST['feedback_id'] ?? 0);
            $response = sanitize_input($_POST['admin_response'] ?? '');
            $new_status = $_POST['new_status'] ?? 'responded';
            
            if (empty($response)) {
                $result = ['success' => false, 'message' => 'Response cannot be empty'];
                break;
            }

            // Get grievance details and verify ownership
            $stmt = $pdo->prepare("
                SELECT f.*, p.created_by, p.project_name 
                FROM feedback f
                JOIN projects p ON f.project_id = p.id
                WHERE f.id = ? AND f.status = 'grievance' AND p.created_by = ?
            ");
            $stmt->execute([$feedback_id, $current_admin['id']]);
            $grievance = $stmt->fetch();

            if (!$grievance) {
                $result = ['success' => false, 'message' => 'Grievance not found or access denied'];
                break;
            }

            try {
                // Update grievance with response
                $stmt = $pdo->prepare("
                    UPDATE feedback SET 
                    admin_response = ?, 
                    status = ?, 
                    responded_by = ?, 
                    updated_at = NOW() 
                    WHERE id = ?
                ");
                $stmt->execute([$response, $new_status, $current_admin['id'], $feedback_id]);

                // Send email notification to citizen
                if (!empty($grievance['citizen_email'])) {
                    $subject = "Response to Your Grievance - {$grievance['project_name']}";
                    $message = "
                        <p>Thank you for your feedback regarding the project: <strong>{$grievance['project_name']}</strong></p>
                        <p><strong>Your Original Message:</strong></p>
                        <p style='background-color: #f9f9f9; padding: 15px; border-left: 4px solid #ddd;'>{$grievance['message']}</p>
                        <p><strong>Our Response:</strong></p>
                        <p style='background-color: #e8f4fd; padding: 15px; border-left: 4px solid #1e40af;'>$response</p>
                        <p>If you have further concerns, please feel free to contact us again.</p>
                    ";
                    
                    $email_sent = send_email_notification($grievance['citizen_email'], $subject, $message, $current_admin['id']);
                    
                    if (!$email_sent) {
                        error_log("Failed to send email notification for grievance #$feedback_id");
                    }
                }

                log_activity('grievance_responded', "Responded to grievance #$feedback_id for project: {$grievance['project_name']}", $current_admin['id']);
                $result = ['success' => true, 'message' => 'Grievance response sent successfully'];

            } catch (Exception $e) {
                error_log("Grievance response error: " . $e->getMessage());
                $result = ['success' => false, 'message' => 'Failed to send response'];
            }
            break;

        case 'update_status':
            $feedback_id = intval($_POST['feedback_id'] ?? 0);
            $new_status = $_POST['status'] ?? '';
            
            // Verify grievance exists and admin owns the project
            $stmt = $pdo->prepare("
                SELECT f.admin_response 
                FROM feedback f
                JOIN projects p ON f.project_id = p.id
                WHERE f.id = ? AND f.status = 'grievance' AND p.created_by = ?
            ");
            $stmt->execute([$feedback_id, $current_admin['id']]);
            $grievance = $stmt->fetch();

            if (!$grievance) {
                $result = ['success' => false, 'message' => 'Grievance not found or access denied'];
                break;
            }

            // Only allow status change if a response has been provided
            if (empty($grievance['admin_response'])) {
                $result = ['success' => false, 'message' => 'Cannot change status without providing a response first'];
                break;
            }

            try {
                $stmt = $pdo->prepare("UPDATE feedback SET status = ?, updated_at = NOW() WHERE id = ?");
                $stmt->execute([$new_status, $feedback_id]);
                
                log_activity('grievance_status_updated', "Updated grievance #$feedback_id status to $new_status", $current_admin['id']);
                $result = ['success' => true, 'message' => 'Grievance status updated successfully'];

            } catch (Exception $e) {
                error_log("Grievance status update error: " . $e->getMessage());
                $result = ['success' => false, 'message' => 'Failed to update status'];
            }
            break;
    }

    echo json_encode($result);
    exit;
}

// Get grievances for current admin
$stmt = $pdo->prepare("
    SELECT f.*, p.project_name, p.department_id, d.name as department_name,
           a.name as responded_by_name
    FROM feedback f
    JOIN projects p ON f.project_id = p.id
    JOIN departments d ON p.department_id = d.id
    LEFT JOIN admins a ON f.responded_by = a.id
    WHERE f.status = 'grievance' AND p.created_by = ?
    ORDER BY f.created_at DESC
");
$stmt->execute([$current_admin['id']]);
$grievances = $stmt->fetchAll();

$page_title = "Grievance Management";
include 'includes/adminHeader.php';
?>

<div class="bg-white rounded-xl p-6 mb-6 shadow-sm border border-gray-200">
    <!-- Header -->
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Grievance Management</h1>
            <p class="mt-1 text-sm text-gray-600">Handle citizen grievances requiring immediate attention</p>
        </div>
        <div class="mt-4 sm:mt-0">
            <a href="feedback.php" class="inline-flex items-center px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700">
                <i class="fas fa-arrow-left mr-2"></i>Back to Feedback
            </a>
        </div>
    </div>

    <!-- Grievances List -->
    <div class="bg-white rounded-lg shadow-sm border border-gray-200">
        <div class="p-4 border-b border-gray-200 bg-red-50">
            <div class="flex items-center">
                <i class="fas fa-exclamation-triangle text-red-600 mr-3"></i>
                <h3 class="text-lg font-semibold text-red-900">
                    Active Grievances (<?php echo count($grievances); ?>)
                </h3>
            </div>
            <p class="text-sm text-red-700 mt-1">These require immediate attention and response</p>
        </div>

        <?php if (empty($grievances)): ?>
            <div class="p-12 text-center">
                <i class="fas fa-check-circle text-4xl text-green-400 mb-4"></i>
                <h3 class="text-lg font-medium text-gray-900 mb-2">No Active Grievances</h3>
                <p class="text-gray-600">All grievances have been handled.</p>
            </div>
        <?php else: ?>
            <div class="divide-y divide-gray-200">
                <?php foreach ($grievances as $grievance): ?>
                    <div class="p-6">
                        <div class="flex items-start justify-between">
                            <div class="flex-1">
                                <div class="flex items-center mb-3">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 mr-3">
                                        <i class="fas fa-exclamation-triangle mr-1"></i>
                                        Grievance
                                    </span>
                                    <span class="text-sm text-gray-500">
                                        <?php echo htmlspecialchars($grievance['project_name']); ?> • 
                                        <?php echo htmlspecialchars($grievance['department_name']); ?>
                                    </span>
                                </div>

                                <div class="mb-4">
                                    <h4 class="text-lg font-semibold text-gray-900 mb-2">
                                        <?php echo htmlspecialchars($grievance['subject'] ?: 'Project Grievance'); ?>
                                    </h4>
                                    <div class="text-sm text-gray-600 mb-2">
                                        <strong>From:</strong> <?php echo htmlspecialchars($grievance['citizen_name']); ?>
                                        <?php if ($grievance['citizen_email']): ?>
                                            (<?php echo htmlspecialchars($grievance['citizen_email']); ?>)
                                        <?php endif; ?>
                                    </div>
                                    <div class="bg-gray-50 p-4 rounded-lg">
                                        <p class="text-gray-800"><?php echo nl2br(htmlspecialchars($grievance['message'])); ?></p>
                                    </div>
                                </div>

                                <?php if ($grievance['admin_response']): ?>
                                    <div class="mt-4 p-4 bg-blue-50 rounded-lg">
                                        <h5 class="font-medium text-blue-900 mb-2">Your Response:</h5>
                                        <p class="text-blue-800"><?php echo nl2br(htmlspecialchars($grievance['admin_response'])); ?></p>
                                        <div class="flex items-center justify-between mt-3">
                                            <span class="text-sm text-blue-600">
                                                Responded by: <?php echo htmlspecialchars($grievance['responded_by_name'] ?? 'Unknown'); ?>
                                            </span>
                                            <div class="flex space-x-2">
                                                <button onclick="updateGrievanceStatus(<?php echo $grievance['id']; ?>, 'resolved')" 
                                                        class="bg-green-600 text-white px-3 py-1 rounded text-sm hover:bg-green-700">
                                                    Mark Resolved
                                                </button>
                                                <button onclick="updateGrievanceStatus(<?php echo $grievance['id']; ?>, 'pending')" 
                                                        class="bg-yellow-600 text-white px-3 py-1 rounded text-sm hover:bg-yellow-700">
                                                    Mark Pending
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                <?php else: ?>
                                    <button onclick="showResponseModal(<?php echo $grievance['id']; ?>, '<?php echo htmlspecialchars($grievance['citizen_name'], ENT_QUOTES); ?>')" 
                                            class="inline-flex items-center px-4 py-2 bg-red-600 text-white text-sm font-medium rounded-md hover:bg-red-700">
                                        <i class="fas fa-reply mr-2"></i>Respond to Grievance
                                    </button>
                                <?php endif; ?>
                            </div>

                            <div class="ml-6 text-right">
                                <div class="text-sm text-gray-500">
                                    <?php echo date('M j, Y g:i A', strtotime($grievance['created_at'])); ?>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- Response Modal -->
<div id="responseModal" class="hidden fixed inset-0 bg-gray-600 bg-opacity-50 z-50 overflow-y-auto">
    <div class="flex items-center justify-center min-h-screen px-4">
        <div class="bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div class="p-6">
                <div class="flex items-center justify-between mb-6">
                    <h3 class="text-xl font-semibold text-gray-900">Respond to Grievance</h3>
                    <button onclick="closeResponseModal()" class="text-gray-400 hover:text-gray-600">
                        <i class="fas fa-times text-xl"></i>
                    </button>
                </div>

                <form id="responseForm">
                    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                    <input type="hidden" name="action" value="respond_grievance">
                    <input type="hidden" name="feedback_id" id="responseGrievanceId">
                    <input type="hidden" name="ajax" value="1">

                    <div class="mb-4">
                        <p class="text-sm text-gray-600">
                            Responding to grievance from: <span id="responseGrievanceAuthor" class="font-medium"></span>
                        </p>
                    </div>

                    <div class="mb-6">
                        <label for="adminResponse" class="block text-sm font-medium text-gray-700 mb-2">Your Response *</label>
                        <textarea name="admin_response" id="adminResponse" rows="6" required
                                  class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500"
                                  placeholder="Provide a detailed response addressing the citizen's concerns..."></textarea>
                    </div>

                    <div class="mb-6">
                        <label for="newStatus" class="block text-sm font-medium text-gray-700 mb-2">Update Status</label>
                        <select name="new_status" id="newStatus" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500">
                            <option value="responded">Responded</option>
                            <option value="resolved">Resolved</option>
                            <option value="pending">Keep as Pending</option>
                        </select>
                    </div>

                    <div class="flex justify-end space-x-3">
                        <button type="button" onclick="closeResponseModal()" 
                                class="px-6 py-3 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 hover:bg-gray-50">
                            Cancel
                        </button>
                        <button type="submit" 
                                class="px-6 py-3 bg-red-600 text-white text-sm font-medium rounded-lg hover:bg-red-700">
                            <i class="fas fa-paper-plane mr-2"></i>Send Response & Email
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>

<script>
function showResponseModal(grievanceId, authorName) {
    document.getElementById('responseGrievanceId').value = grievanceId;
    document.getElementById('responseGrievanceAuthor').textContent = authorName;
    document.getElementById('adminResponse').value = '';
    document.getElementById('responseModal').classList.remove('hidden');
}

function closeResponseModal() {
    document.getElementById('responseModal').classList.add('hidden');
}

function updateGrievanceStatus(grievanceId, status) {
    if (confirm(`Are you sure you want to mark this grievance as ${status}?`)) {
        const formData = new FormData();
        formData.append('action', 'update_status');
        formData.append('feedback_id', grievanceId);
        formData.append('status', status);
        formData.append('csrf_token', '<?php echo generate_csrf_token(); ?>');
        formData.append('ajax', '1');

        fetch('grievances.php', {
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
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred while updating status.');
        });
    }
}

// Response form submission
document.getElementById('responseForm').addEventListener('submit', function(e) {
    e.preventDefault();

    const submitBtn = this.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Sending...';
    submitBtn.disabled = true;

    const formData = new FormData(this);

    fetch('grievances.php', {
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
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred while sending the response.');
    })
    .finally(() => {
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
    });
});
</script>

<?php include 'includes/adminFooter.php'; ?>
