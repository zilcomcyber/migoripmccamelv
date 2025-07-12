<?php
$page_title = "Budget Management";
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

// Require admin authentication
require_admin();
$current_admin = get_current_admin();

// Check permissions
require_permission('manage_budgets');

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_protect();

    $action = $_POST['action'] ?? '';

    if ($action === 'add_transaction' || $action === 'edit_transaction') {
        $project_id = (int)$_POST['project_id'];
        $transaction_type = sanitize_input($_POST['transaction_type']);
        $amount = (float)$_POST['amount'];
        $description = sanitize_input($_POST['description']);
        $transaction_date = $_POST['transaction_date'];
        $reference_number = sanitize_input($_POST['reference_number'] ?? '');
        $fund_source = sanitize_input($_POST['fund_source']);
        $funding_category = sanitize_input($_POST['funding_category']);
        $voucher_number = sanitize_input($_POST['voucher_number'] ?? '');
        $disbursement_method = sanitize_input($_POST['disbursement_method'] ?? '');
        $receipt_number = sanitize_input($_POST['receipt_number'] ?? '');
        $bank_receipt_reference = sanitize_input($_POST['bank_receipt_reference'] ?? '');
        $edit_reason = sanitize_input($_POST['edit_reason'] ?? '');

        // Handle "Other" fund source
        if ($fund_source === 'Other' && !empty($_POST['other_fund_source'])) {
            $fund_source = sanitize_input($_POST['other_fund_source']);
        }

        // Handle "Other" funding category - keep as 'other' for ENUM, store custom value in description if needed
        $custom_funding_category = '';
        if ($funding_category === 'other' && !empty($_POST['other_funding_category'])) {
            $custom_funding_category = ' (Category: ' . sanitize_input($_POST['other_funding_category']) . ')';
            $description .= $custom_funding_category;
        }

        // Ensure funding_category is valid for ENUM or set to default
        $valid_categories = ['development', 'recurrent', 'emergency', 'donor', 'other'];
        if (!in_array($funding_category, $valid_categories)) {
            $funding_category = 'development'; // Default fallback
        }

        // Validate inputs (funding_category is optional)
        if (!$project_id || !$transaction_type || !$amount || !$description || !$transaction_date || !$reference_number || !$fund_source) {
            $_SESSION['error_message'] = 'All required fields must be filled';
        } elseif ($amount <= 0) {
            $_SESSION['error_message'] = 'Amount must be greater than zero';
        } else {
            // Check project ownership
            if (!owns_project($project_id, $current_admin['id'])) {
                $_SESSION['error_message'] = 'You can only manage transactions for your own projects';
            } else {
                try {
                    $pdo->beginTransaction();

                    if ($action === 'add_transaction') {
                        $stmt = $pdo->prepare("INSERT INTO project_transactions 
                            (project_id, transaction_type, amount, description, transaction_date, reference_number, 
                             created_by, created_at, fund_source, funding_category, voucher_number, disbursement_method,
                             receipt_number, bank_receipt_reference, transaction_status) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?, ?, ?, ?, 'active')");
                        $result = $stmt->execute([$project_id, $transaction_type, $amount, $description, $transaction_date, 
                                                $reference_number, $current_admin['id'], $fund_source, $funding_category, 
                                                $voucher_number, $disbursement_method, $receipt_number, $bank_receipt_reference]);
                        $transaction_id = $pdo->lastInsertId();
                        $log_message = "Added new $transaction_type transaction";
                    } else {
                        // Edit transaction - create history entry
                        $transaction_id = (int)$_POST['transaction_id'];

                        // First, get the original transaction
                        $stmt = $pdo->prepare("SELECT * FROM project_transactions WHERE id = ? AND created_by = ?");
                        $stmt->execute([$transaction_id, $current_admin['id']]);
                        $original = $stmt->fetch();

                        if (!$original) {
                            throw new Exception('Transaction not found or access denied');
                        }

                        // Create a copy of the original with 'edited' status
                        $stmt = $pdo->prepare("INSERT INTO project_transactions 
                            (project_id, transaction_type, amount, description, transaction_date, reference_number, 
                             created_by, created_at, fund_source, funding_category, voucher_number, disbursement_method,
                             receipt_number, bank_receipt_reference, transaction_status, original_transaction_id, edit_reason, modified_by, modified_at) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'edited', ?, ?, ?, NOW())");
                        $stmt->execute([$original['project_id'], $original['transaction_type'], $original['amount'], 
                                      $original['description'], $original['transaction_date'], $original['reference_number'], 
                                      $original['created_by'], $original['created_at'], $original['fund_source'], 
                                      $original['funding_category'], $original['voucher_number'], $original['disbursement_method'],
                                      $original['receipt_number'], $original['bank_receipt_reference'], $transaction_id, 
                                      $edit_reason, $current_admin['id']]);

                        // Update the original transaction
                        $stmt = $pdo->prepare("UPDATE project_transactions SET 
                            transaction_type = ?, amount = ?, description = ?, transaction_date = ?, reference_number = ?, 
                            fund_source = ?, funding_category = ?, voucher_number = ?, disbursement_method = ?,
                            receipt_number = ?, bank_receipt_reference = ?, modified_by = ?, modified_at = NOW(), updated_at = NOW() 
                            WHERE id = ? AND created_by = ?");
                        $result = $stmt->execute([$transaction_type, $amount, $description, $transaction_date, $reference_number, 
                                                $fund_source, $funding_category, $voucher_number, $disbursement_method,
                                                $receipt_number, $bank_receipt_reference, $current_admin['id'], $transaction_id, $current_admin['id']]);
                        $log_message = "Edited $transaction_type transaction";
                    }

                    if ($result) {
                        // Update project progress immediately after transaction is added/updated
                        require_once '../includes/projectProgressCalculator.php';
                        
                        // Calculate and update progress
                        $new_progress = calculate_complete_project_progress($project_id);
                        $stmt = $pdo->prepare("UPDATE projects SET progress_percentage = ?, updated_at = NOW() WHERE id = ?");
                        $progress_update_result = $stmt->execute([$new_progress, $project_id]);
                        
                        if (!$progress_update_result) {
                            throw new Exception('Failed to update project progress');
                        }
                        
                        // Also run the full progress update function
                        update_project_progress_and_status($project_id, false, false);
                        
                        // Handle document upload if provided
                        if (isset($_FILES['transaction_document']) && $_FILES['transaction_document']['error'] === UPLOAD_ERR_OK) {
                            $allowed_extensions = ['pdf', 'jpg', 'jpeg', 'png', 'doc', 'docx'];
                            $upload_result = secure_file_upload(
                                $_FILES['transaction_document'], 
                                $allowed_extensions, 
                                20971520 // 20MB
                            );

                            if ($upload_result['success']) {
                                $stmt = $pdo->prepare("
                                    INSERT INTO project_transaction_documents 
                                    (transaction_id, file_path, original_filename, file_size, mime_type, uploaded_by, created_at) 
                                    VALUES (?, ?, ?, ?, ?, ?, NOW())
                                ");

                                $doc_result = $stmt->execute([
                                    $transaction_id,
                                    $upload_result['filename'],
                                    $upload_result['original_name'],
                                    $_FILES['transaction_document']['size'],
                                    $upload_result['mime_type'],
                                    $current_admin['id']
                                ]);

                                if (!$doc_result) {
                                    throw new Exception('Failed to save document information');
                                }
                            } else {
                                throw new Exception('Document upload error: ' . $upload_result['message']);
                            }
                        }

                        $pdo->commit();
                        log_activity('transaction_' . ($action === 'add_transaction' ? 'added' : 'updated'), 
                                   $log_message . " for project ID $project_id", $current_admin['id']);
                        $_SESSION['success_message'] = 'Transaction ' . ($action === 'add_transaction' ? 'added' : 'updated') . ' successfully';
                    } else {
                        throw new Exception('Failed to ' . ($action === 'add_transaction' ? 'add' : 'update') . ' transaction');
                    }
                } catch (Exception $e) {
                    $pdo->rollBack();
                    $_SESSION['error_message'] = 'Error adding transaction. Please check your input and try again.';
                }
            }
        }
    }

    if ($action === 'delete_transaction') {
        $transaction_id = (int)$_POST['transaction_id'];
        $deletion_reason = sanitize_input($_POST['deletion_reason'] ?? 'Administrative deletion');

        if (!$transaction_id) {
            $_SESSION['error_message'] = 'Invalid transaction ID';
        } elseif (empty($_POST['deletion_reason'])){
            $_SESSION['error_message'] = 'Deletion reason is required';
        } else {
            try {
                $pdo->beginTransaction();

                // Check ownership
                $stmt = $pdo->prepare("SELECT pt.*, p.created_by as project_owner FROM project_transactions pt 
                                     JOIN projects p ON pt.project_id = p.id WHERE pt.id = ?");
                $stmt->execute([$transaction_id]);
                $transaction = $stmt->fetch();

                if (!$transaction || $transaction['project_owner'] != $current_admin['id']) {
                    throw new Exception('Transaction not found or access denied');
                }

                // Mark as deleted instead of actually deleting
                $stmt = $pdo->prepare("UPDATE project_transactions SET 
                    transaction_status = 'deleted', deletion_reason = ?, modified_by = ?, modified_at = NOW() 
                    WHERE id = ?");
                $result = $stmt->execute([$deletion_reason, $current_admin['id'], $transaction_id]);

                if ($result) {
                    $pdo->commit();
                    log_activity('transaction_deleted', "Marked transaction ID $transaction_id as deleted", $current_admin['id']);
                    $_SESSION['success_message'] = 'Transaction marked as deleted successfully';
                } else {
                    throw new Exception('Failed to delete transaction');
                }
            } catch (Exception $e) {
                $pdo->rollBack();
                $_SESSION['error_message'] = 'Error deleting transaction. Please try again.';
            }
        }
    }

    header('Location: budgetManagement.php');
    exit;
}

// Get filter parameters
$project_filter = $_GET['project'] ?? '';
$transaction_type_filter = $_GET['type'] ?? '';
$status_filter = $_GET['status'] ?? 'active';
$page = max(1, intval($_GET['page'] ?? 1));
$per_page = 20;

// Check if we're editing a transaction
$edit_transaction_id = $_GET['edit'] ?? 0;
$edit_transaction = null;

if ($edit_transaction_id) {
    try {
        $stmt = $pdo->prepare("SELECT pt.*, COUNT(ptd.id) as document_count 
                              FROM project_transactions pt 
                              LEFT JOIN project_transaction_documents ptd ON pt.id = ptd.transaction_id 
                              JOIN projects p ON pt.project_id = p.id
                              WHERE pt.id = ? AND p.created_by = ? 
                              GROUP BY pt.id");
        $stmt->execute([$edit_transaction_id, $current_admin['id']]);
        $edit_transaction = $stmt->fetch();

        if (!$edit_transaction) {
            $_SESSION['error_message'] = 'Transaction not found or access denied';
            header('Location: budgetManagement.php');
            exit;
        }
    } catch (Exception $e) {
        $_SESSION['error_message'] = 'Error fetching transaction details';
        header('Location: budgetManagement.php');
        exit;
    }
}

// Get projects owned by current admin
try {
    $projects_stmt = $pdo->prepare("SELECT id, project_name FROM projects WHERE created_by = ? ORDER BY project_name");
    $projects_stmt->execute([$current_admin['id']]);
    $projects = $projects_stmt->fetchAll();
} catch (Exception $e) {
    $_SESSION['error_message'] = 'Error fetching projects.';
    $projects = [];
}

// Get active transaction types
try {
    $types_stmt = $pdo->prepare("SELECT type_code, display_name, description FROM transaction_types WHERE is_active = 1 ORDER BY display_name");
    $types_stmt->execute();
    $transaction_types = $types_stmt->fetchAll();
} catch (Exception $e) {
    $_SESSION['error_message'] = 'Error fetching transaction types.';
    $transaction_types = [];
}

// Get transactions with search functionality, pagination, and ownership filtering
$search_term = $_GET['search'] ?? '';
$offset = ($page - 1) * $per_page;

$transaction_sql = "
    SELECT pt.*, p.project_name,
           GROUP_CONCAT(ptd.original_filename SEPARATOR ', ') as documents,
           pt.fund_source, pt.funding_category, pt.voucher_number, pt.disbursement_method,
           pt.receipt_number, pt.bank_receipt_reference, pt.transaction_status,
           modifier.name as modified_by_name
    FROM project_transactions pt
    JOIN projects p ON pt.project_id = p.id
    LEFT JOIN project_transaction_documents ptd ON pt.id = ptd.transaction_id
    LEFT JOIN admins modifier ON pt.modified_by = modifier.id
    WHERE p.created_by = ?";

$count_sql = "
    SELECT COUNT(DISTINCT pt.id)
    FROM project_transactions pt
    JOIN projects p ON pt.project_id = p.id
    WHERE p.created_by = ?";

$params = [$current_admin['id']];

// Status filtering
if (!empty($status_filter)) {
    $transaction_sql .= " AND pt.transaction_status = ?";
    $count_sql .= " AND pt.transaction_status = ?";
    $params[] = $status_filter;
}

// Search filtering
if (!empty($search_term)) {
    $transaction_sql .= " AND (p.project_name LIKE ? OR pt.description LIKE ? OR pt.reference_number LIKE ?)";
    $count_sql .= " AND (p.project_name LIKE ? OR pt.description LIKE ? OR pt.reference_number LIKE ?)";
    $search_param = '%' . $search_term . '%';
    $params[] = $search_param;
    $params[] = $search_param;
    $params[] = $search_param;
}

// Project filter
if (!empty($project_filter)) {
    $transaction_sql .= " AND pt.project_id = ?";
    $count_sql .= " AND pt.project_id = ?";
    $params[] = $project_filter;
}

// Transaction type filter
if (!empty($transaction_type_filter)) {
    $transaction_sql .= " AND pt.transaction_type = ?";
    $count_sql .= " AND pt.transaction_type = ?";
    $params[] = $transaction_type_filter;
}

try {
    // Get total count
    $count_stmt = $pdo->prepare($count_sql);
    $count_stmt->execute($params);
    $total_transactions = $count_stmt->fetchColumn();
    $total_pages = ceil($total_transactions / $per_page);

    // Get transactions with pagination
    $transaction_sql .= " GROUP BY pt.id ORDER BY pt.created_at DESC LIMIT ? OFFSET ?";
    $params[] = $per_page;
    $params[] = $offset;

    $transaction_stmt = $pdo->prepare($transaction_sql);
    $transaction_stmt->execute($params);
    $transactions = $transaction_stmt->fetchAll();
} catch (Exception $e) {
    $_SESSION['error_message'] = 'Error fetching transactions.';
    $transactions = [];
    $total_transactions = 0;
    $total_pages = 1;
}

include 'includes/adminHeader.php';
?>

<!-- Breadcrumb -->
<div class="mb-6">
    <nav class="flex" aria-label="Breadcrumb">
        <ol class="flex items-center space-x-2 text-sm">
            <li class="text-gray-600 font-medium">
                <i class="fas fa-home mr-1"></i> Dashboard
            </li>
            <li class="text-gray-400">/</li>
            <li class="text-gray-600 font-medium">Budget Management</li>
        </ol>
    </nav>
</div>

<!-- Page Header -->
<div class="mb-8">
    <div class="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
        <div class="flex flex-col md:flex-row items-start justify-between">
            <div class="mb-4 md:mb-0">
                <h1 class="text-2xl font-bold text-gray-900 mb-2">Budget Management</h1>
                <p class="text-gray-600">Manage project transactions with complete history tracking</p>
                <p class="text-sm text-gray-500 mt-2">Track budget allocations, disbursements, and expenditures</p>
            </div>
            <div class="text-center md:text-right">
                <div class="text-3xl font-bold text-green-600 mb-1">
                    <i class="fas fa-money-bill-wave"></i>
                </div>
                <div class="text-sm text-gray-600 mb-3">Financial Management</div>
                <div class="text-xs text-gray-500">Transaction Tracking</div>
            </div>
        </div>
    </div>
</div>

<!-- Success/Error Messages -->
<?php if (isset($_SESSION['success_message'])): ?>
    <div class="mb-6 rounded-md bg-green-50 p-4 border border-green-200">
        <div class="flex items-center">
            <div class="flex-shrink-0">
                <i class="fas fa-check-circle text-green-400"></i>
            </div>
            <div class="ml-3">
                <p class="text-sm text-green-700"><?php echo htmlspecialchars($_SESSION['success_message']); ?></p>
            </div>
        </div>
    </div>
    <?php unset($_SESSION['success_message']); ?>
<?php endif; ?>

<?php if (isset($_SESSION['error_message'])): ?>
    <div class="mb-6 rounded-md bg-red-50 p-4 border border-red-200">
        <div class="flex items-center">
            <div class="flex-shrink-0">
                <i class="fas fa-exclamation-circle text-red-400"></i>
            </div>
            <div class="ml-3">
                <p class="text-sm text-red-700"><?php echo htmlspecialchars($_SESSION['error_message']); ?></p>
            </div>
        </div>
    </div>
    <?php unset($_SESSION['error_message']); ?>
<?php endif; ?>

<!-- Transaction Form -->
<div class="bg-white shadow-sm rounded-lg border border-gray-200 mb-8">
    <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
        <div class="flex justify-between items-center">
            <h2 class="text-lg font-semibold text-gray-900">
                <?php echo $edit_transaction ? 'Edit Transaction' : 'Add Transaction'; ?>
            </h2>
            <?php if ($edit_transaction): ?>
                <a href="budgetManagement.php" class="text-sm text-gray-500 hover:text-gray-700">
                    <i class="fas fa-times mr-1"></i> Cancel
                </a>
            <?php endif; ?>
        </div>
    </div>
    <div class="p-6">
        <form method="POST" enctype="multipart/form-data" class="space-y-6">
            <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
            <input type="hidden" name="action" value="<?php echo $edit_transaction ? 'edit_transaction' : 'add_transaction'; ?>">
            <?php if ($edit_transaction): ?>
                <input type="hidden" name="transaction_id" value="<?php echo $edit_transaction['id']; ?>">
            <?php endif; ?>

            <!-- Primary Information Section -->
            <div class="bg-gray-50 rounded-lg p-4 mb-6">
                <h4 class="text-sm font-semibold text-gray-800 mb-3 flex items-center">
                    <i class="fas fa-info-circle text-blue-500 mr-2"></i>
                    Primary Transaction Details
                </h4>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <!-- Project Search -->
                    <div>
                        <label for="project_search" class="block text-sm font-medium text-gray-700 mb-2">Project *</label>
                        <div class="relative">
                            <input type="text" id="project_search" placeholder="Search for a project..." 
                                   class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200"
                                   autocomplete="off">
                            <input type="hidden" id="project_id" name="project_id" required>
                            <div id="project_results" class="absolute z-10 w-full bg-white border border-gray-300 rounded-md shadow-lg mt-1 max-h-60 overflow-y-auto hidden">
                                <!-- Search results will appear here -->
                            </div>
                        </div>
                    </div>

                    <!-- Transaction Type -->
                    <div>
                        <label for="transaction_type" class="block text-sm font-medium text-gray-700 mb-2">Transaction Type *</label>
                        <select name="transaction_type" id="transaction_type" required 
                                class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200" 
                                onchange="handleTransactionTypeChange(this.value)">
                            <option value="">Select Type</option>
                            <?php foreach ($transaction_types as $type): ?>
                                <option value="<?php echo htmlspecialchars($type['type_code']); ?>" 
                                        <?php echo ($edit_transaction && $edit_transaction['transaction_type'] === $type['type_code']) ? 'selected' : ''; ?>
                                        title="<?php echo htmlspecialchars($type['description']); ?>">
                                    <?php echo htmlspecialchars($type['display_name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
            </div>

            <!-- Financial Information Section -->
            <div class="bg-green-50 rounded-lg p-4 mb-6">
                <h4 class="text-sm font-semibold text-gray-800 mb-3 flex items-center">
                    <i class="fas fa-dollar-sign text-green-500 mr-2"></i>
                    Financial Information
                </h4>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">

                <!-- Fund Source -->
                <div>
                    <label for="fund_source" class="block text-sm font-medium text-gray-700 mb-1">Fund Source *</label>
                    <select name="fund_source" id="fund_source" required class="focus:ring-blue-500 focus:border-blue-500 block w-full sm:text-sm border-gray-300 rounded-md" onchange="toggleOtherFundSource()">
                        <option value="">Select Fund Source</option>
                        <?php
                        try {
                            $sources_stmt = $pdo->query("SELECT * FROM fund_sources WHERE is_active = 1 ORDER BY source_name");
                            $fund_sources = $sources_stmt->fetchAll();
                            
                            // Remove duplicate "Other" option if it exists
                            $unique_sources = [];
                            foreach ($fund_sources as $source) {
                                if ($source['source_name'] !== 'Other' || !in_array('Other', array_column($unique_sources, 'source_name'))) {
                                    $unique_sources[] = $source;
                                }
                            }
                            
                            foreach ($unique_sources as $source): ?>
                                <option value="<?php echo htmlspecialchars($source['source_name']); ?>" 
                                        data-type="<?php echo $source['source_type']; ?>"
                                        <?php echo ($edit_transaction && $edit_transaction['fund_source'] === $source['source_name']) ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($source['source_name']); ?> <?php if($source['source_code'] !== 'OTHER'): ?>(<?php echo htmlspecialchars($source['source_code']); ?>)<?php endif; ?>
                                </option>
                            <?php endforeach;
                        } catch (Exception $e) {
                            // Fallback to default options if fund_sources table doesn't exist yet
                            $default_sources = ['County Development Fund', 'World Bank', 'African Development Bank', 'USAID', 'Emergency Fund', 'Other'];
                            foreach ($default_sources as $source): ?>
                                <option value="<?php echo $source; ?>" <?php echo ($edit_transaction && $edit_transaction['fund_source'] === $source) ? 'selected' : ''; ?>><?php echo $source; ?></option>
                            <?php endforeach;
                        } ?>
                    </select>
                </div>

                <!-- Other Fund Source (hidden by default) -->
                <div id="other_fund_source_field" style="display: none;">
                    <label for="other_fund_source" class="block text-sm font-medium text-gray-700 mb-1">Specify Fund Source *</label>
                    <input type="text" name="other_fund_source" id="other_fund_source" 
                           class="focus:ring-blue-500 focus:border-blue-500 block w-full sm:text-sm border-gray-300 rounded-md" 
                           placeholder="Enter fund source name" <?php echo ($edit_transaction && $edit_transaction['fund_source'] === 'Other') ? 'required' : ''; ?>>
                </div>

                <!-- Funding Category -->
                <div>
                    <label for="funding_category" class="block text-sm font-medium text-gray-700 mb-1">Funding Category</label>
                    <select name="funding_category" id="funding_category" class="focus:ring-blue-500 focus:border-blue-500 block w-full sm:text-sm border-gray-300 rounded-md" onchange="toggleOtherFundingCategory()">
                        <option value="">Select Category (Optional)</option>
                        <option value="development" <?php echo ($edit_transaction && $edit_transaction['funding_category'] === 'development') ? 'selected' : ''; ?>>Development</option>
                        <option value="recurrent" <?php echo ($edit_transaction && $edit_transaction['funding_category'] === 'recurrent') ? 'selected' : ''; ?>>Recurrent</option>
                        <option value="emergency" <?php echo ($edit_transaction && $edit_transaction['funding_category'] === 'emergency') ? 'selected' : ''; ?>>Emergency</option>
                        <option value="donor" <?php echo ($edit_transaction && $edit_transaction['funding_category'] === 'donor') ? 'selected' : ''; ?>>Donor Funded</option>
                        <option value="other" <?php echo ($edit_transaction && $edit_transaction['funding_category'] === 'other') ? 'selected' : ''; ?>>Other</option>
                    </select>
                </div>

                <!-- Other Funding Category (hidden by default) -->
                <div id="other_funding_category_field" style="display: none;">
                    <label for="other_funding_category" class="block text-sm font-medium text-gray-700 mb-1">Specify Category</label>
                    <input type="text" name="other_funding_category" id="other_funding_category" 
                           class="focus:ring-blue-500 focus:border-blue-500 block w-full sm:text-sm border-gray-300 rounded-md" 
                           placeholder="Enter funding category">
                </div>

                <!-- Amount -->
                <div>
                    <label for="amount" class="block text-sm font-medium text-gray-700 mb-1">Amount (KES) *</label>
                    <input type="number" id="amount" name="amount" step="0.01" min="0" required 
                           class="mt-1 focus:ring-blue-500 focus:border-blue-500 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md"
                           placeholder="0.00" 
                           value="<?php echo $edit_transaction ? htmlspecialchars($edit_transaction['amount']) : ''; ?>">
                </div>

                <!-- Reference Number -->
                <div>
                    <label for="reference_number" class="block text-sm font-medium text-gray-700 mb-1">Reference Number *</label>
                    <input type="text" name="reference_number" id="reference_number" required 
                           value="<?php echo $edit_transaction ? htmlspecialchars($edit_transaction['reference_number']) : ''; ?>"
                           class="focus:ring-blue-500 focus:border-blue-500 block w-full sm:text-sm border-gray-300 rounded-md" 
                           placeholder="Cheque No, Transaction Code, Payment Voucher No, etc">
                </div>

                <!-- Receipt Number -->
                <div>
                    <label for="receipt_number" class="block text-sm font-medium text-gray-700 mb-1">Receipt Number</label>
                    <input type="text" name="receipt_number" id="receipt_number"
                           value="<?php echo $edit_transaction ? htmlspecialchars($edit_transaction['receipt_number'] ?? '') : ''; ?>"
                           class="focus:ring-blue-500 focus:border-blue-500 block w-full sm:text-sm border-gray-300 rounded-md" 
                           placeholder="RCT/2024/001">
                </div>

                <!-- Bank Receipt Reference -->
                <div>
                    <label for="bank_receipt_reference" class="block text-sm font-medium text-gray-700 mb-1">Bank Receipt Reference</label>
                    <input type="text" name="bank_receipt_reference" id="bank_receipt_reference"
                           value="<?php echo $edit_transaction ? htmlspecialchars($edit_transaction['bank_receipt_reference'] ?? '') : ''; ?>"
                           class="focus:ring-blue-500 focus:border-blue-500 block w-full sm:text-sm border-gray-300 rounded-md" 
                           placeholder="Bank reference number">
                </div>

                <!-- Transaction Date -->
                <div>
                    <label for="transaction_date" class="block text-sm font-medium text-gray-700 mb-1">Date *</label>
                    <input type="date" id="transaction_date" name="transaction_date" required 
                           class="mt-1 focus:ring-blue-500 focus:border-blue-500 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md"
                           value="<?php echo $edit_transaction ? htmlspecialchars($edit_transaction['transaction_date']) : date('Y-m-d'); ?>">
                </div>

                <!-- Voucher Number (for expenditures) -->
                <div id="voucher_field" style="display: none;">
                    <label for="voucher_number" class="block text-sm font-medium text-gray-700 mb-1">Voucher Number</label>
                    <input type="text" name="voucher_number" id="voucher_number" 
                           value="<?php echo $edit_transaction ? htmlspecialchars($edit_transaction['voucher_number'] ?? '') : ''; ?>"
                           class="focus:ring-blue-500 focus:border-blue-500 block w-full sm:text-sm border-gray-300 rounded-md" 
                           placeholder="VCH/2024/001">
                </div>

                <!-- Disbursement Method -->
                <div id="disbursement_field" style="display: none;">
                    <label for="disbursement_method" class="block text-sm font-medium text-gray-700 mb-1">Disbursement Method</label>
                    <select name="disbursement_method" id="disbursement_method" class="focus:ring-blue-500 focus:border-blue-500 block w-full sm:text-sm border-gray-300 rounded-md">
                        <option value="bank_transfer" <?php echo ($edit_transaction && ($edit_transaction['disbursement_method'] ?? '') === 'bank_transfer') ? 'selected' : ''; ?>>Bank Transfer</option>
                        <option value="cheque" <?php echo ($edit_transaction && ($edit_transaction['disbursement_method'] ?? '') === 'cheque') ? 'selected' : ''; ?>>Cheque</option>
                        <option value="mobile_money" <?php echo ($edit_transaction && ($edit_transaction['disbursement_method'] ?? '') === 'mobile_money') ? 'selected' : ''; ?>>Mobile Money</option>
                        <option value="cash" <?php echo ($edit_transaction && ($edit_transaction['disbursement_method'] ?? '') === 'cash') ? 'selected' : ''; ?>>Cash</option>
                    </select>
                </div>

                <!-- Description -->
                <div class="md:col-span-2 lg:col-span-3">
                    <label for="description" class="block text-sm font-medium text-gray-700 mb-1">Description *</label>
                    <textarea id="description" name="description" rows="3" required 
                              class="shadow-sm focus:ring-blue-500 focus:border-blue-500 mt-1 block w-full sm:text-sm border border-gray-300 rounded-md"
                              placeholder="Enter transaction description"><?php echo $edit_transaction ? htmlspecialchars($edit_transaction['description']) : ''; ?></textarea>
                </div>

                <?php if ($edit_transaction): ?>
                <!-- Edit Reason -->
                <div class="md:col-span-2 lg:col-span-3">
                    <label for="edit_reason" class="block text-sm font-medium text-gray-700 mb-1">Reason for Edit *</label>
                    <textarea id="edit_reason" name="edit_reason" rows="2" required
                              class="shadow-sm focus:ring-blue-500 focus:border-blue-500 mt-1 block w-full sm:text-sm border border-gray-300 rounded-md"
                              placeholder="Explain why this transaction is being edited"></textarea>
                </div>
                <?php endif; ?>

                <!-- Document Upload -->
                <div class="md:col-span-2 lg:col-span-3">
                    <label for="transaction_document" class="block text-sm font-medium text-gray-700 mb-1">Supporting Document (Bank Receipt, Invoice, etc.)</label>
                    <div class="mt-1 flex justify-center px-6 pt-5 pb-6 border-2 border-gray-300 border-dashed rounded-md">
                        
                        <div class="space-y-1 text-center">
                            <svg class="mx-auto h-12 w-12 text-gray-400" stroke="currentColor"fill="none" viewBox="0 0 48 48" aria-hidden="true">
                                <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
                            </svg>
                            <div class="flex text-sm text-gray-600">
                                <label for="transaction_document" class="relative cursor-pointer bg-white rounded-md font-medium text-blue-600 hover:text-blue-500 focus-within:outline-none focus-within:ring-2 focus-within:ring-offset-2 focus-within:ring-blue-500">
                                    <span>Upload a file</span>
                                    <input id="transaction_document" name="transaction_document" type="file" class="sr-only" accept=".pdf,.jpg,.jpeg,.png,.doc,.docx">
                                </label>
                                <p class="pl-1">or drag and drop</p>
                            </div>
                            <p class="text-xs text-gray-500">PDF, JPG, PNG, DOC, DOCX up to 20MB</p>
                            <p id="file-name-display" class="text-sm text-gray-700 mt-2"></p>
                        </div>
                    </div>
                    <?php if ($edit_transaction && $edit_transaction['document_count'] > 0): ?>
                        <p class="mt-2 text-sm text-gray-500">Current documents: <?php echo $edit_transaction['document_count']; ?></p>
                    <?php endif; ?>
                </div>
            </div>

            <div class="flex justify-end pt-4">
                <button type="submit" class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                    <?php if ($edit_transaction): ?>
                        <i class="fas fa-save mr-2"></i> Update Transaction
                    <?php else: ?>
                        <i class="fas fa-plus mr-2"></i> Add Transaction
                    <?php endif; ?>
                </button>
            </div>
        </form>
    </div>
</div>

<!-- Transactions List -->
<div class="bg-white shadow-sm rounded-lg border border-gray-200 overflow-hidden">
    <div class="px-6 py-4 border-b border-gray-200 bg-gray-50">
        <div class="flex flex-col space-y-4">
            <div class="flex justify-between items-center">
                <h2 class="text-lg font-semibold text-gray-900">Transaction History (<?php echo number_format($total_transactions ?? 0); ?>)</h2>
                <div class="flex space-x-2">
                    <a href="../api/exportTransactionHistory.php?project_id=<?php echo $project_filter; ?>&format=csv" 
                       class="text-sm bg-green-600 text-white px-3 py-2 rounded hover:bg-green-700">
                        <i class="fas fa-download mr-1"></i> Export CSV
                    </a>
                    <a href="../api/exportTransactionHistory.php?project_id=<?php echo $project_filter; ?>&format=pdf" 
                       class="text-sm bg-red-600 text-white px-3 py-2 rounded hover:bg-red-700">
                        <i class="fas fa-file-pdf mr-1"></i> Export PDF
                    </a>
                </div>
            </div>

            <!-- Filters Form -->
            <form method="GET" class="grid grid-cols-1 md:grid-cols-5 gap-4">
                <div class="relative rounded-md shadow-sm">
                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <i class="fas fa-search text-gray-400"></i>
                    </div>
                    <input type="text" name="search" placeholder="Search transactions..." 
                           class="focus:ring-blue-500 focus:border-blue-500 block w-full pl-10 sm:text-sm border-gray-300 rounded-md"
                           value="<?php echo htmlspecialchars($search_term); ?>">
                </div>

                <select name="project" class="focus:ring-blue-500 focus:border-blue-500 block w-full sm:text-sm border-gray-300 rounded-md">
                    <option value="">All Projects</option>
                    <?php foreach ($projects as $project): ?>
                        <option value="<?php echo $project['id']; ?>" <?php echo $project_filter == $project['id'] ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($project['project_name']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>

                <select name="type" class="focus:ring-blue-500 focus:border-blue-500 block w-full sm:text-sm border-gray-300 rounded-md">
                    <option value="">All Types</option>
                    <option value="budget_increase" <?php echo $transaction_type_filter === 'budget_increase' ? 'selected' : ''; ?>>Budget Increase</option>
                    <option value="disbursement" <?php echo $transaction_type_filter === 'disbursement' ? 'selected' : ''; ?>>Disbursement</option>
                    <option value="expenditure" <?php echo $transaction_type_filter === 'expenditure' ? 'selected' : ''; ?>>Expenditure</option>
                    <option value="adjustment" <?php echo $transaction_type_filter === 'adjustment' ? 'selected' : ''; ?>>Adjustment</option>
                </select>

                <select name="status" class="focus:ring-blue-500 focus:border-blue-500 block w-full sm:text-sm border-gray-300 rounded-md">
                    <option value="">All Status</option>
                    <option value="active" <?php echo $status_filter === 'active' ? 'selected' : ''; ?>>Active</option>
                    <option value="edited" <?php echo $status_filter === 'edited' ? 'selected' : ''; ?>>Edited</option>
                    <option value="deleted" <?php echo $status_filter === 'deleted' ? 'selected' : ''; ?>>Deleted</option>
                </select>

                <div class="flex space-x-2">
                    <button type="submit" class="flex-1 inline-flex items-center justify-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700">
                        Filter
                    </button>
                    <a href="budgetManagement.php" class="inline-flex items-center px-3 py-2 border border-gray-300 text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                        Clear
                    </a>
                </div>
            </form>
        </div>
    </div>

    <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Amount</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Reference</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Receipt</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Fund Source</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Documents</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
                <?php if (empty($transactions)): ?>
                    <tr>
                        <td colspan="11" class="px-6 py-4 text-center text-sm text-gray-500">No transactions found</td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($transactions as $transaction): ?>
                        <tr class="hover:bg-gray-50 <?php echo $transaction['transaction_status'] !== 'active' ? 'bg-gray-50' : ''; ?>">
                            <td class="px-6 py-4 whitespace-nowrap">
                                <div class="text-sm font-medium text-gray-900"><?php echo htmlspecialchars($transaction['project_name']); ?></div>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap">
                                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                                    <?php 
                                    switch($transaction['transaction_type']) {
                                        case 'allocation': echo 'bg-blue-100 text-blue-800'; break;
                                        case 'budget_increase': echo 'bg-purple-100 text-purple-800'; break;
                                        case 'disbursement': echo 'bg-green-100 text-green-800'; break;
                                        case 'expenditure': echo 'bg-red-100 text-red-800'; break;
                                        case 'adjustment': echo 'bg-yellow-100 text-yellow-800'; break;
                                        default: echo 'bg-gray-100 text-gray-800';
                                    }
                                    ?>">
                                    <?php 
                                    $type_labels = [
                                        'allocation' => 'Initial Allocation',
                                        'budget_increase' => 'Budget Increase',
                                        'disbursement' => 'Disbursement',
                                        'expenditure' => 'Expenditure',
                                        'adjustment' => 'Adjustment'
                                    ];
                                    echo htmlspecialchars($type_labels[$transaction['transaction_type']] ?? ucfirst($transaction['transaction_type'])); 
                                    ?>
                                </span>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                <?php echo format_currency($transaction['amount']); ?>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                <?php echo format_date($transaction['transaction_date']); ?>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                <?php echo htmlspecialchars($transaction['reference_number']); ?>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                <?php echo htmlspecialchars($transaction['receipt_number'] ?? '-'); ?>
                            </td>
                            <td class="px-6 py-4 text-sm text-gray-500 max-w-xs truncate" title="<?php echo htmlspecialchars($transaction['description']); ?>">
                                <?php echo htmlspecialchars($transaction['description']); ?>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                <?php echo htmlspecialchars($transaction['fund_source']); ?>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap">
                                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                                    <?php 
                                    switch($transaction['transaction_status']) {
                                        case 'active': echo 'bg-green-100 text-green-800'; break;
                                        case 'edited': echo 'bg-yellow-100 text-yellow-800'; break;
                                        case 'deleted': echo 'bg-red-100 text-red-800'; break;
                                        default: echo 'bg-gray-100 text-gray-800';
                                    }
                                    ?>">
                                    <?php echo htmlspecialchars(ucfirst($transaction['transaction_status'])); ?>
                                </span>
                                <?php if ($transaction['modified_by_name']): ?>
                                    <div class="text-xs text-gray-400 mt-1">by <?php echo htmlspecialchars($transaction['modified_by_name']); ?></div>
                                <?php endif; ?>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                <?php if (!empty($transaction['documents'])): ?>
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                        <i class="fas fa-file mr-1"></i>
                                        <?php echo substr_count($transaction['documents'], ',') + 1; ?>
                                    </span>
                                <?php else: ?>
                                    <span class="text-gray-400">None</span>
                                <?php endif; ?>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                <?php if ($transaction['transaction_status'] === 'active'): ?>
                                    <div class="flex items-center space-x-2">
                                        <a href="budgetManagement.php?edit=<?php echo $transaction['id']; ?>" class="text-blue-600 hover:text-blue-900">
                                            <i class="fas fa-edit"></i>
                                        </a>
                                        <button onclick="confirmDelete(<?php echo $transaction['id']; ?>)" class="text-red-600 hover:text-red-900">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    </div>
                                <?php else: ?>
                                    <span class="text-gray-400">N/A</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- Pagination -->
    <?php if ($total_pages > 1): ?>
        <div class="px-4 py-3 border-t border-gray-200 bg-gray-50">
            <div class="flex items-center justify-between">
                <div class="text-sm text-gray-700">
                    Showing <?php echo (($page - 1) * $per_page) + 1; ?> to 
                    <?php echo min($page * $per_page, $total_transactions); ?> of 
                    <?php echo number_format($total_transactions); ?> results
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
</div>

<!-- Delete Confirmation Modal -->
<div id="deleteModal" class="fixed inset-0 z-50 hidden overflow-y-auto">
    <div class="flex items-center justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
        <div class="fixed inset-0 transition-opacity" aria-hidden="true">
            <div class="absolute inset-0 bg-gray-500 opacity-75"></div>
        </div>
        <span class="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>
        <div class="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
            <form id="deleteForm" method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                <input type="hidden" name="action" value="delete_transaction">
                <input type="hidden" name="transaction_id" id="deleteTransactionId">

                <div class="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                    <div class="sm:flex sm:items-start">
                        <div class="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-red-100 sm:mx-0 sm:h-10 sm:w-10">
                            <i class="fas fa-exclamation-triangle text-red-600"></i>
                        </div>
                        <div class="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left">
                            <h3 class="text-lg leading-6 font-medium text-gray-900">Delete Transaction</h3>
                            <div class="mt-2">
                                <p class="text-sm text-gray-500">
                                    This will mark the transaction as deleted. It will remain in the history but won't affect financial calculations.
                                </p>
                                <div class="mt-4">
                                    <label for="deletion_reason" class="block text-sm font-medium text-gray-700">Reason for deletion:</label>
                                    <textarea name="deletion_reason" id="deletion_reason" rows="3" required
                                              class="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-red-500 focus:border-red-500 sm:text-sm"
                                              placeholder="Please provide a reason for deleting this transaction"></textarea>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                    <button type="submit" class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-red-600 text-base font-medium text-white hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 sm:ml-3 sm:w-auto sm:text-sm">
                        Delete Transaction
                    </button>
                    <button type="button" onclick="closeDeleteModal()" class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm">
                        Cancel
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const transactionType = document.getElementById('transaction_type');
    const voucherField = document.getElementById('voucher_field');
    const disbursementField = document.getElementById('disbursement_field');
    const fundSourceField = document.getElementById('fund_source');
    
    // Initialize project search
    const projectSearch = document.getElementById('project_search');
    const projectResults = document.getElementById('project_results');
    const projectIdInput = document.getElementById('project_id');
    
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
        
        // Add click handlers to results
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

    function toggleFields() {
        if (transactionType.value === 'expenditure' || transactionType.value === 'disbursement') {
            voucherField.style.display = 'block';
            disbursementField.style.display = 'block';
        } else {
            voucherField.style.display = 'none';
            disbursementField.style.display = 'none';
        }
    }

    function handleTransactionTypeChange(value) {
        toggleFields();
        
        // Automatically set fund source to "Disbursed Allocation" for project expenditures
        if (value === 'expenditure') {
            // Find the "Disbursed Allocation" option
            const disbursedOption = Array.from(fundSourceField.options).find(opt => 
                opt.text.includes('Disbursed Allocation') || opt.text.includes('Disbursement')
            );
            
            if (disbursedOption) {
                disbursedOption.selected = true;
                fundSourceField.disabled = true;
                document.getElementById('other_fund_source_field').style.display = 'none';
            }
        } else {
            fundSourceField.disabled = false;
        }
    }

    if (transactionType) {
        transactionType.addEventListener('change', function() {
            handleTransactionTypeChange(this.value);
        });
        
        // Initialize fields
        handleTransactionTypeChange(transactionType.value);
        toggleFields();
    }
});

// Handle Other fund source selection
function toggleOtherFundSource() {
    const fundSource = document.getElementById('fund_source');
    const otherField = document.getElementById('other_fund_source_field');
    const otherInput = document.getElementById('other_fund_source');

    if (fundSource.value === 'Other') {
        otherField.style.display = 'block';
        otherInput.required = true;
    } else {
        otherField.style.display = 'none';
        otherInput.required = false;
        otherInput.value = '';
    }
}

// Handle Other funding category selection
function toggleOtherFundingCategory() {
    const fundingCategory = document.getElementById('funding_category');
    const otherField = document.getElementById('other_funding_category_field');
    const otherInput = document.getElementById('other_funding_category');

    if (fundingCategory.value === 'other') {
        otherField.style.display = 'block';
    } else {
        otherField.style.display = 'none';
        otherInput.value = '';
    }
}

// Display selected file name
document.getElementById('transaction_document').addEventListener('change', function(e) {
    const fileNameDisplay = document.getElementById('file-name-display');
    if (this.files.length > 0) {
        fileNameDisplay.textContent = 'Selected file: ' + this.files[0].name;
    } else {
        fileNameDisplay.textContent = '';
    }
});

function confirmDelete(transactionId) {
    document.getElementById('deleteTransactionId').value = transactionId;
    document.getElementById('deleteModal').classList.remove('hidden');
}

function closeDeleteModal() {
    document.getElementById('deleteModal').classList.add('hidden');
    document.getElementById('deletion_reason').value = '';
}

// Initialize dynamic fields on page load
document.addEventListener('DOMContentLoaded', function() {
    toggleOtherFundSource();
    toggleOtherFundingCategory();
    
    // Set initial project if editing
    <?php if ($edit_transaction): ?>
        const editProject = projects.find(p => p.id == <?php echo $edit_transaction['project_id']; ?>);
        if (editProject) {
            document.getElementById('project_search').value = editProject.project_name;
            document.getElementById('project_id').value = editProject.id;
        }
    <?php endif; ?>
});
</script>

<?php include 'includes/adminFooter.php'; ?>
