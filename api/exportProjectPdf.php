<?php
require_once '../config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

// Check if user has permission to export
if (!isset($_SESSION['admin_id']) && !isset($_GET['public'])) {
    http_response_code(403);
    die('Access denied');
}

$project_id = (int)($_GET['id'] ?? 0);
if (!$project_id) {
    http_response_code(400);
    die('Invalid project ID');
}

// Get project details
$project = get_project_by_id($project_id);
if (!$project) {
    http_response_code(404);
    die('Project not found');
}

// Check if project is accessible
if ($project['visibility'] === 'private' && !isset($_SESSION['admin_id'])) {
    http_response_code(403);
    die('Access denied');
}

// Get project steps
$stmt = $pdo->prepare("SELECT * FROM project_steps WHERE project_id = ? ORDER BY step_number");
$stmt->execute([$project_id]);
$project_steps = $stmt->fetchAll();

// Get financial data
$stmt = $pdo->prepare("
    SELECT 
        SUM(CASE WHEN transaction_type = 'allocation' THEN amount ELSE 0 END) as total_allocated,
        SUM(CASE WHEN transaction_type = 'expenditure' THEN amount ELSE 0 END) as total_spent,
        COUNT(*) as transaction_count
    FROM project_transactions 
    WHERE project_id = ?
");
$stmt->execute([$project_id]);
$financial_data = $stmt->fetch();

$total_allocated = $financial_data['total_allocated'] ?? 0;
$total_spent = $financial_data['total_spent'] ?? 0;
$remaining_balance = $total_allocated - $total_spent;

// Get recent transactions
try {
    $stmt = $pdo->prepare("
        SELECT pt.*, ptd.file_path as document_path, ptd.original_filename
        FROM project_transactions pt 
        LEFT JOIN project_transaction_documents ptd ON pt.id = ptd.transaction_id
        WHERE pt.project_id = ? 
        ORDER BY pt.transaction_date DESC, pt.created_at DESC 
        LIMIT 20
    ");
    $stmt->execute([$project_id]);
    $transactions = $stmt->fetchAll();
} catch (PDOException $e) {
    $stmt = $pdo->prepare("
        SELECT pt.*, NULL as document_path, NULL as original_filename
        FROM project_transactions pt 
        WHERE pt.project_id = ? 
        ORDER BY pt.transaction_date DESC, pt.created_at DESC 
        LIMIT 20
    ");
    $stmt->execute([$project_id]);
    $transactions = $stmt->fetchAll();
}

// Calculate progress
$enhanced_progress = calculate_project_progress($project_id);

// Set headers for PDF download
header('Content-Type: application/pdf');
header('Content-Disposition: attachment; filename="' . preg_replace('/[^A-Za-z0-9\-_]/', '_', $project['project_name']) . '_Report.pdf"');

// Generate HTML content for PDF
ob_start();
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Project Report: <?php echo htmlspecialchars($project['project_name']); ?></title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; color: #333; }
        .header { text-align: center; border-bottom: 2px solid #4CAF50; padding-bottom: 20px; margin-bottom: 30px; }
        .logo { color: #4CAF50; font-size: 24px; font-weight: bold; }
        .project-title { font-size: 20px; margin: 10px 0; }
        .section { margin: 20px 0; page-break-inside: avoid; }
        .section-title { font-size: 16px; font-weight: bold; color: #4CAF50; border-bottom: 1px solid #ddd; padding-bottom: 5px; margin-bottom: 15px; }
        .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 15px 0; }
        .info-item { border: 1px solid #ddd; padding: 10px; }
        .info-label { font-weight: bold; color: #666; }
        .progress-bar { background: #f0f0f0; height: 20px; border-radius: 10px; overflow: hidden; margin: 10px 0; }
        .progress-fill { background: #4CAF50; height: 100%; text-align: center; color: white; line-height: 20px; font-size: 12px; }
        .step { border: 1px solid #ddd; margin: 10px 0; padding: 15px; }
        .step-completed { background: #e8f5e8; border-color: #4CAF50; }
        .step-progress { background: #e3f2fd; border-color: #2196F3; }
        .step-pending { background: #f5f5f5; border-color: #999; }
        .transaction { border-bottom: 1px solid #eee; padding: 10px 0; }
        .amount-positive { color: #4CAF50; font-weight: bold; }
        .amount-negative { color: #f44336; font-weight: bold; }
        .footer { text-align: center; margin-top: 40px; font-size: 12px; color: #666; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f5f5f5; font-weight: bold; }
    </style>
</head>
<body>
    <!-- Header -->
    <div class="header">
        <div class="logo">MIGORI COUNTY PMC</div>
        <div class="project-title"><?php echo htmlspecialchars($project['project_name']); ?></div>
        <div>Project Report - Generated on <?php echo date('F j, Y \a\t g:i A'); ?></div>
    </div>

    <!-- Project Overview -->
    <div class="section">
        <div class="section-title">Project Overview</div>
        <div class="info-grid">
            <div class="info-item">
                <div class="info-label">Status:</div>
                <div><?php echo ucfirst($project['status']); ?></div>
            </div>
            <div class="info-item">
                <div class="info-label">Progress:</div>
                <div><?php echo $enhanced_progress; ?>%</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: <?php echo $enhanced_progress; ?>%">
                        <?php echo $enhanced_progress; ?>%
                    </div>
                </div>
            </div>
            <div class="info-item">
                <div class="info-label">Department:</div>
                <div><?php echo htmlspecialchars($project['department_name']); ?></div>
            </div>
            <div class="info-item">
                <div class="info-label">Location:</div>
                <div><?php echo htmlspecialchars($project['ward_name'] . ', ' . $project['sub_county_name'] . ', ' . $project['county_name']); ?></div>
            </div>
            <div class="info-item">
                <div class="info-label">Project Year:</div>
                <div><?php echo $project['project_year']; ?></div>
            </div>
            <?php if ($project['contractor_name']): ?>
            <div class="info-item">
                <div class="info-label">Contractor:</div>
                <div><?php echo htmlspecialchars($project['contractor_name']); ?></div>
            </div>
            <?php endif; ?>
        </div>
        
        <div class="info-item">
            <div class="info-label">Description:</div>
            <div><?php echo htmlspecialchars($project['description']); ?></div>
        </div>
    </div>

    <!-- Financial Summary -->
    <div class="section">
        <div class="section-title">Financial Summary</div>
        <table>
            <tr>
                <th>Budget Item</th>
                <th>Amount (KES)</th>
                <th>Percentage</th>
            </tr>
            <tr>
                <td>Total Allocated</td>
                <td class="amount-positive"><?php echo number_format($total_allocated); ?></td>
                <td>100%</td>
            </tr>
            <tr>
                <td>Total Spent</td>
                <td class="amount-negative"><?php echo number_format($total_spent); ?></td>
                <td><?php echo $total_allocated > 0 ? number_format(($total_spent / $total_allocated) * 100, 1) : 0; ?>%</td>
            </tr>
            <tr>
                <td>Remaining Balance</td>
                <td class="<?php echo $remaining_balance >= 0 ? 'amount-positive' : 'amount-negative'; ?>">
                    <?php echo number_format($remaining_balance); ?>
                </td>
                <td><?php echo $total_allocated > 0 ? number_format(($remaining_balance / $total_allocated) * 100, 1) : 0; ?>%</td>
            </tr>
        </table>
    </div>

    <!-- Project Steps -->
    <?php if (!empty($project_steps)): ?>
    <div class="section">
        <div class="section-title">Project Timeline</div>
        <?php foreach ($project_steps as $step): ?>
            <div class="step step-<?php echo $step['status']; ?>">
                <div style="font-weight: bold;"><?php echo $step['step_number']; ?>. <?php echo htmlspecialchars($step['step_name']); ?></div>
                <div style="margin: 5px 0;"><?php echo htmlspecialchars($step['description'] ?? ''); ?></div>
                <div style="font-size: 12px; color: #666;">
                    Status: <?php echo ucfirst(str_replace('_', ' ', $step['status'])); ?>
                    <?php if ($step['completion_date']): ?>
                        | Completed: <?php echo date('M j, Y', strtotime($step['completion_date'])); ?>
                    <?php endif; ?>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>

    <!-- Recent Transactions -->
    <?php if (!empty($transactions)): ?>
    <div class="section">
        <div class="section-title">Financial Transactions</div>
        <table>
            <tr>
                <th>Date</th>
                <th>Type</th>
                <th>Description</th>
                <th>Reference</th>
                <th>Amount (KES)</th>
            </tr>
            <?php foreach ($transactions as $transaction): ?>
            <tr>
                <td><?php echo date('M j, Y', strtotime($transaction['transaction_date'])); ?></td>
                <td><?php echo ucfirst($transaction['transaction_type']); ?></td>
                <td><?php echo htmlspecialchars($transaction['description']); ?></td>
                <td><?php echo htmlspecialchars($transaction['reference_number'] ?? 'N/A'); ?></td>
                <td class="<?php echo $transaction['transaction_type'] === 'allocation' ? 'amount-positive' : 'amount-negative'; ?>">
                    <?php echo ($transaction['transaction_type'] === 'allocation' ? '+' : '-') . number_format($transaction['amount']); ?>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
    </div>
    <?php endif; ?>

    <!-- Footer -->
    <div class="footer">
        <div>Generated by Migori County Project Management & Coordination System</div>
        <div>Report generated on <?php echo date('F j, Y \a\t g:i A'); ?></div>
        <div>For official use only</div>
    </div>
</body>
</html>
<?php
$html = ob_get_clean();
?>