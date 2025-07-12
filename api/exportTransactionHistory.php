<?php
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

// Require admin authentication
require_admin();
$current_admin = get_current_admin();

// Check permissions
require_permission('manage_budgets');

$project_id = $_GET['project_id'] ?? '';
$format = $_GET['format'] ?? 'csv';
$selected_projects = $_GET['selected_projects'] ?? '';
$export_all = $_GET['export_all'] ?? false;

try {
    // Build the base query
    $sql = "SELECT 
        pt.id,
        p.project_name,
        pt.transaction_type,
        pt.amount,
        pt.description,
        pt.transaction_date,
        pt.reference_number,
        pt.receipt_number,
        pt.bank_receipt_reference,
        pt.fund_source,
        pt.funding_category,
        pt.voucher_number,
        pt.disbursement_method,
        pt.transaction_status,
        pt.edit_reason,
        pt.deletion_reason,
        creator.name as created_by_name,
        modifier.name as modified_by_name,
        pt.created_at,
        pt.modified_at
    FROM project_transactions pt
    JOIN projects p ON pt.project_id = p.id
    LEFT JOIN admins creator ON pt.created_by = creator.id
    LEFT JOIN admins modifier ON pt.modified_by = modifier.id
    WHERE p.created_by = ?";

    $params = [$current_admin['id']];

    // Apply filters
    if (!empty($project_id)) {
        $sql .= " AND pt.project_id = ?";
        $params[] = $project_id;
    } elseif (!empty($selected_projects)) {
        $project_ids = explode(',', $selected_projects);
        $placeholders = str_repeat('?,', count($project_ids) - 1) . '?';
        $sql .= " AND pt.project_id IN ($placeholders)";
        $params = array_merge($params, $project_ids);
    }

    $sql .= " ORDER BY pt.created_at DESC";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $transactions = $stmt->fetchAll();

    if ($format === 'csv') {
        // CSV Export
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="transaction_history_' . date('Y-m-d') . '.csv"');

        $output = fopen('php://output', 'w');

        // CSV Headers
        fputcsv($output, [
            'Transaction ID',
            'Project Name',
            'Transaction Type',
            'Amount (KES)',
            'Description',
            'Transaction Date',
            'Reference Number',
            'Receipt Number',
            'Bank Receipt Reference',
            'Fund Source',
            'Funding Category',
            'Voucher Number',
            'Disbursement Method',
            'Status',
            'Edit Reason',
            'Deletion Reason',
            'Created By',
            'Modified By',
            'Created Date',
            'Modified Date'
        ]);

        // CSV Data
        foreach ($transactions as $transaction) {
            fputcsv($output, [
                $transaction['id'],
                $transaction['project_name'],
                ucfirst($transaction['transaction_type']),
                number_format($transaction['amount'], 2),
                $transaction['description'],
                $transaction['transaction_date'],
                $transaction['reference_number'],
                $transaction['receipt_number'] ?? '',
                $transaction['bank_receipt_reference'] ?? '',
                $transaction['fund_source'],
                $transaction['funding_category'],
                $transaction['voucher_number'] ?? '',
                $transaction['disbursement_method'] ?? '',
                ucfirst($transaction['transaction_status']),
                $transaction['edit_reason'] ?? '',
                $transaction['deletion_reason'] ?? '',
                $transaction['created_by_name'],
                $transaction['modified_by_name'] ?? '',
                $transaction['created_at'],
                $transaction['modified_at'] ?? ''
            ]);
        }

        fclose($output);
        exit;

    } elseif ($format === 'pdf') {
        // PDF Export
        require_once 'vender/autoload.php'; // A PDF library like TCPDF or DOMPDF installed
        // For now, we'll create a simple HTML-to-PDF solution
        
        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="transaction_history_' . date('Y-m-d') . '.pdf"');

        // Simple HTML to PDF conversion 
        $html = '<!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 10px; }
                th { background-color: #f5f5f5; font-weight: bold; }
                .header { text-align: center; margin-bottom: 20px; }
                .status-active { color: green; }
                .status-edited { color: orange; }
                .status-deleted { color: red; }
            </style>
        </head>
        <body>
            <div class="header">
                <h2>Migori County - Transaction History Report</h2>
                <p>Generated on: ' . date('F j, Y') . '</p>
                <p>Administrator: ' . htmlspecialchars($current_admin['name']) . '</p>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>Project</th>
                        <th>Type</th>
                        <th>Amount (KES)</th>
                        <th>Date</th>
                        <th>Reference</th>
                        <th>Receipt</th>
                        <th>Fund Source</th>
                        <th>Status</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>';

        foreach ($transactions as $transaction) {
            $status_class = 'status-' . $transaction['transaction_status'];
            $html .= '<tr>
                <td>' . htmlspecialchars($transaction['project_name']) . '</td>
                <td>' . htmlspecialchars(ucfirst($transaction['transaction_type'])) . '</td>
                <td>' . number_format($transaction['amount'], 2) . '</td>
                <td>' . date('M j, Y', strtotime($transaction['transaction_date'])) . '</td>
                <td>' . htmlspecialchars($transaction['reference_number']) . '</td>
                <td>' . htmlspecialchars($transaction['receipt_number'] ?? '-') . '</td>
                <td>' . htmlspecialchars($transaction['fund_source']) . '</td>
                <td class="' . $status_class . '">' . htmlspecialchars(ucfirst($transaction['transaction_status'])) . '</td>
                <td>' . htmlspecialchars(substr($transaction['description'], 0, 50)) . (strlen($transaction['description']) > 50 ? '...' : '') . '</td>
            </tr>';
        }

        $html .= '</tbody>
            </table>
            
            <div style="margin-top: 30px; font-size: 12px; color: #666;">
                <p><strong>Status Legend:</strong></p>
                <p><span class="status-active">Active:</span> Current transaction</p>
                <p><span class="status-edited">Edited:</span> Transaction has been modified</p>
                <p><span class="status-deleted">Deleted:</span> Transaction marked as deleted</p>
            </div>
        </body>
        </html>';

        // Use wkhtmltopdf if available, otherwise fall back to HTML
        if (shell_exec('which wkhtmltopdf')) {
            $temp_html = tempnam(sys_get_temp_dir(), 'transaction_report') . '.html';
            file_put_contents($temp_html, $html);
            
            $temp_pdf = tempnam(sys_get_temp_dir(), 'transaction_report') . '.pdf';
            shell_exec("wkhtmltopdf --page-size A4 --orientation Landscape '$temp_html' '$temp_pdf'");
            
            readfile($temp_pdf);
            unlink($temp_html);
            unlink($temp_pdf);
        } else {
            // Fallback: output HTML with PDF headers (browser will handle conversion)
            echo $html;
        }
        exit;
    }

} catch (Exception $e) {
    error_log("Export transaction history error: " . $e->getMessage());
    $_SESSION['error_message'] = 'Error exporting transaction history: ' . $e->getMessage();
    header('Location: ../admin/budgetManagement.php');
    exit;
}
?>
