<?php
require_once '../config.php';
require_once '../includes/functions.php';

// Simple PDF generation without external libraries. exposting shall be implimented later using a library like TCPDF or mPDF
try {
    // Get filter parameters
    $filters = [
        'search' => $_GET['search'] ?? '',
        'status' => $_GET['status'] ?? '',
        'department' => $_GET['department'] ?? '',
        'ward' => $_GET['ward'] ?? '',
        'sub_county' => $_GET['sub_county'] ?? '',
        'year' => $_GET['year'] ?? '',
        'min_budget' => $_GET['min_budget'] ?? '',
        'max_budget' => $_GET['max_budget'] ?? ''
    ];

    // Remove empty filters
    $filters = array_filter($filters, function($value) {
        return $value !== '' && $value !== null;
    });

    // Check if single project export
    if (isset($_GET['project_id'])) {
        $project = get_project_by_id($_GET['project_id']);
        if (!$project) {
            http_response_code(404);
            echo "Project not found";
            exit;
        }
        $projects = [$project];
        $filename = "project_{$project['id']}_details.pdf";
    } else {
        // Get projects based on filters
        $projects = get_projects($filters);
        $filename = "county_projects_" . date('Y-m-d_H-i-s') . ".pdf";
    }

    // Generate HTML content for PDF
    $html = generatePDFHTML($projects, $filters);

    // Set headers for PDF download
    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Cache-Control: private, max-age=0, must-revalidate');
    header('Pragma: public');

    // Simple HTML to PDF conversion using browser's print functionality
    // In production, use a proper PDF library like TCPDF or mPDF
    echo $html;

} catch (Exception $e) {
    error_log("PDF Export Error: " . $e->getMessage());
    http_response_code(500);
    echo "Export failed: " . $e->getMessage();
}

function generatePDFHTML($projects, $filters) {
    $total_projects = count($projects);
    $total_budget = array_sum(array_column($projects, 'budget'));
    
    $html = '<!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>County Projects Report</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                margin: 20px; 
                line-height: 1.4; 
                color: #333;
            }
            .header { 
                text-align: center; 
                margin-bottom: 30px; 
                border-bottom: 2px solid #333;
                padding-bottom: 20px;
            }
            .header h1 { 
                margin: 0; 
                color: #2563eb; 
                font-size: 24px;
            }
            .header .subtitle { 
                color: #666; 
                margin-top: 5px;
                font-size: 14px;
            }
            .summary { 
                background: #f8f9fa; 
                padding: 15px; 
                margin-bottom: 20px; 
                border-radius: 5px;
                border-left: 4px solid #2563eb;
            }
            .summary h3 { 
                margin: 0 0 10px 0; 
                color: #2563eb;
            }
            .summary-grid { 
                display: grid; 
                grid-template-columns: repeat(2, 1fr); 
                gap: 15px;
            }
            .summary-item { 
                background: white; 
                padding: 10px; 
                border-radius: 3px;
                border: 1px solid #e5e7eb;
            }
            .summary-item strong { 
                display: block; 
                color: #374151; 
                font-size: 18px;
            }
            .summary-item span { 
                color: #6b7280; 
                font-size: 12px;
            }
            .filters { 
                background: #f1f5f9; 
                padding: 10px; 
                margin-bottom: 20px; 
                border-radius: 5px;
                border: 1px solid #cbd5e1;
            }
            .filters h4 { 
                margin: 0 0 10px 0; 
                font-size: 14px;
                color: #475569;
            }
            .project { 
                border: 1px solid #e5e7eb; 
                margin-bottom: 20px; 
                padding: 15px; 
                border-radius: 5px;
                page-break-inside: avoid;
            }
            .project-header { 
                border-bottom: 1px solid #e5e7eb; 
                padding-bottom: 10px; 
                margin-bottom: 15px;
            }
            .project-title { 
                font-size: 18px; 
                font-weight: bold; 
                color: #1f2937; 
                margin: 0 0 5px 0;
            }
            .project-status { 
                display: inline-block; 
                padding: 3px 8px; 
                border-radius: 12px; 
                font-size: 11px; 
                font-weight: bold; 
                text-transform: uppercase;
            }
            .status-planning { background: #fef3c7; color: #92400e; }
            .status-ongoing { background: #dbeafe; color: #1e40af; }
            .status-completed { background: #d1fae5; color: #065f46; }
            .status-suspended { background: #fed7aa; color: #c2410c; }
            .status-cancelled { background: #fecaca; color: #991b1b; }
            .project-grid { 
                display: grid; 
                grid-template-columns: repeat(2, 1fr); 
                gap: 15px; 
                margin-top: 15px;
            }
            .project-info { 
                background: #f9fafb; 
                padding: 10px; 
                border-radius: 3px;
            }
            .project-info dt { 
                font-weight: bold; 
                color: #374151; 
                font-size: 12px; 
                margin-bottom: 2px;
            }
            .project-info dd { 
                margin: 0 0 8px 0; 
                color: #6b7280; 
                font-size: 14px;
            }
            .progress-bar { 
                width: 100%; 
                height: 8px; 
                background: #e5e7eb; 
                border-radius: 4px; 
                overflow: hidden;
                margin-top: 5px;
            }
            .progress-fill { 
                height: 100%; 
                background: #10b981; 
                border-radius: 4px;
            }
            .footer { 
                margin-top: 30px; 
                text-align: center; 
                font-size: 12px; 
                color: #6b7280; 
                border-top: 1px solid #e5e7eb; 
                padding-top: 15px;
            }
            @media print {
                .project { page-break-inside: avoid; }
                body { margin: 0; }
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>' . htmlspecialchars(APP_NAME) . '</h1>
            <div class="subtitle">County Projects Report - Generated on ' . date('F j, Y \a\t g:i A') . '</div>
        </div>';

    // Add filters if any
    $active_filters = array_filter($filters);
    if (!empty($active_filters)) {
        $html .= '<div class="filters">
            <h4>Applied Filters:</h4>';
        foreach ($active_filters as $key => $value) {
            $html .= '<strong>' . ucfirst(str_replace('_', ' ', $key)) . ':</strong> ' . htmlspecialchars($value) . ' &nbsp; ';
        }
        $html .= '</div>';
    }

    // Summary section
    $html .= '<div class="summary">
        <h3>Report Summary</h3>
        <div class="summary-grid">
            <div class="summary-item">
                <strong>' . number_format($total_projects) . '</strong>
                <span>Total Projects</span>
            </div>
            <div class="summary-item">
                <strong>' . format_currency($total_budget) . '</strong>
                <span>Total Budget</span>
            </div>
        </div>
    </div>';

    // Projects section
    if (empty($projects)) {
        $html .= '<div class="project">
            <h3 style="text-align: center; color: #6b7280;">No projects found matching the criteria.</h3>
        </div>';
    } else {
        foreach ($projects as $project) {
            $status_class = 'status-' . $project['status'];
            $progress_width = max(0, min(100, intval($project['progress_percentage'])));
            
            $html .= '<div class="project">
                <div class="project-header">
                    <div class="project-title">' . htmlspecialchars($project['project_name']) . '</div>
                    <span class="project-status ' . $status_class . '">' . ucfirst($project['status']) . '</span>
                </div>';

            if (!empty($project['description'])) {
                $html .= '<p style="margin: 0 0 15px 0; color: #4b5563;">' . htmlspecialchars($project['description']) . '</p>';
            }

            $html .= '<div class="project-grid">
                <div class="project-info">
                    <dt>Department</dt>
                    <dd>' . htmlspecialchars($project['department_name']) . '</dd>
                    
                    <dt>Location</dt>
                    <dd>' . htmlspecialchars($project['ward_name']) . ', ' . htmlspecialchars($project['sub_county_name']) . '</dd>
                    
                    <dt>Year</dt>
                    <dd>' . htmlspecialchars($project['project_year']) . '</dd>
                </div>
                
                <div class="project-info">
                    <dt>Budget</dt>
                    <dd>' . format_currency($project['budget']) . '</dd>';

            if (!empty($project['contractor_name'])) {
                $html .= '<dt>Contractor</dt>
                    <dd>' . htmlspecialchars($project['contractor_name']) . '</dd>';
            }

            if (!empty($project['start_date'])) {
                $html .= '<dt>Start Date</dt>
                    <dd>' . format_date($project['start_date']) . '</dd>';
            }

            $html .= '</div>
            </div>';

            if ($project['progress_percentage'] > 0) {
                $html .= '<div style="margin-top: 15px;">
                    <dt style="font-weight: bold; color: #374151; font-size: 12px; margin-bottom: 5px;">Progress: ' . $project['progress_percentage'] . '%</dt>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ' . $progress_width . '%"></div>
                    </div>
                </div>';
            }

            $html .= '</div>';
        }
    }

    $html .= '<div class="footer">
        <p>This report was generated automatically by ' . htmlspecialchars(APP_NAME) . '</p>
        <p>For questions or concerns, please contact the county administration.</p>
    </div>

    </body>
    </html>';

    return $html;
}

// Validate project ID
$project_id = (int)($_GET['project_id'] ?? 0);
if ($project_id <= 0) {
    http_response_code(400);
    exit('Invalid project ID');
}

// Get project details
$project = get_project_by_id($project_id);
if (!$project) {
    http_response_code(404);
    exit('Project not found');
}

// Check project visibility
if ($project['visibility'] === 'private' && !isset($_SESSION['admin_id'])) {
    http_response_code(403);
    exit('Access denied');
}

// Calculate progress
$progress = calculate_project_progress($project_id);

// Get project steps
$stmt = $pdo->prepare("SELECT * FROM project_steps WHERE project_id = ? ORDER BY step_number");
$stmt->execute([$project_id]);
$project_steps = $stmt->fetchAll();

// Get financial data
$financial_data = get_project_financial_summary($project_id);
$total_allocated = $financial_data['total_allocated'] ?? 0;
$total_spent = $financial_data['total_spent'] ?? 0;
$remaining_balance = $total_allocated - $total_spent;

// Get recent transactions
$recent_transactions = get_project_transactions($project_id);

// Set headers for PDF download
header('Content-Type: application/pdf');
header('Content-Disposition: attachment; filename="project_' . $project_id . '_report.pdf"');

// Generate HTML content for PDF
$html = '
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Project Report - ' . htmlspecialchars($project['project_name']) . '</title>
    <style>
        body { font-family: Arial, sans-serif; font-size: 12px; line-height: 1.4; }
        .header { text-align: center; margin-bottom: 30px; border-bottom: 2px solid #003366; padding-bottom: 20px; }
        .logo { font-size: 24px; font-weight: bold; color: #003366; margin-bottom: 10px; }
        .title { font-size: 20px; font-weight: bold; margin-bottom: 5px; }
        .subtitle { color: #666; font-size: 14px; }
        .section { margin-bottom: 25px; }
        .section-title { font-size: 16px; font-weight: bold; color: #003366; margin-bottom: 10px; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
        .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 15px; }
        .info-item { margin-bottom: 8px; }
        .info-label { font-weight: bold; color: #333; }
        .info-value { color: #666; }
        .progress-bar { background: #f0f0f0; height: 20px; border-radius: 10px; margin: 10px 0; }
        .progress-fill { background: linear-gradient(90deg, #facc15, #3b82f6, #22c55e); height: 100%; border-radius: 10px; }
        .financial-summary { background: #f9f9f9; padding: 15px; border-radius: 5px; margin-bottom: 15px; }
        .financial-item { display: inline-block; margin-right: 30px; margin-bottom: 10px; }
        .amount { font-weight: bold; font-size: 14px; }
        .amount.positive { color: #22c55e; }
        .amount.negative { color: #ef4444; }
        .amount.neutral { color: #3b82f6; }
        .steps-list { margin-top: 10px; }
        .step-item { margin-bottom: 15px; padding: 10px; border-left: 4px solid #ccc; background: #f9f9f9; }
        .step-item.completed { border-left-color: #22c55e; }
        .step-item.in-progress { border-left-color: #3b82f6; }
        .step-item.pending { border-left-color: #facc15; }
        .step-title { font-weight: bold; margin-bottom: 5px; }
        .step-status { font-size: 11px; padding: 3px 8px; border-radius: 12px; color: white; }
        .status-completed { background: #22c55e; }
        .status-in-progress { background: #3b82f6; }
        .status-pending { background: #facc15; color: #333; }
        .transactions-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        .transactions-table th, .transactions-table td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        .transactions-table th { background: #f5f5f5; font-weight: bold; }
        .transaction-allocation { color: #22c55e; }
        .transaction-expenditure { color: #ef4444; }
        .footer { margin-top: 30px; text-align: center; color: #666; font-size: 10px; border-top: 1px solid #ccc; padding-top: 15px; }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">MIGORI COUNTY PMC</div>
        <div class="title">' . htmlspecialchars($project['project_name']) . '</div>
        <div class="subtitle">Project Comprehensive Report - Generated on ' . date('F j, Y') . '</div>
    </div>

    <div class="section">
        <div class="section-title">Project Overview</div>
        <div class="info-grid">
            <div>
                <div class="info-item">
                    <span class="info-label">Project Name:</span>
                    <span class="info-value">' . htmlspecialchars($project['project_name']) . '</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Department:</span>
                    <span class="info-value">' . htmlspecialchars($project['department_name']) . '</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Location:</span>
                    <span class="info-value">' . htmlspecialchars($project['ward_name'] . ', ' . $project['sub_county_name']) . '</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Status:</span>
                    <span class="info-value">' . ucfirst($project['status']) . '</span>
                </div>
            </div>
            <div>
                <div class="info-item">
                    <span class="info-label">Project Year:</span>
                    <span class="info-value">' . $project['project_year'] . '</span>
                </div>';

if ($project['contractor_name']) {
    $html .= '
                <div class="info-item">
                    <span class="info-label">Contractor:</span>
                    <span class="info-value">' . htmlspecialchars($project['contractor_name']) . '</span>
                </div>';
}

if ($project['start_date']) {
    $html .= '
                <div class="info-item">
                    <span class="info-label">Start Date:</span>
                    <span class="info-value">' . format_date($project['start_date']) . '</span>
                </div>';
}

$html .= '
                <div class="info-item">
                    <span class="info-label">Overall Progress:</span>
                    <span class="info-value">' . $progress . '%</span>
                </div>
            </div>
        </div>

        <div class="progress-bar">
            <div class="progress-fill" style="width: ' . $progress . '%;"></div>
        </div>
    </div>

    <div class="section">
        <div class="section-title">Project Description</div>
        <p>' . nl2br(htmlspecialchars($project['description'])) . '</p>
    </div>';

// Financial Information
if ($total_allocated > 0) {
    $spent_percentage = $total_allocated > 0 ? ($total_spent / $total_allocated) * 100 : 0;
    
    $html .= '
    <div class="section">
        <div class="section-title">Financial Summary</div>
        <div class="financial-summary">
            <div class="financial-item">
                <div>Total Budget:</div>
                <div class="amount positive">KES ' . number_format($total_allocated) . '</div>
            </div>
            <div class="financial-item">
                <div>Total Spent:</div>
                <div class="amount negative">KES ' . number_format($total_spent) . '</div>
            </div>
            <div class="financial-item">
                <div>Remaining:</div>
                <div class="amount ' . ($remaining_balance >= 0 ? 'neutral' : 'negative') . '">KES ' . number_format($remaining_balance) . '</div>
            </div>
            <div class="financial-item">
                <div>Budget Utilization:</div>
                <div class="amount neutral">' . number_format($spent_percentage, 1) . '%</div>
            </div>
        </div>';

    // Recent Transactions
    if (!empty($recent_transactions)) {
        $html .= '
        <table class="transactions-table">
            <thead>
                <tr>
                    <th>Date</th>
                    <th>Description</th>
                    <th>Type</th>
                    <th>Amount</th>
                    <th>Reference</th>
                </tr>
            </thead>
            <tbody>';
        
        foreach (array_slice($recent_transactions, 0, 10) as $transaction) {
            $amount_class = $transaction['transaction_type'] === 'allocation' ? 'transaction-allocation' : 'transaction-expenditure';
            $amount_prefix = $transaction['transaction_type'] === 'allocation' ? '+' : '-';
            
            $html .= '
                <tr>
                    <td>' . date('M j, Y', strtotime($transaction['transaction_date'])) . '</td>
                    <td>' . htmlspecialchars($transaction['description']) . '</td>
                    <td>' . ucfirst($transaction['transaction_type']) . '</td>
                    <td class="' . $amount_class . '">' . $amount_prefix . 'KES ' . number_format($transaction['amount']) . '</td>
                    <td>' . htmlspecialchars($transaction['reference_number'] ?? '-') . '</td>
                </tr>';
        }
        
        $html .= '
            </tbody>
        </table>';
    }
    
    $html .= '
    </div>';
}

// Project Timeline
if (!empty($project_steps)) {
    $completed_steps = 0;
    $in_progress_steps = 0;
    $pending_steps = 0;
    
    foreach ($project_steps as $step) {
        switch ($step['status']) {
            case 'completed': $completed_steps++; break;
            case 'in_progress': $in_progress_steps++; break;
            default: $pending_steps++; break;
        }
    }
    
    $html .= '
    <div class="section">
        <div class="section-title">Project Timeline & Steps</div>
        <div class="financial-summary">
            <div class="financial-item">
                <div>Completed Steps:</div>
                <div class="amount positive">' . $completed_steps . '</div>
            </div>
            <div class="financial-item">
                <div>In Progress:</div>
                <div class="amount neutral">' . $in_progress_steps . '</div>
            </div>
            <div class="financial-item">
                <div>Pending:</div>
                <div class="amount">' . $pending_steps . '</div>
            </div>
            <div class="financial-item">
                <div>Total Steps:</div>
                <div class="amount">' . count($project_steps) . '</div>
            </div>
        </div>
        
        <div class="steps-list">';
    
    foreach ($project_steps as $step) {
        $step_class = str_replace('_', '-', $step['status']);
        $status_class = 'status-' . str_replace('_', '-', $step['status']);
        
        $html .= '
            <div class="step-item ' . $step_class . '">
                <div class="step-title">
                    ' . $step['step_number'] . '. ' . htmlspecialchars($step['step_name']) . '
                    <span class="step-status ' . $status_class . '">' . ucfirst(str_replace('_', ' ', $step['status'])) . '</span>
                </div>';
        
        if ($step['description']) {
            $html .= '<div>' . htmlspecialchars($step['description']) . '</div>';
        }
        
        if ($step['expected_end_date']) {
            $html .= '<div style="font-size: 11px; color: #666; margin-top: 5px;">Expected completion: ' . format_date($step['expected_end_date']) . '</div>';
        }
        
        $html .= '
            </div>';
    }
    
    $html .= '
        </div>
    </div>';
}

$html .= '
    <div class="footer">
        <p>This report was generated from the Migori County Project Management System</p>
        <p>© ' . date('Y') . ' Migori County Government - All rights reserved</p>
        <p>Generated on: ' . date('F j, Y \a\t g:i A') . '</p>
    </div>
</body>
</html>';

// Use a simple HTML to PDF conversion (this is a basic implementation)
// For production, you might want to use libraries like TCPDF, mPDF, or Dompdf

// Simple HTML to PDF conversion using browser print styles
echo '<script>
window.onload = function() {
    window.print();
};
</script>';

echo $html;
?>
