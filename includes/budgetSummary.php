<?php
/**
 * Budget Summary Functions
 * Functions to calculate and display project budget information including increases
 */

function get_project_budget_summary($project_id) {
    global $pdo;
    
    try {
        // Get base budget
        $stmt = $pdo->prepare("SELECT total_budget FROM projects WHERE id = ?");
        $stmt->execute([$project_id]);
        $project = $stmt->fetch();
        $base_budget = $project['total_budget'] ?? 0;
        
        // Get budget increases
        $stmt = $pdo->prepare("
            SELECT SUM(amount) as total_increases
            FROM project_transactions 
            WHERE project_id = ? 
            AND transaction_type = 'budget_increase' 
            AND transaction_status = 'active'
        ");
        $stmt->execute([$project_id]);
        $result = $stmt->fetch();
        $budget_increases = $result['total_increases'] ?? 0;
        
        // Get total expenditure
        $stmt = $pdo->prepare("
            SELECT SUM(amount) as total_expenditure
            FROM project_transactions 
            WHERE project_id = ? 
            AND transaction_type = 'expenditure' 
            AND transaction_status = 'active'
        ");
        $stmt->execute([$project_id]);
        $result = $stmt->fetch();
        $total_expenditure = $result['total_expenditure'] ?? 0;
        
        // Get total disbursements
        $stmt = $pdo->prepare("
            SELECT SUM(amount) as total_disbursed
            FROM project_transactions 
            WHERE project_id = ? 
            AND transaction_type = 'disbursement' 
            AND transaction_status = 'active'
        ");
        $stmt->execute([$project_id]);
        $result = $stmt->fetch();
        $total_disbursed = $result['total_disbursed'] ?? 0;
        
        $total_approved = $base_budget + $budget_increases;
        $remaining_budget = $total_approved - $total_expenditure;
        
        return [
            'base_budget' => $base_budget,
            'budget_increases' => $budget_increases,
            'total_approved' => $total_approved,
            'total_expenditure' => $total_expenditure,
            'total_disbursed' => $total_disbursed,
            'remaining_budget' => $remaining_budget,
            'expenditure_percentage' => $total_approved > 0 ? ($total_expenditure / $total_approved) * 100 : 0
        ];
        
    } catch (Exception $e) {
        error_log("Get project budget summary error: " . $e->getMessage());
        return [
            'base_budget' => 0,
            'budget_increases' => 0,
            'total_approved' => 0,
            'total_expenditure' => 0,
            'total_disbursed' => 0,
            'remaining_budget' => 0,
            'expenditure_percentage' => 0
        ];
    }
}

function display_budget_summary_card($project_id) {
    $budget = get_project_budget_summary($project_id);
    ?>
    <div class="bg-white rounded-lg shadow-md p-6 mb-6">
        <h3 class="text-lg font-semibold text-gray-900 mb-4">Budget Summary</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div class="text-center">
                <div class="text-2xl font-bold text-blue-600">KES <?php echo number_format($budget['base_budget']); ?></div>
                <div class="text-sm text-gray-500">Original Budget</div>
            </div>
            
            <?php if ($budget['budget_increases'] > 0): ?>
            <div class="text-center">
                <div class="text-2xl font-bold text-green-600">+KES <?php echo number_format($budget['budget_increases']); ?></div>
                <div class="text-sm text-gray-500">Budget Increases</div>
            </div>
            <?php endif; ?>
            
            <div class="text-center">
                <div class="text-2xl font-bold text-purple-600">KES <?php echo number_format($budget['total_approved']); ?></div>
                <div class="text-sm text-gray-500">Total Approved</div>
            </div>
            
            <div class="text-center">
                <div class="text-2xl font-bold text-red-600">KES <?php echo number_format($budget['total_expenditure']); ?></div>
                <div class="text-sm text-gray-500">Total Spent (<?php echo number_format($budget['expenditure_percentage'], 1); ?>%)</div>
            </div>
            
            <div class="text-center">
                <div class="text-2xl font-bold text-orange-600">KES <?php echo number_format($budget['total_disbursed']); ?></div>
                <div class="text-sm text-gray-500">Total Disbursed</div>
            </div>
            
            <div class="text-center">
                <div class="text-2xl font-bold <?php echo $budget['remaining_budget'] >= 0 ? 'text-green-600' : 'text-red-600'; ?>">
                    KES <?php echo number_format($budget['remaining_budget']); ?>
                </div>
                <div class="text-sm text-gray-500">Remaining Budget</div>
            </div>
        </div>
    </div>
    <?php
}
?>
