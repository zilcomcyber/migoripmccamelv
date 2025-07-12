<?php
require_once '../config.php';
require_once '../includes/auth.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);

if (!isset($input['project_name']) || empty(trim($input['project_name']))) {
    echo json_encode(['exists' => false]);
    exit;
}

$project_name = trim($input['project_name']);
$department_id = $input['department_id'] ?? null;
$project_year = $input['project_year'] ?? null;
$total_budget = $input['total_budget'] ?? null;
$ward_id = $input['ward_id'] ?? null;
$sub_county_id = $input['sub_county_id'] ?? null;

try {
    $duplicate_checks = [];
    
    // Check 1: Exact same project name in same department and year
    if ($department_id && $project_year) {
        $stmt = $pdo->prepare("
            SELECT id, project_name, project_year, total_budget, department_id 
            FROM projects 
            WHERE LOWER(project_name) = LOWER(?) 
            AND department_id = ? 
            AND project_year = ?
        ");
        $stmt->execute([$project_name, $department_id, $project_year]);
        $exact_match = $stmt->fetch();
        
        if ($exact_match) {
            $duplicate_checks[] = [
                'type' => 'exact_match',
                'message' => 'A project with this exact name already exists in the same department and year',
                'severity' => 'high',
                'project_id' => $exact_match['id']
            ];
        }
    }
    
    // Check 2: Very similar project name (90%+ similarity) in same department
    if ($department_id) {
        $stmt = $pdo->prepare("
            SELECT id, project_name, project_year, total_budget 
            FROM projects 
            WHERE department_id = ? 
            AND project_name != ?
        ");
        $stmt->execute([$department_id, $project_name]);
        $similar_projects = $stmt->fetchAll();
        
        foreach ($similar_projects as $similar) {
            $similarity = similarity($project_name, $similar['project_name']);
            if ($similarity >= 0.9) {
                $duplicate_checks[] = [
                    'type' => 'similar_name',
                    'message' => "Very similar project name found: '{$similar['project_name']}'",
                    'severity' => 'medium',
                    'similarity' => round($similarity * 100, 1) . '%',
                    'project_id' => $similar['id']
                ];
            }
        }
    }
    
    // Check 3: Same budget amount in same location (ward/sub-county)
    if ($total_budget && $total_budget > 0) {
        $budget_tolerance = $total_budget * 0.05; // 5% tolerance
        $location_condition = '';
        $location_params = [];
        
        if ($ward_id) {
            $location_condition = " AND ward_id = ?";
            $location_params[] = $ward_id;
        } elseif ($sub_county_id) {
            $location_condition = " AND sub_county_id = ?";
            $location_params[] = $sub_county_id;
        }
        
        if ($location_condition) {
            $stmt = $pdo->prepare("
                SELECT id, project_name, total_budget, project_year 
                FROM projects 
                WHERE total_budget BETWEEN ? AND ?" . $location_condition . "
                AND project_name != ?
            ");
            
            $params = [
                $total_budget - $budget_tolerance,
                $total_budget + $budget_tolerance,
                ...$location_params,
                $project_name
            ];
            
            $stmt->execute($params);
            $budget_matches = $stmt->fetchAll();
            
            foreach ($budget_matches as $match) {
                $duplicate_checks[] = [
                    'type' => 'budget_location_match',
                    'message' => "Similar budget amount (KES " . number_format($match['total_budget']) . ") found in same location: '{$match['project_name']}'",
                    'severity' => 'medium',
                    'project_id' => $match['id']
                ];
            }
        }
    }
    
    // Check 4: Multiple matching criteria (name similarity + department + year)
    if ($department_id && $project_year) {
        $stmt = $pdo->prepare("
            SELECT id, project_name, total_budget 
            FROM projects 
            WHERE department_id = ? 
            AND project_year = ?
            AND project_name != ?
        ");
        $stmt->execute([$department_id, $project_year, $project_name]);
        $dept_year_projects = $stmt->fetchAll();
        
        foreach ($dept_year_projects as $project) {
            $similarity = similarity($project_name, $project['project_name']);
            if ($similarity >= 0.7) { // 70% similarity threshold
                $duplicate_checks[] = [
                    'type' => 'multiple_criteria',
                    'message' => "Potential duplicate in same department and year: '{$project['project_name']}'",
                    'severity' => 'medium',
                    'similarity' => round($similarity * 100, 1) . '%',
                    'project_id' => $project['id']
                ];
            }
        }
    }
    
    // Determine overall duplicate status
    $has_high_severity = false;
    $has_medium_severity = false;
    
    foreach ($duplicate_checks as $check) {
        if ($check['severity'] === 'high') {
            $has_high_severity = true;
            break;
        } elseif ($check['severity'] === 'medium') {
            $has_medium_severity = true;
        }
    }
    
    $response = [
        'exists' => $has_high_severity,
        'warnings' => $has_medium_severity && !$has_high_severity,
        'checks' => $duplicate_checks,
        'total_issues' => count($duplicate_checks),
        'recommendation' => getDuplicateRecommendation($duplicate_checks)
    ];
    
    echo json_encode($response);
    
} catch (Exception $e) {
    error_log("Enhanced duplicate check error: " . $e->getMessage());
    echo json_encode([
        'exists' => false, 
        'error' => 'Unable to verify project details. Please try again.',
        'checks' => [],
        'total_issues' => 0
    ]);
}

// Helper function to calculate string similarity
function similarity($str1, $str2) {
    $str1 = strtolower(trim($str1));
    $str2 = strtolower(trim($str2));
    
    if ($str1 === $str2) return 1.0;
    
    // Use Levenshtein distance for similarity calculation
    $maxLen = max(strlen($str1), strlen($str2));
    if ($maxLen == 0) return 1.0;
    
    $distance = levenshtein($str1, $str2);
    return 1 - ($distance / $maxLen);
}

// Helper function to provide recommendations
function getDuplicateRecommendation($checks) {
    if (empty($checks)) {
        return 'No duplicate concerns found. You can proceed with creating this project.';
    }
    
    $high_severity = array_filter($checks, function($check) {
        return $check['severity'] === 'high';
    });
    
    if (!empty($high_severity)) {
        return 'This project appears to be a duplicate. Please verify the project details or modify the project name to make it unique.';
    }
    
    $medium_severity = array_filter($checks, function($check) {
        return $check['severity'] === 'medium';
    });
    
    if (!empty($medium_severity)) {
        return 'Similar projects detected. Please review the warnings and ensure this is indeed a new project.';
    }
    
    return 'Minor similarities detected. Please verify project details are correct.';
}
?>
