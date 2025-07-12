<?php
require_once '../config.php';
require_once '../includes/functions.php';
require_once '../includes/auth.php';

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Initialize session and check authentication
init_secure_session();

if (!is_logged_in()) {
    json_response(['success' => false, 'message' => 'Unauthorized access']);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_response(['success' => false, 'message' => 'Invalid request method']);
}

// Verify CSRF token
if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
    json_response(['success' => false, 'message' => 'Invalid security token']);
}

if ($_FILES['csv_file']['error'] !== UPLOAD_ERR_OK) {
    $error_messages = [
        UPLOAD_ERR_INI_SIZE => 'File too large (exceeds php.ini limit)',
        UPLOAD_ERR_FORM_SIZE => 'File too large (exceeds form limit)',
        UPLOAD_ERR_PARTIAL => 'File upload was interrupted',
        UPLOAD_ERR_NO_FILE => 'No file was uploaded',
        UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',
        UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',
        UPLOAD_ERR_EXTENSION => 'Upload stopped by extension'
    ];
    $error_msg = $error_messages[$_FILES['csv_file']['error']] ?? 'Unknown upload error';
    json_response(['success' => false, 'message' => $error_msg]);
}

$file_size = $_FILES['csv_file']['size'];
$file_name = $_FILES['csv_file']['name'];
$temp_path = $_FILES['csv_file']['tmp_name'];

if ($file_size === 0) {
    json_response(['success' => false, 'message' => 'Uploaded file is empty']);
}

$file_extension = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
if ($file_extension !== 'csv') {
    json_response(['success' => false, 'message' => 'Only CSV files are allowed']);
}

try {
    $handle = fopen($temp_path, 'r');
    if ($handle === false) {
        json_response(['success' => false, 'message' => 'Failed to read uploaded file']);
    }

    $headers = fgetcsv($handle);
    if ($headers === false) {
        fclose($handle);
        json_response(['success' => false, 'message' => 'Invalid CSV format - no headers found']);
    }

    $expected_headers = [
        'project_name','description','department','county','sub_county','ward',
        'location_address','location_coordinates','project_year','start_date',
        'expected_completion_date','contractor_name','contractor_contact',
        'total_budget','step_name','step_description'
    ];

    if (count($headers) !== count($expected_headers)) {
        fclose($handle);
        json_response([
            'success' => false, 
            'message' => 'CSV file format is incorrect. Please use the provided template.',
            'technical_details' => "Expected {count($expected_headers)} columns, found " . count($headers) . " columns"
        ]);
    }

    $pdo->beginTransaction();

    $success_count = 0;
    $error_count = 0;
    $errors = [];
    $row_number = 1;

    while (($data = fgetcsv($handle)) !== false) {
        $row_number++;

        if (strtolower(trim($data[0])) === 'project_name' || empty(array_filter($data))) {
            continue;
        }

        $data = array_pad($data, count($expected_headers), '');

        [$project_name, $description, $department_name, $county_name, $sub_county_name,
         $ward_name, $location_address, $location_coordinates, $project_year,
         $start_date, $expected_completion_date, $contractor_name, $contractor_contact,
         $total_budget, $step_name, $step_description] = array_map('trim', $data);

        // Check for missing required fields
        $missing_fields = [];
        if (empty($project_name)) $missing_fields[] = 'project name';
        if (empty($department_name)) $missing_fields[] = 'department';
        if (empty($county_name)) $missing_fields[] = 'county';
        if (empty($sub_county_name)) $missing_fields[] = 'sub-county';
        if (empty($ward_name)) $missing_fields[] = 'ward';
        
        if (!empty($missing_fields)) {
            $errors[] = [
                'user_message' => "Row {$row_number}: Please fill in the " . implode(', ', $missing_fields),
                'technical_details' => "Row {$row_number}: Missing required fields: " . implode(', ', $missing_fields)
            ];
            $error_count++;
            continue;
        }

        try {
            $stmt = $pdo->prepare("SELECT id FROM departments WHERE name = ?");
            $stmt->execute([$department_name]);
            $department_id = $stmt->fetchColumn();
            if (!$department_id) {
                throw new Exception("Department '{$department_name}' not found in the system");
            }

            $stmt = $pdo->prepare("SELECT id FROM counties WHERE name = ?");
            $stmt->execute([$county_name]);
            $county_id = $stmt->fetchColumn();
            if (!$county_id) {
                throw new Exception("County '{$county_name}' not found in the system");
            }

            $stmt = $pdo->prepare("SELECT id FROM sub_counties WHERE name = ? AND county_id = ?");
            $stmt->execute([$sub_county_name, $county_id]);
            $sub_county_id = $stmt->fetchColumn();
            if (!$sub_county_id) {
                throw new Exception("Sub-county '{$sub_county_name}' not found in '{$county_name}' county");
            }

            $stmt = $pdo->prepare("SELECT id FROM wards WHERE name = ? AND sub_county_id = ?");
            $stmt->execute([$ward_name, $sub_county_id]);
            $ward_id = $stmt->fetchColumn();
            if (!$ward_id) {
                throw new Exception("Ward '{$ward_name}' not found in '{$sub_county_name}' sub-county");
            }

            $duplicate_check = $pdo->prepare("SELECT id FROM projects WHERE project_name = ?");
            $duplicate_check->execute([$project_name]);
            if ($duplicate_check->fetch()) {
                throw new Exception("Project '{$project_name}' already exists in the system");
            }

            if (!empty($location_coordinates) && strpos($location_coordinates, '-') !== 0) {
                $location_coordinates = '-' . ltrim($location_coordinates, '-');
            }

            // Validate and format budget
            $total_budget_formatted = null;
            if (!empty($total_budget)) {
                $total_budget_cleaned = preg_replace('/[^\d.]/', '', $total_budget);
                if (is_numeric($total_budget_cleaned) && $total_budget_cleaned > 0) {
                    $total_budget_formatted = floatval($total_budget_cleaned);
                }
            }

            $start_date_formatted = !empty($start_date) ? date('Y-m-d', strtotime($start_date)) : null;
            $expected_completion_formatted = !empty($expected_completion_date) ? date('Y-m-d', strtotime($expected_completion_date)) : null;

            $stmt = $pdo->prepare("INSERT INTO projects (
                project_name, description, department_id, county_id, sub_county_id, ward_id,
                location_address, location_coordinates, project_year, start_date,
                expected_completion_date, contractor_name, contractor_contact, total_budget, status,
                visibility, total_steps, completed_steps, progress_percentage, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'planning', 'private', 1, 0, 0, ?, NOW())");

            $stmt->execute([
                $project_name, $description, $department_id, $county_id, $sub_county_id, $ward_id,
                $location_address, $location_coordinates, intval($project_year),
                $start_date_formatted, $expected_completion_formatted,
                $contractor_name, $contractor_contact, $total_budget_formatted, $_SESSION['admin_id']
            ]);

            $project_id = $pdo->lastInsertId();

            // Insert budget data into total_budget table if budget is provided
            if ($total_budget_formatted && $total_budget_formatted > 0) {
                $fiscal_year = $project_year . '/' . ($project_year + 1);
                $budget_stmt = $pdo->prepare("INSERT INTO total_budget (
                    project_id, budget_amount, budget_type, budget_source, fiscal_year,
                    approval_status, created_by, created_at
                ) VALUES (?, ?, 'initial', 'County Development Fund', ?, 'approved', ?, NOW())");

                $budget_stmt->execute([
                    $project_id, 
                    $total_budget_formatted, 
                    $fiscal_year, 
                    $_SESSION['admin_id']
                ]);
            }

            $step_name_final = $step_name ?: 'Project Planning & Approval';
            $step_description_final = $step_description ?: 'Initial planning, design, and approvals';

            $stmt = $pdo->prepare("INSERT INTO project_steps (
                project_id, step_number, step_name, description, status, created_at
            ) VALUES (?, 1, ?, ?, 'pending', NOW())");
            $stmt->execute([$project_id, $step_name_final, $step_description_final]);

            $success_count++;

        } catch (Exception $e) {
            $error_message = $e->getMessage();
            $errors[] = [
                'user_message' => "Row {$row_number}: {$error_message}",
                'technical_details' => "Row {$row_number}: {$error_message} | Project: {$project_name}"
            ];
            $error_count++;
        }
    }

    fclose($handle);

    // Log the import results
    $error_details = null;
    if (!empty($errors)) {
        $error_details = json_encode($errors);
    }

    $log_stmt = $pdo->prepare("INSERT INTO import_logs (
        filename, total_rows, successful_imports, failed_imports, 
        error_details, imported_by, imported_at
    ) VALUES (?, ?, ?, ?, ?, ?, NOW())");
    
    $log_stmt->execute([
        $file_name,
        $row_number - 1, // Total rows processed (excluding header)
        $success_count,
        $error_count,
        $error_details,
        $_SESSION['admin_id']
    ]);

    $pdo->commit();

    json_response([
        'success' => $success_count > 0,
        'message' => $success_count > 0 ? "Imported {$success_count} projects with {$error_count} errors" : 'No projects were imported',
        'imported_count' => $success_count,
        'error_count' => $error_count,
        'errors' => $errors
    ]);

} catch (Throwable $e) {
    error_log("Fatal error in upload_csv: " . $e->getMessage());
    json_response(['success' => false, 'message' => 'Unexpected server error']);
}
?>