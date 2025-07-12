<?php
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

require_admin();

$current_admin = get_current_admin();

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid security token';
        header("Location: createProject.php?error=" . urlencode($error));
        exit();
    } else {
        $action = $_POST['action'] ?? '';

        if ($action === 'create_project') {
            $result = handle_project_creation($_POST);
            if ($result['success']) {
                $project_id = $result['project_id'];

                // Check if user has permission to manage projects, otherwise redirect to projects list
                if (has_permission('manage_projects') || has_permission('view_projects')) {
                    if (has_permission('manage_projects')) {
                        header("Location: manageProject.php?id=$project_id&created=1");
                    } else {
                        header("Location: projects.php?created=1&project_id=$project_id");
                    }
                } else {
                    // Fallback to dashboard with success message
                    header("Location: index.php?created=1&project_name=" . urlencode($result['project_name'] ?? 'New Project'));
                }
                exit();
            } else {
                $error = $result['message'];
                header("Location: createProject.php?error=" . urlencode($error));
                exit();
            }
        }
    }
} else {
    // Redirect if not POST request
    header("Location: createProject.php");
    exit();
}

function handle_project_creation($data) {
    global $pdo, $current_admin;

    try {
        // Validate required fields
        $required_fields = ['project_name', 'department_id', 'project_year', 'county_id', 'sub_county_id', 'ward_id'];
        foreach ($required_fields as $field) {
            if (empty($data[$field])) {
                return ['success' => false, 'message' => "Please fill in all required fields. Missing: $field"];
            }
        }

        $pdo->beginTransaction();

        // Check for duplicate project name
        $duplicate_check = $pdo->prepare("SELECT COUNT(*) FROM projects WHERE LOWER(project_name) = LOWER(?)");
        $duplicate_check->execute([trim(strip_tags($data['project_name']))]);
        if ($duplicate_check->fetchColumn() > 0) {
            return ['success' => false, 'message' => 'A project with this name already exists. Please choose a different name.'];
        }

        // Create project - using prepared statements for SQL safety
        $sql = "INSERT INTO projects (
                    project_name, description, department_id, project_year,
                    county_id, sub_county_id, ward_id, location_address, location_coordinates,
                    contractor_name, contractor_contact, start_date, expected_completion_date, 
                    total_budget, status, visibility, step_status, progress_percentage, total_steps, completed_steps, created_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        // Basic sanitization (trim whitespace, remove tags) without HTML encoding
        $total_budget = null;
        if (!empty($data['total_budget']) && is_numeric($data['total_budget'])) {
            $total_budget = floatval($data['total_budget']);
        }

        $params = [
            trim(strip_tags($data['project_name'])),
            isset($data['description']) ? trim(strip_tags($data['description'])) : '',
            intval($data['department_id']),
            intval($data['project_year']),
            intval($data['county_id']),
            intval($data['sub_county_id']),
            intval($data['ward_id']),
            isset($data['location_address']) ? trim(strip_tags($data['location_address'])) : '',
            isset($data['location_coordinates']) ? trim(strip_tags($data['location_coordinates'])) : '',
            isset($data['contractor_name']) ? trim(strip_tags($data['contractor_name'])) : '',
            isset($data['contractor_contact']) ? trim(strip_tags($data['contractor_contact'])) : '',
            !empty($data['start_date']) ? $data['start_date'] : null,
            !empty($data['expected_completion_date']) ? $data['expected_completion_date'] : null,
            $total_budget,
            'planning', // default status
            'private', // default visibility
            'awaiting', // default step_status
            0, // default progress_percentage
            0, // total_steps (will be updated after inserting steps)
            0, // completed_steps
            $current_admin['id']
        ];

        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $project_id = $pdo->lastInsertId();

        // Create project steps if provided
        $total_steps = 0;
        $completed_steps = 0;

        if (!empty($data['steps']) && is_array($data['steps'])) {
            $step_sql = "INSERT INTO project_steps (
                            project_id, step_number, step_name, description, 
                            status, expected_end_date, actual_end_date
                         ) VALUES (?, ?, ?, ?, ?, ?, ?)";
            $step_stmt = $pdo->prepare($step_sql);

            foreach ($data['steps'] as $index => $step) {
                if (!empty($step['name'])) {
                    $step_status = 'pending';
                    $actual_end_date = null;

                    // Process expected date if provided
                    if (!empty($step['expected_date'])) {
                        $expected_date = $step['expected_date'];
                        if (strtotime($expected_date) <= time()) {
                            $step_status = 'completed';
                            $actual_end_date = $expected_date;
                            $completed_steps++;
                        }
                    } else {
                        $expected_date = null;
                    }

                    // Store raw input (prepared statements handle SQL safety)
                    // Only basic cleaning (trim + strip_tags) without HTML encoding
                    $step_stmt->execute([
                        $project_id,
                        $index + 1,
                        trim(strip_tags($step['name'])),
                        isset($step['description']) ? trim(strip_tags($step['description'])) : '',
                        $step_status,
                        $expected_date,
                        $actual_end_date
                    ]);

                    $total_steps++;
                }
            }
        }

        // Calculate progress percentage
        $progress_percentage = ($total_steps > 0) ? round(($completed_steps / $total_steps) * 100, 2) : 0;

        // Update project status based on progress
        $project_status = 'planning';
        $step_status = 'awaiting';

        if ($progress_percentage > 0 && $progress_percentage < 100) {
            $project_status = 'ongoing';
            $step_status = 'running';
        } elseif ($progress_percentage == 100) {
            $project_status = 'completed';
            $step_status = 'completed';
        }

        // Update project with step counts and progress
        $update_sql = "UPDATE projects SET 
                        total_steps = ?, 
                        completed_steps = ?, 
                        progress_percentage = ?, 
                        status = ?, 
                        step_status = ? 
                       WHERE id = ?";
        $pdo->prepare($update_sql)->execute([
            $total_steps, 
            $completed_steps, 
            $progress_percentage, 
            $project_status, 
            $step_status, 
            $project_id
        ]);

        // Insert budget data into total_budget table if budget is provided
        if ($total_budget && $total_budget > 0) {
            $fiscal_year = $data['project_year'] . '/' . ($data['project_year'] + 1);
            $budget_stmt = $pdo->prepare("INSERT INTO total_budget (
                project_id, budget_amount, budget_type, budget_source, fiscal_year,
                approval_status, created_by, created_at
            ) VALUES (?, ?, 'initial', 'County Development Fund', ?, 'approved', ?, NOW())");

            $budget_stmt->execute([
                $project_id, 
                $total_budget, 
                $fiscal_year, 
                $current_admin['id']
            ]);
        }

        $pdo->commit();
        log_activity("Project created: " . $data['project_name'], $current_admin['id']);

        return [
            'success' => true, 
            'message' => 'Project created successfully', 
            'project_id' => $project_id,
            'project_name' => $data['project_name']
        ];

    } catch (Exception $e) {
        $pdo->rollBack();
        error_log("Project creation error: " . $e->getMessage());
        header("Location: createProject.php?error=" . urlencode("Failed to create project. Please try again."));
        exit();
    }
}