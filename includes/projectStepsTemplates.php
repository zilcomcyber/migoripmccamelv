<?php

// Default project steps templates for different departments

function get_default_project_steps($department_name) {
    // Single default step for all departments
    $default_step = [
        ['step_name' => 'Project Planning & Approval', 'description' => 'Initial project planning, design review, and regulatory approval process']
    ];

    // Return the same single step regardless of department
    return $default_step;
}

/**
 * Generate steps for all existing projects that don't have steps
 */
function generate_missing_project_steps() {
    global $pdo;

    // Get all projects without steps
    $stmt = $pdo->query("
        SELECT p.id, p.project_name, d.name as department_name 
        FROM projects p 
        JOIN departments d ON p.department_id = d.id 
        WHERE p.id NOT IN (SELECT DISTINCT project_id FROM project_steps)
    ");

    $projects_without_steps = $stmt->fetchAll();
    $generated_count = 0;

    foreach ($projects_without_steps as $project) {
        if (create_project_steps($project['id'], $project['department_name'])) {
            $generated_count++;
        }
    }

    return [
        'total_projects' => count($projects_without_steps),
        'generated' => $generated_count
    ];
}
?>