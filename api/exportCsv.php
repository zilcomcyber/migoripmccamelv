<?php
require_once '../config.php';
require_once '../includes/functions.php';

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

    // Get projects based on filters
    $projects = get_projects($filters);

    // Generate filename
    $filename = "county_projects_" . date('Y-m-d_H-i-s') . ".csv";

    // Set headers for CSV download
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Cache-Control: private, max-age=0, must-revalidate');
    header('Pragma: public');

    // Create file pointer connected to the output stream
    $output = fopen('php://output', 'w');

    // Add BOM for proper Excel UTF-8 handling
    fprintf($output, chr(0xEF).chr(0xBB).chr(0xBF));

    // CSV headers
    $headers = [
        'Project ID',
        'Project Name',
        'Description',
        'Department',
        'Ward',
        'Sub County',
        'County',
        'Status',
        'Progress (%)',
        'Year',
        'Contractor',
        'Contractor Contact',
        'Start Date',
        'Expected Completion',
        'Actual Completion',
        'Location Coordinates',
        'Location Address',
        'Created Date'
    ];

    // Write headers to CSV
    fputcsv($output, $headers);

    // Write project data
    foreach ($projects as $project) {
        $row = [
            $project['id'],
            $project['project_name'],
            $project['description'] ?? '',
            $project['department_name'],
            $project['ward_name'],
            $project['sub_county_name'],
            $project['county_name'],
            ucfirst($project['status']),
            $project['progress_percentage'],
            $project['project_year'],
            $project['contractor_name'] ?? '',
            $project['contractor_contact'] ?? '',
            $project['start_date'] ?? '',
            $project['expected_completion_date'] ?? '',
            $project['actual_completion_date'] ?? '',
            $project['location_coordinates'] ?? '',
            $project['location_address'] ?? '',
            $project['created_at']
        ];

        fputcsv($output, $row);
    }

    // Close the file pointer
    fclose($output);

} catch (Exception $e) {
    error_log("CSV Export Error: " . $e->getMessage());
    http_response_code(500);
    echo "Export failed: " . $e->getMessage();
}
?>
