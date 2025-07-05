<?php
require_once '../config.php';
require_once '../includes/functions.php';

header('Content-Type: application/json');

try {
    $action = $_GET['action'] ?? '';
    
    switch ($action) {
        case 'sub_counties':
            $county_id = intval($_GET['county_id'] ?? 0);
            if ($county_id > 0) {
                $sub_counties = get_sub_counties($county_id);
                if ($sub_counties !== false) {
                    json_response(['success' => true, 'data' => $sub_counties]);
                } else {
                    json_response(['success' => false, 'message' => 'Failed to load sub-counties']);
                }
            } else {
                json_response(['success' => false, 'message' => 'Invalid county ID']);
            }
            break;
            
        case 'wards':
            $sub_county_id = intval($_GET['sub_county_id'] ?? 0);
            if ($sub_county_id > 0) {
                $wards = get_wards($sub_county_id);
                if ($wards !== false) {
                    json_response(['success' => true, 'data' => $wards]);
                } else {
                    json_response(['success' => false, 'message' => 'Failed to load wards']);
                }
            } else {
                json_response(['success' => false, 'message' => 'Invalid sub-county ID']);
            }
            break;
            
        default:
            json_response(['success' => false, 'message' => 'Invalid action']);
    }
    
} catch (Exception $e) {
    error_log("Locations API Error: " . $e->getMessage());
    json_response(['success' => false, 'message' => 'Database error: ' . $e->getMessage()], 500);
}
?>
