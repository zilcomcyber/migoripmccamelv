<?php
/**
 * Project Publication Validation System
 * Validates if a project meets all criteria for public publication
 */

class ProjectPublicationValidator {
    private $pdo;
    private $errors = [];
    
    public function __construct($pdo) {
        $this->pdo = $pdo;
    }
    
    /**
     * Validate if project can be published publicly
     */
    public function validateForPublication($project_id) {
        $this->errors = [];
        
        // Get project data with all necessary joins
        $project = $this->getProjectWithDetails($project_id);
        if (!$project) {
            $this->errors[] = "Project not found";
            return false;
        }
        
        // Run all validation checks
        $this->validateContentCompleteness($project);
        $this->validateFinancialStandards($project);
        $this->validateDocumentationStandards($project_id);
        $this->validateLocationStandards($project);
        $this->validateAdministrativeStandards($project);
        $this->validateQualityAssurance($project);
        
        return empty($this->errors);
    }
    
    /**
     * Get validation errors
     */
    public function getErrors() {
        return $this->errors;
    }
    
    /**
     * Get project validation status for UI display
     */
    public function getValidationStatus($project_id) {
        $isValid = $this->validateForPublication($project_id);
        return [
            'is_valid' => $isValid,
            'errors' => $this->errors,
            'can_publish' => $isValid
        ];
    }
    
    private function getProjectWithDetails($project_id) {
        $stmt = $this->pdo->prepare("
            SELECT p.*, d.name as department_name, w.name as ward_name, 
                   sc.name as sub_county_name, c.name as county_name
            FROM projects p
            LEFT JOIN departments d ON p.department_id = d.id
            LEFT JOIN wards w ON p.ward_id = w.id
            LEFT JOIN sub_counties sc ON p.sub_county_id = sc.id
            LEFT JOIN counties c ON p.county_id = c.id
            WHERE p.id = ?
        ");
        $stmt->execute([$project_id]);
        return $stmt->fetch();
    }
    
    private function validateContentCompleteness($project) {
        // Project Description
        if (empty($project['description']) || strlen(trim($project['description'])) < 30) {
            $this->errors[] = "Project description must be at least 30 characters long";
        }
        
        // Step validation
        $stmt = $this->pdo->prepare("SELECT * FROM project_steps WHERE project_id = ? ORDER BY step_number");
        $stmt->execute([$project['id']]);
        $steps = $stmt->fetchAll();
        
        if (count($steps) < 4) {
            $this->errors[] = "Project must have at least 4 steps for proper planning";
        }
        
        foreach ($steps as $step) {
            if (empty($step['description']) || strlen(trim($step['description'])) < 15) {
                $this->errors[] = "Step '{$step['step_name']}' must have a description of at least 15 characters";
            }
        }
        
        // Contractor Information
        if (empty($project['contractor_name'])) {
            $this->errors[] = "Contractor name is required for public projects";
        }
    }
    
    private function validateFinancialStandards($project) {
        if (empty($project['total_budget']) || $project['total_budget'] <= 0) {
            $this->errors[] = "Project must have a valid budget amount greater than 0";
        }
    }
    
    private function validateDocumentationStandards($project_id) {
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) as doc_count 
            FROM project_documents 
            WHERE project_id = ? AND document_status = 'active'
        ");
        $stmt->execute([$project_id]);
        $result = $stmt->fetch();
        
        if ($result['doc_count'] == 0) {
            $this->errors[] = "Project must have at least one active document attached";
        }
    }
    
    private function validateLocationStandards($project) {
        // Valid Coordinates
        if (empty($project['location_coordinates'])) {
            $this->errors[] = "Project must have location coordinates";
        } else {
            $coords = explode(',', $project['location_coordinates']);
            if (count($coords) != 2) {
                $this->errors[] = "Location coordinates must be in format: latitude,longitude";
            } else {
                $lat = floatval(trim($coords[0]));
                $lng = floatval(trim($coords[1]));
                
                // Kenya bounds validation
                if ($lat < -4.7 || $lat > 5.0) {
                    $this->errors[] = "Latitude must be within Kenya's geographic bounds (-4.7 to 5.0)";
                }
                if ($lng < 33.9 || $lng > 41.9) {
                    $this->errors[] = "Longitude must be within Kenya's geographic bounds (33.9 to 41.9)";
                }
            }
        }
        
        // Location Address
        if (empty($project['location_address'])) {
            $this->errors[] = "Project must have a physical address description";
        }
    }
    
    private function validateAdministrativeStandards($project) {
        if (empty($project['department_id']) || empty($project['department_name'])) {
            $this->errors[] = "Project must be assigned to a valid department";
        }
        
        if (empty($project['ward_id']) || empty($project['ward_name'])) {
            $this->errors[] = "Project must be assigned to a specific ward";
        }
        
        if (empty($project['project_year']) || $project['project_year'] < 2020 || $project['project_year'] > date('Y') + 2) {
            $this->errors[] = "Project must have a valid project year";
        }
    }
    
    private function validateQualityAssurance($project) {
        // Duplicate Check
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) as count 
            FROM projects 
            WHERE project_name = ? AND ward_id = ? AND id != ?
        ");
        $stmt->execute([$project['project_name'], $project['ward_id'], $project['id']]);
        $result = $stmt->fetch();
        
        if ($result['count'] > 0) {
            $this->errors[] = "A project with this name already exists in the same ward";
        }
        
        // Name Standards
        if (strlen(trim($project['project_name'])) < 10) {
            $this->errors[] = "Project name must be at least 10 characters long";
        }
        
        // Basic profanity check (simple implementation)
        $offensive_words = ['damn', 'hell', 'shit', 'fuck', 'bitch']; // Add more as needed
        $project_name_lower = strtolower($project['project_name']);
        foreach ($offensive_words as $word) {
            if (strpos($project_name_lower, $word) !== false) {
                $this->errors[] = "Project name contains inappropriate language";
                break;
            }
        }
    }
    
    /**
     * Log publication attempt
     */
    public function logPublicationAttempt($project_id, $admin_id, $success, $errors = []) {
        $stmt = $this->pdo->prepare("
            INSERT INTO publication_logs 
            (project_id, admin_id, attempt_date, success, errors, ip_address) 
            VALUES (?, ?, NOW(), ?, ?, ?)
        ");
        
        $stmt->execute([
            $project_id,
            $admin_id,
            $success ? 1 : 0,
            json_encode($errors),
            $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]);
    }
    
    /**
     * Security check: Enforce publication validation at database level
     * This prevents any bypass attempts and ensures data integrity
     */
    public function enforcePublicationSecurity($project_id, $requested_visibility) {
        // If requesting to publish, absolutely must pass validation
        if ($requested_visibility === 'published') {
            if (!$this->validateForPublication($project_id)) {
                // Log security violation
                error_log("SECURITY ALERT: Attempted to bypass publication validation for project ID: $project_id");
                
                // Return false to prevent the action
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Get detailed validation report for security logging
     */
    public function getSecurityValidationReport($project_id) {
        $this->validateForPublication($project_id);
        
        return [
            'project_id' => $project_id,
            'is_valid' => empty($this->errors),
            'validation_errors' => $this->errors,
            'timestamp' => date('Y-m-d H:i:s'),
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ];
    }
}

// Helper function for use in templates
function get_project_validation_status($project_id) {
    global $pdo;
    $validator = new ProjectPublicationValidator($pdo);
    return $validator->getValidationStatus($project_id);
}

// Helper function to get CSS classes based on publication status
function get_publication_status_class($project) {
    if ($project['visibility'] === 'published') {
        return 'bg-green-50 border-green-200 text-green-800';
    } else {
        return 'bg-red-50 border-red-200 text-red-800';
    }
}

function get_publication_button_class($project) {
    if ($project['visibility'] === 'published') {
        return 'bg-green-600 hover:bg-green-700 border-green-600';
    } else {
        return 'bg-red-600 hover:bg-red-700 border-red-600';
    }
}
?>
