<?php
require_once 'includes/pageSecurity.php';
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';
require_once '../includes/rbac.php';

// Require authentication and permission to create projects
require_admin();
if (!has_permission('create_projects')) {
    header('Location: index.php?error=access_denied');
    exit;
}

$page_title = "Create New Project";
$current_admin = get_current_admin();

// Get data for dropdowns
$departments = get_departments();
$counties = get_counties();

include 'includes/adminHeader.php';
?>

<!-- Breadcrumb -->
<div class="mb-6">
    <nav class="flex" aria-label="Breadcrumb">
        <ol class="flex items-center space-x-2 text-sm">
            <li class="text-gray-600 font-medium">
                <i class="fas fa-home mr-1"></i> Dashboard
            </li>
            <li class="text-gray-400">/</li>
            <li class="text-gray-600 font-medium">Projects</li>
            <li class="text-gray-400">/</li>
            <li class="text-gray-600 font-medium">Create New</li>
        </ol>
    </nav>
</div>

<!-- Page Header -->
<div class="mb-8">
    <div class="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
        <div class="flex flex-col md:flex-row items-start justify-between">
            <div class="mb-4 md:mb-0">
                <h1 class="text-2xl font-bold text-gray-900 mb-2">Create New Project</h1>
                <p class="text-gray-600">Initialize a new PMC project with comprehensive details</p>
                <p class="text-sm text-gray-500 mt-2">Complete all required fields to ensure proper project tracking</p>
            </div>
            <div class="text-center md:text-right">
                <div class="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center mb-2">
                    <i class="fas fa-plus-circle text-blue-600 text-xl"></i>
                </div>
                <div class="text-sm text-gray-600">New Project</div>
            </div>
        </div>
    </div>
</div>

<div class="bg-white shadow-sm border border-gray-200">

    <!-- Messages -->
    <?php if (isset($_GET['success'])): ?>
        <div class="mb-6 bg-green-50 border-l-4 border-green-400 p-4 rounded-r-lg shadow-sm">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <i class="fas fa-check-circle text-green-500 text-xl"></i>
                </div>
                <div class="ml-3">
                    <p class="text-green-800 font-medium"><?php echo htmlspecialchars($_GET['success']); ?></p>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <?php if (isset($_GET['error'])): ?>
        <div class="mb-6 bg-red-50 border-l-4 border-red-400 p-4 rounded-r-lg shadow-sm">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <i class="fas fa-exclamation-circle text-red-500 text-xl"></i>
                </div>
                <div class="ml-3">
                    <p class="text-red-800 font-medium"><?php echo htmlspecialchars($_GET['error']); ?></p>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <!-- Professional Multi-Step Form -->
    <div class="bg-white rounded-xl shadow-xl border border-gray-200 overflow-hidden">
        <!-- Enhanced Step Indicator -->
        <div class="bg-gray-50 border-b border-gray-200 px-8 py-6">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-8">
                    <div class="flex items-center" id="step1-indicator">
                        <div class="flex-shrink-0 w-10 h-10 bg-blue-600 rounded-full flex items-center justify-center shadow-lg">
                            <span class="text-sm font-bold text-white">1</span>
                        </div>
                        <div class="ml-4 hidden md:block">
                            <p class="text-sm font-semibold text-gray-900">Basic Information</p>
                        </div>
                    </div>
                    <div class="hidden md:block w-16 h-0.5 bg-gray-300"></div>
                    <div class="flex items-center" id="step2-indicator">
                        <div class="flex-shrink-0 w-10 h-10 bg-gray-300 rounded-full flex items-center justify-center">
                            <span class="text-sm font-bold text-white">2</span>
                        </div>
                        <div class="ml-4 hidden md:block">
                            <p class="text-sm font-medium text-gray-500">Location & Demographics</p>
                        </div>
                    </div>
                    <div class="hidden md:block w-16 h-0.5 bg-gray-300"></div>
                    <div class="flex items-center" id="step3-indicator">
                        <div class="flex-shrink-0 w-10 h-10 bg-gray-300 rounded-full flex items-center justify-center">
                            <span class="text-sm font-bold text-white">3</span>
                        </div>
                        <div class="ml-4 hidden md:block">
                            <p class="text-sm font-medium text-gray-500">Timeline & Contractor</p>
                        </div>
                    </div>
                    <div class="hidden md:block w-16 h-0.5 bg-gray-300"></div>
                    <div class="flex items-center" id="step4-indicator">
                        <div class="flex-shrink-0 w-10 h-10 bg-gray-300 rounded-full flex items-center justify-center">
                            <span class="text-sm font-bold text-white">4</span>
                        </div>
                        <div class="ml-4 hidden md:block">
                            <p class="text-sm font-medium text-gray-500">Project Steps</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <form id="projectForm" method="POST" action="submitProject.php" class="h-full">
            <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
            <input type="hidden" name="action" value="create_project">

            <!-- Step 1: Basic Information -->
            <div id="step1" class="step-content p-4 md:p-8">
                <div class="mb-6 md:mb-8">
                    <h3 class="text-xl md:text-2xl font-bold text-gray-900 mb-2">Basic Project Information</h3>
                    <p class="text-sm text-gray-600">Enter the fundamental details of your project</p>
                </div>

                <div class="bg-white rounded-lg border border-gray-200 p-4 md:p-6 mb-6">
                    <div class="grid grid-cols-1 gap-6">
                        <!-- Project Name - Full width -->
                        <div class="col-span-1">
                            <label class="block text-sm font-semibold text-gray-700 mb-2">Project Name *</label>
                            <input type="text" name="project_name" id="projectName" required 
                                   class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200"
                                   placeholder="Enter descriptive project name">
                        </div>

                        <!-- Row for Year and Department -->
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6">
                            <div>
                                <label class="block text-sm font-semibold text-gray-700 mb-2">Project Year *</label>
                                <input type="number" name="project_year" id="projectYear" min="2020" max="2030" required 
                                       value="<?php echo date('Y'); ?>"
                                       class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200">
                            </div>

                            <div>
                                <label class="block text-sm font-semibold text-gray-700 mb-2">Department *</label>
                                <select name="department_id" id="departmentId" required 
                                        class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200">
                                    <option value="">Select Department</option>
                                    <?php foreach ($departments as $dept): ?>
                                        <option value="<?php echo $dept['id']; ?>"><?php echo htmlspecialchars($dept['name']); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                        </div>

                        <!-- Budget - Full width -->
                        <div class="col-span-1">
                            <label class="block text-sm font-semibold text-gray-700 mb-2">Total Budget (KES)</label>
                            <div class="relative">
                                <span class="absolute left-3 top-3 text-gray-500">KES</span>
                                <input type="number" name="total_budget" id="totalBudget" min="0" step="0.01"
                                       class="w-full pl-12 pr-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200"
                                       placeholder="0.00">
                            </div>
                            <p class="text-xs text-gray-500 mt-1">Enter the total project budget in Kenya Shillings</p>
                        </div>

                        <!-- Description - Full width -->
                        <div class="col-span-1">
                            <label class="block text-sm font-semibold text-gray-700 mb-2">Project Description</label>
                            <textarea name="description" id="projectDescription" rows="6" 
                                      class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200 resize-none"
                                      placeholder="Describe the project objectives, relevancy, scope, and expected outcomes..."></textarea>
                            <p class="text-xs text-gray-500 mt-1">Provide a comprehensive description of what this project aims to achieve</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Step 2: Location & Demographics -->
            <div id="step2" class="step-content p-8 hidden">
                <div class="mb-8">
                    <h3 class="text-2xl font-bold text-gray-900 mb-2">Location & Demographics</h3>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">County *</label>
                        <select name="county_id" id="countyId" required onchange="loadSubCounties(this.value)"
                                class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200">
                            <option value="">Select County</option>
                            <?php foreach ($counties as $county): ?>
                                <option value="<?php echo $county['id']; ?>"><?php echo htmlspecialchars($county['name']); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">Sub County *</label>
                        <select name="sub_county_id" id="subCountyId" required onchange="loadWards(this.value)"
                                class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200">
                            <option value="">Select Sub County</option>
                        </select>
                    </div>

                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">Ward *</label>
                        <select name="ward_id" id="wardId" required 
                                class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200">
                            <option value="">Select Ward</option>
                        </select>
                    </div>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">Location Address</label>
                        <input type="text" name="location_address" id="locationAddress" 
                               class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200"
                               placeholder="Specific street address or landmark">
                    </div>

                    <div>
                        <label class="block text-sm font-semibold text-gray-700 mb-2">GPS Coordinates</label>
                        <input type="text" name="location_coordinates" id="locationCoordinates" 
                               placeholder="latitude,longitude (e.g., -1.0833, 34.7500)" 
                               class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200">
                    </div>
                </div>
            </div>

            <!-- Step 3: Timeline -->
            <div id="step3" class="step-content p-8 hidden">
                <div class="mb-8">
                    <h3 class="text-2xl font-bold text-gray-900 mb-2">Timeline & Contractor Information</h3>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    <div class="space-y-6">
                        <div>
                            <label class="block text-sm font-semibold text-gray-700 mb-2">Start Date</label>
                            <input type="date" name="start_date" id="startDate" 
                                   class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200">
                        </div>

                        <div>
                            <label class="block text-sm font-semibold text-gray-700 mb-2">Expected Completion</label>
                            <input type="date" name="expected_completion_date" id="expectedCompletion" 
                                   class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200">
                        </div>
                    </div>

                    <div class="space-y-6">
                        <div>
                            <label class="block text-sm font-semibold text-gray-700 mb-2">Contractor Name</label>
                            <input type="text" name="contractor_name" id="contractorName" 
                                   class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200"
                                   placeholder="Primary contractor or implementing agency">
                        </div>

                        <div>
                            <label class="block text-sm font-semibold text-gray-700 mb-2">Contractor Contact</label>
                            <input type="text" name="contractor_contact" id="contractorContact" 
                                   class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200"
                                   placeholder="Phone number or email">
                        </div>
                    </div>
                </div>
            </div>

            <!-- Step 4: Project Steps -->
            <div id="step4" class="step-content p-8 hidden">
                <div class="mb-8">
                    <h3 class="text-2xl font-bold text-gray-900 mb-2">Project Implementation Steps</h3>
                    <p class="text-gray-600">Define the phases and milestones for project execution</p>
                </div>

                <div class="bg-blue-50 border border-blue-200 rounded-lg p-6 mb-6">
                    <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                        <div>
                            <h4 class="font-semibold text-blue-900 mb-1">Step Management</h4>
                            <p class="text-sm text-blue-700">Create and organize the project implementation phases</p>
                        </div>
                        <div class="flex flex-col sm:flex-row gap-2">
                            <button type="button" onclick="addProjectStep()" class="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium">
                                <i class="fas fa-plus mr-2"></i>Add Step
                            </button>
                            <button type="button" onclick="generateDefaultSteps()" class="inline-flex items-center px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors font-medium">
                                <i class="fas fa-magic mr-2"></i>Generate Default
                            </button>
                        </div>
                    </div>
                </div>

                <div id="projectSteps" class="space-y-4 mb-6">
                    <!-- Steps will be added dynamically -->
                </div>

                <div class="text-center">
                    <button type="button" onclick="clearAllSteps()" class="inline-flex items-center px-4 py-2 text-red-600 hover:text-red-800 hover:bg-red-50 rounded-lg transition-colors">
                        <i class="fas fa-trash mr-2"></i>Clear All Steps
                    </button>
                </div>
            </div>

            <!-- Professional Navigation -->
            <div class="bg-gray-50 border-t border-gray-200 px-8 py-6">
                <div class="flex flex-col md:flex-row justify-between items-center gap-4">
                    <button type="button" id="prevBtn" onclick="changeStep(-1)" class="hidden order-1 md:order-none inline-flex items-center px-6 py-3 border border-gray-300 text-gray-700 bg-white rounded-lg hover:bg-gray-50 transition-all duration-200 font-medium">
                        <i class="fas fa-arrow-left mr-2"></i>Previous Step
                    </button>

                    <div class="flex items-center space-x-2 order-2 md:order-none">
                        <span class="text-sm text-gray-500">Step</span>
                        <span id="currentStepNumber" class="font-bold text-blue-600">1</span>
                        <span class="text-sm text-gray-500">of 4</span>
                    </div>

                    <div class="order-3 md:order-none">
                        <button type="button" id="nextBtn" onclick="changeStep(1)" class="inline-flex items-center px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-all duration-200 font-medium shadow-lg">
                            Next Step<i class="fas fa-arrow-right ml-2"></i>
                        </button>
                        <button type="submit" id="submitBtn" class="hidden inline-flex items-center px-6 py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-all duration-200 font-medium shadow-lg">
                            <i class="fas fa-save mr-2"></i>Create Project
                        </button>
                    </div>
                </div>
            </div>
        </form>
    </div>
</div>

<style>
.step-content {
    min-height: 500px;
    animation: slideIn 0.3s ease-out;
}

@keyframes slideIn {
    from {
        opacity: 0;
        transform: translateX(20px);
    }
    to {
        opacity: 1;
        transform: translateX(0);
    }
}

.project-step-card {
    background: white;
    border: 1px solid #e5e7eb;
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    transition: all 0.2s ease;
}

.project-step-card:hover {
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    border-color: #3b82f6;
}

.project-step-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
    padding-bottom: 0.75rem;
    border-bottom: 1px solid #f3f4f6;
}

.project-step-header h4 {
    font-weight: 600;
    color: #1f2937;
    margin: 0;
    font-size: 1.1rem;
}

.remove-step-btn {
    color: #ef4444;
    background: #fef2f2;
    border: 1px solid #fecaca;
    padding: 0.5rem;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.2s;
    font-size: 0.875rem;
}

.remove-step-btn:hover {
    background: #fee2e2;
    border-color: #fca5a5;
}

@media (max-width: 768px) {
    .step-content {
        padding: 1.5rem;
        min-height: auto;
    }

    .project-step-header {
        flex-direction: column;
        align-items: stretch;
        gap: 0.75rem;
    }

    .grid {
        grid-template-columns: 1fr !important;
    }
}
</style>

<script>
let currentStep = 1;
const totalSteps = 4;
let stepCounter = 0;

async function changeStep(direction) {
    if (direction === 1 && currentStep < totalSteps) {
        const isValid = await validateCurrentStep();
        if (isValid) {
            currentStep++;
            updateStepDisplay();
        }
    } else if (direction === -1 && currentStep > 1) {
        currentStep--;
        updateStepDisplay();
    }
}

function updateStepDisplay() {
    // Hide all steps
    for (let i = 1; i <= totalSteps; i++) {
        document.getElementById(`step${i}`).classList.add('hidden');
        const indicator = document.getElementById(`step${i}-indicator`);
        const circle = indicator.querySelector('div');
        const texts = indicator.querySelectorAll('p');

        if (i < currentStep) {
            circle.className = 'flex-shrink-0 w-10 h-10 bg-green-600 rounded-full flex items-center justify-center shadow-lg';
            circle.innerHTML = '<i class="fas fa-check text-white text-sm"></i>';
            texts.forEach(text => text.className = text.className.replace('text-gray-500', 'text-gray-900').replace('text-gray-400', 'text-gray-600'));
        } else if (i === currentStep) {
            circle.className = 'flex-shrink-0 w-10 h-10 bg-blue-600 rounded-full flex items-center justify-center shadow-lg';
            circle.innerHTML = `<span class="text-sm font-bold text-white">${i}</span>`;
            texts.forEach(text => text.className = text.className.replace('text-gray-500', 'text-gray-900').replace('text-gray-400', 'text-gray-600'));
        } else {
            circle.className = 'flex-shrink-0 w-10 h-10 bg-gray-300 rounded-full flex items-center justify-center';
            circle.innerHTML = `<span class="text-sm font-bold text-white">${i}</span>`;
            if (texts.length > 0) {
                texts[0].className = 'text-sm font-medium text-gray-500';
                if (texts.length > 1) texts[1].className = 'text-xs text-gray-400';
            }
        }
    }

    // Show current step
    document.getElementById(`step${currentStep}`).classList.remove('hidden');

    // Update step counter
    document.getElementById('currentStepNumber').textContent = currentStep;

    // Update navigation buttons
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const submitBtn = document.getElementById('submitBtn');

    if (currentStep === 1) {
        prevBtn.classList.add('hidden');
    } else {
        prevBtn.classList.remove('hidden');
    }

    if (currentStep === totalSteps) {
        nextBtn.classList.add('hidden');
        submitBtn.classList.remove('hidden');
    } else {
        nextBtn.classList.remove('hidden');
        submitBtn.classList.add('hidden');
    }
}

async function validateCurrentStep() {
    const step = document.getElementById(`step${currentStep}`);
    const requiredFields = step.querySelectorAll('[required]');

    for (let field of requiredFields) {
        if (!field.value.trim()) {
            field.focus();
            alert('Please fill in all required fields before proceeding.');
            return false;
        }
    }

    // Budget confirmation check when moving from step 1 to step 2
    if (currentStep === 1) {
        const budgetAmount = document.getElementById('totalBudget').value.trim();
        
        // Check budget confirmation if budget is entered
        if (budgetAmount && parseFloat(budgetAmount) > 0) {
            const confirmed = await confirmBudgetAmount(budgetAmount);
            if (!confirmed) {
                document.getElementById('totalBudget').focus();
                return false;
            }
        }
        
        // Enhanced duplicate detection with multiple criteria
        const projectName = document.getElementById('projectName').value.trim();
        const departmentId = document.getElementById('departmentId').value;
        const projectYear = document.getElementById('projectYear').value;
        const wardId = document.getElementById('wardId').value;
        const subCountyId = document.getElementById('subCountyId').value;
        
        if (projectName) {
            try {
                const response = await fetch('../api/checkDuplicate.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ 
                        project_name: projectName,
                        department_id: departmentId,
                        project_year: projectYear,
                        total_budget: budgetAmount,
                        ward_id: wardId,
                        sub_county_id: subCountyId
                    })
                });
                const data = await response.json();

                if (data.exists) {
                    let message = 'Duplicate project detected!\n\n';
                    data.checks.forEach(check => {
                        if (check.severity === 'high') {
                            message += `❌ ${check.message}\n`;
                        }
                    });
                    message += '\nPlease modify the project details to make it unique.';
                    
                    alert(message);
                    document.getElementById('projectName').focus();
                    return false;
                }
                
                if (data.warnings && data.total_issues > 0) {
                    let warningMessage = 'Potential duplicate concerns detected:\n\n';
                    data.checks.forEach(check => {
                        if (check.severity === 'medium') {
                            warningMessage += `⚠️ ${check.message}\n`;
                        }
                    });
                    warningMessage += `\n${data.recommendation}\n\nDo you want to continue?`;
                    
                    if (!confirm(warningMessage)) {
                        document.getElementById('projectName').focus();
                        return false;
                    }
                }
            } catch (error) {
                console.error('Error checking for duplicates:', error);
                alert('Unable to verify project uniqueness. Please ensure all project details are correct.');
            }
        }
    }

    return true;
}

function addProjectStep() {
    stepCounter++;
    const stepsContainer = document.getElementById('projectSteps');

    const stepDiv = document.createElement('div');
    stepDiv.className = 'project-step-card';
    stepDiv.innerHTML = `
        <div class="project-step-header">
            <h4><i class="fas fa-tasks text-blue-600 mr-2"></i>Step ${stepCounter}</h4>
            <button type="button" onclick="removeProjectStep(this)" class="remove-step-btn">
                <i class="fas fa-trash mr-1"></i>Remove
            </button>
        </div>
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div>
                <label class="block text-sm font-semibold text-gray-700 mb-2">Step Name</label>
                <input type="text" name="steps[${stepCounter}][name]" 
                       class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200"
                       placeholder="Enter step name">
            </div>
            <div>
                <label class="block text-sm font-semibold text-gray-700 mb-2">Expected End Date</label>
                <input type="date" name="steps[${stepCounter}][expected_date]" 
                       class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200">
            </div>
        </div>
        <div class="mt-4">
            <label class="block text-sm font-semibold text-gray-700 mb-2">Description</label>
            <textarea name="steps[${stepCounter}][description]" rows="3" 
                      class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200 resize-none"
                      placeholder="Describe what needs to be accomplished in this step"></textarea>
        </div>
    `;

    stepsContainer.appendChild(stepDiv);
}

function removeProjectStep(button) {
    button.closest('.project-step-card').remove();
}

function generateDefaultSteps() {
    const departmentId = document.getElementById('departmentId').value;
    if (!departmentId) {
        alert('Please select a department first.');
        return;
    }

    clearAllSteps();

    fetch('../api/getDefaultSteps.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ department_id: departmentId })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            data.steps.forEach((step, index) => {
                addProjectStepWithData(step.step_name, step.description);
            });
        } else {
            alert('Error loading default steps: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error loading default steps');
    });
}

function addProjectStepWithData(name, description) {
    stepCounter++;
    const stepsContainer = document.getElementById('projectSteps');

    const stepDiv = document.createElement('div');
    stepDiv.className = 'project-step-card';
    stepDiv.innerHTML = `
        <div class="project-step-header">
            <h4><i class="fas fa-tasks text-blue-600 mr-2"></i>Step ${stepCounter}</h4>
            <button type="button" onclick="removeProjectStep(this)" class="remove-step-btn">
                <i class="fas fa-trash mr-1"></i>Remove
            </button>
        </div>
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div>
                <label class="block text-sm font-semibold text-gray-700 mb-2">Step Name</label>
                <input type="text" name="steps[${stepCounter}][name]" value="${name}"
                       class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200">
            </div>
            <div>
                <label class="block text-sm font-semibold text-gray-700 mb-2">Expected End Date</label>
                <input type="date" name="steps[${stepCounter}][expected_date]" 
                       class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200">
            </div>
        </div>
        <div class="mt-4">
            <label class="block text-sm font-semibold text-gray-700 mb-2">Description</label>
            <textarea name="steps[${stepCounter}][description]" rows="3" 
                      class="w-full px-4 py-3 border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200 resize-none">${description}</textarea>
        </div>
    `;

    stepsContainer.appendChild(stepDiv);
}

function clearAllSteps() {
    document.getElementById('projectSteps').innerHTML = '';
    stepCounter = 0;
}

// Load sub-counties based on county selection
function loadSubCounties(countyId) {
    const subCountySelect = document.getElementById('subCountyId');
    const wardSelect = document.getElementById('wardId');

    subCountySelect.innerHTML = '<option value="">Select Sub County</option>';
    wardSelect.innerHTML = '<option value="">Select Ward</option>';

    if (countyId) {
        fetch(`../api/locations.php?action=sub_counties&county_id=${countyId}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    data.data.forEach(subCounty => {
                        const option = document.createElement('option');
                        option.value = subCounty.id;
                        option.textContent = subCounty.name;
                        subCountySelect.appendChild(option);
                    });
                }
            })
            .catch(error => console.error('Error loading sub-counties:', error));
    }
}

function loadWards(subCountyId) {
    const wardSelect = document.getElementById('wardId');
    wardSelect.innerHTML = '<option value="">Select Ward</option>';

    if (subCountyId) {
        fetch(`../api/locations.php?action=wards&sub_county_id=${subCountyId}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    data.data.forEach(ward => {
                        const option = new Option(ward.name, ward.id);
                        wardSelect.add(option);
                    });
                }
            })
            .catch(error => console.error('Error loading wards:', error));
    }
}

// Budget confirmation function
async function confirmBudgetAmount(amount) {
    return new Promise((resolve) => {
        // Create modal overlay
        const overlay = document.createElement('div');
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            z-index: 9999;
            display: flex;
            align-items: center;
            justify-content: center;
            animation: fadeIn 0.3s ease-out;
        `;

        // Create modal content
        const modal = document.createElement('div');
        modal.style.cssText = `
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            max-width: 500px;
            width: 90%;
            margin: 1rem;
            animation: slideIn 0.3s ease-out;
        `;

        const formattedAmount = parseFloat(amount).toLocaleString('en-KE', {
            style: 'currency',
            currency: 'KES',
            minimumFractionDigits: 2
        });

        modal.innerHTML = `
            <div class="text-center mb-6">
                <div class="w-16 h-16 bg-yellow-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <i class="fas fa-exclamation-triangle text-yellow-600 text-2xl"></i>
                </div>
                <h3 class="text-xl font-bold text-gray-900 mb-2">Confirm Project Budget</h3>
                <p class="text-gray-600">Please confirm the project budget amount you entered:</p>
            </div>
            
            <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
                <div class="text-center">
                    <p class="text-sm text-blue-700 mb-1">Project Budget Amount</p>
                    <p class="text-2xl font-bold text-blue-900">${formattedAmount}</p>
                </div>
            </div>
            
            <div class="mb-4">
                <label class="block text-sm font-medium text-gray-700 mb-2">
                    Re-enter the budget amount to confirm:
                </label>
                <input type="number" id="confirmBudgetInput" step="0.01" min="0" 
                       class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                       placeholder="Enter budget amount to confirm">
                <div id="budgetMismatchError" class="hidden mt-2 text-sm text-red-600">
                    <i class="fas fa-exclamation-circle mr-1"></i>
                    The amounts do not match. Please check and try again.
                </div>
            </div>
            
            <div class="flex flex-col sm:flex-row gap-3 justify-end">
                <button id="cancelBudgetBtn" class="px-6 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors">
                    Cancel
                </button>
                <button id="confirmBudgetBtn" class="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors">
                    Confirm Budget
                </button>
            </div>
        `;

        // Add CSS animations
        const style = document.createElement('style');
        style.textContent = `
            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }
            @keyframes slideIn {
                from { opacity: 0; transform: translateY(-20px); }
                to { opacity: 1; transform: translateY(0); }
            }
        `;
        document.head.appendChild(style);

        overlay.appendChild(modal);
        document.body.appendChild(overlay);

        // Focus on input
        setTimeout(() => {
            document.getElementById('confirmBudgetInput').focus();
        }, 300);

        // Handle confirm button
        document.getElementById('confirmBudgetBtn').onclick = () => {
            const confirmInput = document.getElementById('confirmBudgetInput');
            const confirmAmount = parseFloat(confirmInput.value);
            const originalAmount = parseFloat(amount);
            const errorDiv = document.getElementById('budgetMismatchError');

            if (Math.abs(confirmAmount - originalAmount) < 0.01) {
                document.body.removeChild(overlay);
                document.head.removeChild(style);
                resolve(true);
            } else {
                errorDiv.classList.remove('hidden');
                confirmInput.focus();
                confirmInput.style.borderColor = '#ef4444';
                setTimeout(() => {
                    confirmInput.style.borderColor = '';
                }, 3000);
            }
        };

        // Handle cancel button
        document.getElementById('cancelBudgetBtn').onclick = () => {
            document.body.removeChild(overlay);
            document.head.removeChild(style);
            resolve(false);
        };

        // Handle Enter key
        document.getElementById('confirmBudgetInput').onkeypress = (e) => {
            if (e.key === 'Enter') {
                document.getElementById('confirmBudgetBtn').click();
            }
        };

        // Handle Escape key
        document.addEventListener('keydown', function escapeHandler(e) {
            if (e.key === 'Escape') {
                document.removeEventListener('keydown', escapeHandler);
                document.getElementById('cancelBudgetBtn').click();
            }
        });
    });
}

// Initialize display on page load
document.addEventListener('DOMContentLoaded', function() {
    updateStepDisplay();
});
</script>

<?php include 'includes/adminFooter.php'; ?>
