<?php
$page_title = "Edit Project";
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';

require_admin();
$current_admin = get_current_admin();

// Get project ID from URL - more flexible validation
$project_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
if ($project_id <= 0) {
    header('Location: projects.php?error=invalid_project');
    exit;
}

// Get project data first to check if it exists
$project = get_project_by_id($project_id);
if (!$project) {
    header('Location: projects.php?error=Project not found');
    exit;
}

// Check project ownership - super admin can edit all projects
if ($current_admin['role'] !== 'super_admin') {
    // Check if this admin created the project
    if ($project['created_by'] != $current_admin['id']) {
        header('Location: projects.php?error=You do not have permission to edit this project');
        exit;
    }
}

// Get data for dropdowns
$departments = get_departments();
$counties = get_counties();
$sub_counties = get_sub_counties($project['county_id']);
$wards = get_wards($project['sub_county_id']);

include 'includes/adminHeader.php';
?>

<div class="bg-white rounded-xl p-6 mb-6 shadow-sm border border-gray-200">
    <!-- Success/Error Messages -->
    <?php if (isset($_GET['success'])): ?>
    <div class="mb-6 rounded-md bg-green-50 p-4 border border-green-200">
        <div class="flex">
            <div class="flex-shrink-0">
                <svg class="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clip-rule="evenodd" />
                </svg>
            </div>
            <div class="ml-3">
                <p class="text-sm font-medium text-green-800"><?php echo htmlspecialchars($_GET['success']); ?></p>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <?php if (isset($_GET['error'])): ?>
    <div class="mb-6 rounded-md bg-red-50 p-4 border border-red-200">
        <div class="flex">
            <div class="flex-shrink-0">
                <svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clip-rule="evenodd" />
                </svg>
            </div>
            <div class="ml-3">
                <p class="text-sm font-medium text-red-800"><?php echo htmlspecialchars($_GET['error']); ?></p>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <div class="space-y-6 lg:space-y-8">
        <!-- Page Header -->
        <div class="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4">
            <div>
                <nav class="flex mb-2" aria-label="Breadcrumb">
                    <ol class="inline-flex items-center space-x-1 md:space-x-3">
                        <li class="inline-flex items-center">
                            <a href="projects.php" class="inline-flex items-center text-sm font-medium text-gray-700 hover:text-blue-600">
                                <i class="fas fa-folder mr-2"></i>
                                Projects
                            </a>
                        </li>
                        <li>
                            <div class="flex items-center">
                                <i class="fas fa-chevron-right text-gray-400 mx-2"></i>
                                <a href="manageProject.php?id=<?php echo $project['id']; ?>" class="ml-1 text-sm font-medium text-gray-700 hover:text-blue-600 md:ml-2">
                                    Manage
                                </a>
                            </div>
                        </li>
                        <li aria-current="page">
                            <div class="flex items-center">
                                <i class="fas fa-chevron-right text-gray-400 mx-2"></i>
                                <span class="ml-1 text-sm font-medium text-gray-500 md:ml-2">Edit</span>
                            </div>
                        </li>
                    </ol>
                </nav>
                <h1 class="text-2xl font-bold text-gray-900">Edit Project</h1>
                <p class="mt-1 text-sm text-gray-600">Update project details and settings for: <span class="font-semibold"><?php echo htmlspecialchars($project['project_name']); ?></span></p>
            </div>
            <div class="flex items-center gap-2">
                <a href="manageProject.php?id=<?php echo $project['id']; ?>" class="inline-flex items-center justify-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 transition-colors">
                    <i class="fas fa-arrow-left mr-2"></i> Back to Manage
                </a>
            </div>
        </div>

        <!-- Edit Project Form -->
        <div class="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
            <div class="bg-gradient-to-r from-blue-50 to-indigo-50 p-6 border-b border-gray-200">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <div class="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                            <i class="fas fa-edit text-blue-600 text-lg"></i>
                        </div>
                    </div>
                    <div class="ml-4">
                        <h3 class="text-lg font-semibold text-gray-900">Project Information</h3>
                        <p class="text-sm text-gray-600 mt-1">Update the project details below</p>
                    </div>
                </div>
            </div>

            <form method="POST" action="updateProject.php" class="p-6 space-y-6">
                <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                <input type="hidden" name="project_id" value="<?php echo $project['id']; ?>">

                <!-- Basic Information -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div class="md:col-span-2">
                        <label class="block text-sm font-medium text-gray-700 mb-1">Project Name *</label>
                        <input type="text" name="project_name" value="<?php echo htmlspecialchars($project['project_name']); ?>" required 
                               class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                    </div>

                    <div class="md:col-span-2">
                        <label class="block text-sm font-medium text-gray-700 mb-1">Description</label>
                        <textarea name="description" rows="3" 
                                  class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"><?php echo htmlspecialchars($project['description']); ?></textarea>
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Department *</label>
                        <select name="department_id" required 
                                class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                            <option value="">Select Department</option>
                            <?php foreach ($departments as $dept): ?>
                                <option value="<?php echo $dept['id']; ?>" <?php echo $dept['id'] == $project['department_id'] ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($dept['name']); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Project Year *</label>
                        <input type="number" name="project_year" min="2020" max="2030" value="<?php echo $project['project_year']; ?>" required 
                               class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                    </div>
                </div>

                <!-- Location -->
                <div class="border-t border-gray-200 pt-6">
                    <h3 class="text-lg font-medium text-gray-900 mb-4">Location</h3>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">County *</label>
                            <select name="county_id" id="countyId" required onchange="loadSubCounties(this.value)"
                                    class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                                <option value="">Select County</option>
                                <?php foreach ($counties as $county): ?>
                                    <option value="<?php echo $county['id']; ?>" <?php echo $county['id'] == $project['county_id'] ? 'selected' : ''; ?>>
                                        <?php echo htmlspecialchars($county['name']); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Sub County *</label>
                            <select name="sub_county_id" id="subCountyId" required onchange="loadWards(this.value)"
                                    class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                                <option value="">Select Sub County</option>
                                <?php foreach ($sub_counties as $sub_county): ?>
                                    <option value="<?php echo $sub_county['id']; ?>" <?php echo $sub_county['id'] == $project['sub_county_id'] ? 'selected' : ''; ?>>
                                        <?php echo htmlspecialchars($sub_county['name']); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Ward *</label>
                            <select name="ward_id" id="wardId" required 
                                    class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                                <option value="">Select Ward</option>
                                <?php foreach ($wards as $ward): ?>
                                    <option value="<?php echo $ward['id']; ?>" <?php echo $ward['id'] == $project['ward_id'] ? 'selected' : ''; ?>>
                                        <?php echo htmlspecialchars($ward['name']); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Location Address</label>
                            <input type="text" name="location_address" value="<?php echo htmlspecialchars($project['location_address']); ?>" 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">GPS Coordinates</label>
                            <input type="text" name="location_coordinates" value="<?php echo htmlspecialchars($project['location_coordinates']); ?>" 
                                   placeholder="latitude,longitude" 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                        </div>
                    </div>
                </div>

                <!-- Financial & Timeline -->
                <div class="border-t border-gray-200 pt-6">
                    <h3 class="text-lg font-medium text-gray-900 mb-4">Financial & Timeline</h3>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Original Budget (KES) *</label>
                            <input type="number" name="total_budget" step="0.01" min="0" value="<?php echo $project['total_budget']; ?>" readonly 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm bg-gray-50 text-gray-600 cursor-not-allowed">
                            <p class="text-xs text-gray-500 mt-1">
                                <i class="fas fa-info-circle mr-1"></i>
                                To increase the budget, use the Budget Management section with proper approval workflow.
                            </p>
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Start Date</label>
                            <input type="date" name="start_date" value="<?php echo $project['start_date']; ?>" 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Expected Completion</label>
                            <input type="date" name="expected_completion_date" value="<?php echo $project['expected_completion_date']; ?>" 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Contractor Name</label>
                            <input type="text" name="contractor_name" value="<?php echo htmlspecialchars($project['contractor_name']); ?>" 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Contractor Contact</label>
                            <input type="text" name="contractor_contact" value="<?php echo htmlspecialchars($project['contractor_contact']); ?>" 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500">                        </div>
                    </div>
                </div>

                <!-- Submit Buttons -->
                <div class="flex flex-col sm:flex-row sm:justify-end gap-3 pt-6 border-t border-gray-200 bg-gray-50 -m-6 mt-6 p-6 rounded-b-lg">
                    <a href="manageProject.php?id=<?php echo $project['id']; ?>" class="w-full sm:w-auto inline-flex justify-center items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500 transition-colors">
                        <i class="fas fa-times mr-2"></i>
                        Cancel
                    </a>
                    <button type="submit" class="w-full sm:w-auto inline-flex justify-center items-center px-6 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors shadow-sm">
                        <i class="fas fa-save mr-2"></i>
                        Update Project
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
// Load sub-counties based on county selection
function loadSubCounties(countyId, selectedSubCountyId = null) {
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
                        if (selectedSubCountyId && subCounty.id == selectedSubCountyId) {
                            option.selected = true;
                        }
                        subCountySelect.appendChild(option);
                    });

                    // If we have a selected sub-county, load its wards
                    if (selectedSubCountyId) {
                        loadWards(selectedSubCountyId, <?php echo $project['ward_id']; ?>);
                    }
                }
            })
            .catch(error => console.error('Error loading sub-counties:', error));
    }
}

function loadWards(subCountyId, selectedWardId = null) {
    const wardSelect = document.getElementById('wardId');
    wardSelect.innerHTML = '<option value="">Select Ward</option>';

    if (subCountyId) {
        fetch(`../api/locations.php?action=wards&sub_county_id=${subCountyId}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    data.data.forEach(ward => {
                        const option = document.createElement('option');
                        option.value = ward.id;
                        option.textContent = ward.name;
                        if (selectedWardId && ward.id == selectedWardId) {
                            option.selected = true;
                        }
                        wardSelect.appendChild(option);
                    });
                }
            })
            .catch(error => console.error('Error loading wards:', error));
    }
}

// Load the dependent dropdowns when page loads
document.addEventListener('DOMContentLoaded', function() {
    const countyId = <?php echo $project['county_id']; ?>;
    const subCountyId = <?php echo $project['sub_county_id']; ?>;

    if (countyId) {
        loadSubCounties(countyId, subCountyId);
    }
});
</script>

<?php include 'includes/adminFooter.php'; ?>
