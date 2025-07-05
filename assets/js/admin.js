// Admin-specific JavaScript functionality for the County Project Tracking System by Mirema Business Solutions

class AdminManager {
    constructor() {
        this.init();
    }

    init() {
        this.initDropdowns();
        this.initFileUpload();
        this.initProjectForm();
        this.initFeedbackManagement();
    }

    initDropdowns() {
        // Close dropdowns when clicking outside
        document.addEventListener('click', (e) => {
            const dropdowns = document.querySelectorAll('[id^="dropdown-"]');
            dropdowns.forEach(dropdown => {
                if (!dropdown.contains(e.target) && !e.target.onclick) {
                    dropdown.classList.add('hidden');
                }
            });
        });
    }

    initFileUpload() {
        const fileUploadArea = document.getElementById('fileUploadArea');
        if (!fileUploadArea) return;

        // Drag and drop functionality
        fileUploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            fileUploadArea.classList.add('dragover');
        });

        fileUploadArea.addEventListener('dragleave', () => {
            fileUploadArea.classList.remove('dragover');
        });

        fileUploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            fileUploadArea.classList.remove('dragover');

            const files = e.dataTransfer.files;
            if (files.length > 0) {
                const csvFile = document.getElementById('csvFile');
                csvFile.files = files;
                this.handleFileSelect(csvFile);
            }
        });

        // Form submission
        const uploadForm = document.getElementById('uploadForm');
        if (uploadForm) {
            uploadForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.uploadCSV();
            });
        }
    }

    initProjectForm() {
        // Dynamic loading of location data
        window.loadSubCounties = (countyId) => {
            if (!countyId) {
                this.clearSelect('subCountyId');
                this.clearSelect('wardId');
                return;
            }

            fetch(`../api/locations.php?action=sub_counties&county_id=${countyId}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        this.populateSelect('subCountyId', data.data, 'id', 'name', 'Select Sub County');
                    }
                    this.clearSelect('wardId');
                })
                .catch(error => {
                    console.error('Error loading sub counties:', error);
                    Utils.showNotification('Failed to load sub counties', 'error');
                });
        };

        window.loadWards = (subCountyId) => {
            if (!subCountyId) {
                this.clearSelect('wardId');
                return;
            }

            fetch(`../api/locations.php?action=wards&sub_county_id=${subCountyId}`)
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        this.populateSelect('wardId', data.data, 'id', 'name', 'Select Ward');
                    }
                })
                .catch(error => {
                    console.error('Error loading wards:', error);
                    Utils.showNotification('Failed to load wards', 'error');
                });
        };
    }

    initFeedbackManagement() {
        // Initialize feedback-specific functionality
        this.initResponseModal();
    }

    initResponseModal() {
        const responseForm = document.getElementById('responseForm');
        if (responseForm) {
            responseForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.submitResponse();
            });
        }
    }

    clearSelect(selectId) {
        const select = document.getElementById(selectId);
        if (select) {
            select.innerHTML = '<option value="">Select...</option>';
        }
    }

    populateSelect(selectId, data, valueField, textField, placeholder) {
        const select = document.getElementById(selectId);
        if (!select) return;

        select.innerHTML = `<option value="">${placeholder}</option>`;
        data.forEach(item => {
            const option = document.createElement('option');
            option.value = item[valueField];
            option.textContent = item[textField];
            select.appendChild(option);
        });
    }

    async uploadCSV() {
        const form = document.getElementById('uploadForm');
        const submitBtn = document.getElementById('submitBtn');
        const submitText = document.getElementById('submitText');
        const uploadingText = document.getElementById('uploadingText');

        // Show loading state
        submitBtn.disabled = true;
        submitText.classList.add('hidden');
        uploadingText.classList.remove('hidden');

        try {
            const formData = new FormData(form);
            const response = await fetch('api/uploadCsv.php', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (data.success) {
                Utils.showNotification(data.message, 'success');
                this.showImportResults(data);
                this.clearFile();
            } else {
                Utils.showNotification(data.message || 'Import failed', 'error');
                if (data.errors && data.errors.length > 0) {
                    this.showImportResults(data);
                }
            }

        } catch (error) {
            console.error('Upload error:', error);
            Utils.showNotification('Upload failed', 'error');
        } finally {
            // Reset loading state
            submitBtn.disabled = false;
            submitText.classList.remove('hidden');
            uploadingText.classList.add('hidden');
        }
    }

    showImportResults(data) {
        const resultsDiv = document.getElementById('importResults');
        const contentDiv = document.getElementById('resultsContent');

        if (!resultsDiv || !contentDiv) return;

        let html = `
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <div class="text-center p-4 bg-blue-50 dark:bg-blue-900 rounded-lg">
                    <div class="text-2xl font-bold text-blue-600 dark:text-blue-400">${data.total_rows || 0}</div>
                    <div class="text-sm text-blue-600 dark:text-blue-400">Total Rows</div>
                </div>
                <div class="text-center p-4 bg-green-50 dark:bg-green-900 rounded-lg">
                    <div class="text-2xl font-bold text-green-600 dark:text-green-400">${data.successful_imports || 0}</div>
                    <div class="text-sm text-green-600 dark:text-green-400">Successful</div>
                </div>
                <div class="text-center p-4 bg-red-50 dark:bg-red-900 rounded-lg">
                    <div class="text-2xl font-bold text-red-600 dark:text-red-400">${data.failed_imports || 0}</div>
                    <div class="text-sm text-red-600 dark:text-red-400">Failed</div>
                </div>
            </div>
        `;

        if (data.errors && data.errors.length > 0) {
            html += `
                <div class="bg-red-50 dark:bg-red-900 border border-red-200 dark:border-red-700 rounded-lg p-4">
                    <h4 class="font-medium text-red-800 dark:text-red-200 mb-2">Import Errors:</h4>
                    <div class="max-h-40 overflow-y-auto">
                        <ul class="space-y-1 text-sm text-red-700 dark:text-red-300">
                            ${data.errors.map(error => `<li>• ${this.escapeHtml(error)}</li>`).join('')}
                        </ul>
                    </div>
                </div>
            `;
        }

        contentDiv.innerHTML = html;
        resultsDiv.classList.remove('hidden');
        resultsDiv.scrollIntoView({ behavior: 'smooth' });
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    async submitResponse() {
        const form = document.getElementById('responseForm');
        const formData = new FormData(form);

        try {
            const response = await fetch(window.location.href, {
                method: 'POST',
                body: formData
            });

            if (response.ok) {
                Utils.showNotification('Response sent successfully', 'success');
                this.closeResponseModal();
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
            } else {
                throw new Error('Response failed');
            }

        } catch (error) {
            console.error('Response error:', error);
            Utils.showNotification('Failed to send response', 'error');
        }
    }

    closeResponseModal() {
        const modal = document.getElementById('responseModal');
        if (modal) {
            modal.classList.add('hidden');
            document.body.style.overflow = 'auto';
        }
    }
}

// Global functions for HTML onclick handlers

function handleFileSelect(input) {
    const file = input.files[0];
    if (!file) return;

    const fileInfo = document.getElementById('fileInfo');
    const fileName = document.getElementById('fileName');
    const fileSize = document.getElementById('fileSize');
    const submitBtn = document.getElementById('submitBtn');

    if (file.type !== 'text/csv' && !file.name.endsWith('.csv')) {
        Utils.showNotification('Please select a CSV file', 'error');
        input.value = '';
        return;
    }

    if (file.size > 5 * 1024 * 1024) { // 5MB limit
        Utils.showNotification('File size must be less than 5MB', 'error');
        input.value = '';
        return;
    }

    fileName.textContent = file.name;
    fileSize.textContent = `${(file.size / 1024 / 1024).toFixed(2)} MB`;
    fileInfo.classList.remove('hidden');
    submitBtn.disabled = false;
}

function clearFile() {
    const csvFile = document.getElementById('csvFile');
    const fileInfo = document.getElementById('fileInfo');
    const submitBtn = document.getElementById('submitBtn');

    csvFile.value = '';
    fileInfo.classList.add('hidden');
    submitBtn.disabled = true;
}

function downloadSampleCSV() {
    const csvContent = `project_name,description,department,ward,sub_county,county,year,status,progress_percentage,contractor_name,start_date,expected_completion_date,location_coordinates,location_address
New Water Plant,Construction of new water treatment plant,Water and Sanitation,Central Ward,Nairobi Central,Nairobi,2024,ongoing,45,ABC Contractors,2024-01-15,2024-12-31,-1.2921,36.8219,123 Main Street Nairobi
Road Construction,Tarmacking of rural roads,Roads and Transport,West Ward,Kiambu East,Kiambu,2024,planning,0,XYZ Construction,2024-03-01,2024-11-30,-1.1744,36.9482,Rural Road Network
Health Center,Construction of new health center,Health Services,Health Services,North Ward,Nakuru East,Nakuru,2023,completed,100,Health Builders Ltd,2023-01-01,2023-12-15,-0.3031,36.0800,Hospital Road Nakuru`;

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = 'sample_projects.csv';
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
}

function showProjectForm(project = null) {
    const modal = document.getElementById('projectModal');
    const modalTitle = document.getElementById('modalTitle');
    const formAction = document.getElementById('formAction');
    const submitText = document.getElementById('submitText');
    const form = document.getElementById('projectForm');

    if (project) {
        modalTitle.textContent = 'Edit Project';
        formAction.value = 'update';
        submitText.textContent = 'Update Project';
        populateProjectForm(project);
    } else {
        modalTitle.textContent = 'Add New Project';
        formAction.value = 'create';
        submitText.textContent = 'Create Project';
        form.reset();
        document.getElementById('projectId').value = '';
    }

    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
}

function closeProjectForm() {
    const modal = document.getElementById('projectModal');
    modal.classList.add('hidden');
    document.body.style.overflow = 'auto';
}

function populateProjectForm(project) {
    document.getElementById('projectId').value = project.id;
    document.getElementById('projectName').value = project.project_name;
    document.getElementById('projectDescription').value = project.description || '';
    document.getElementById('departmentId').value = project.department_id;
    document.getElementById('countyId').value = project.county_id;
    document.getElementById('subCountyId').value = project.sub_county_id;
    document.getElementById('wardId').value = project.ward_id;

    document.getElementById('projectYear').value = project.project_year;
    document.getElementById('projectStatus').value = project.status;
    document.getElementById('progressPercentage').value = project.progress_percentage || '';
    document.getElementById('contractorName').value = project.contractor_name || '';
    document.getElementById('contractorContact').value = project.contractor_contact || '';
    document.getElementById('startDate').value = project.start_date || '';
    document.getElementById('expectedCompletion').value = project.expected_completion_date || '';
    document.getElementById('actualCompletion').value = project.actual_completion_date || '';
    document.getElementById('locationCoordinates').value = project.location_coordinates || '';
    document.getElementById('locationAddress').value = project.location_address || '';

    // Load dependent dropdowns
    if (project.county_id) {
        loadSubCounties(project.county_id);
        setTimeout(() => {
            document.getElementById('subCountyId').value = project.sub_county_id;
            if (project.sub_county_id) {
                loadWards(project.sub_county_id);
                setTimeout(() => {
                    document.getElementById('wardId').value = project.ward_id;
                }, 500);
            }
        }, 500);
    }
}

function editProject(project) {
    showProjectForm(project);
}

function deleteProject(projectId, projectName) {
    if (confirm(`Are you sure you want to delete "${projectName}"? This action cannot be undone and will also delete all associated steps and feedback.`)) {
        // Create form to delete project
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = 'projects.php';

        // Try to get CSRF token from any form on the page
        let csrfToken = '';
        const csrfInputs = document.querySelectorAll('input[name="csrf_token"]');
        if (csrfInputs.length > 0) {
            csrfToken = csrfInputs[0].value;
        } else {
            // If no CSRF token found, try to get it from meta tag or other sources
            const metaCsrf = document.querySelector('meta[name="csrf-token"]');
            if (metaCsrf) {
                csrfToken = metaCsrf.getAttribute('content');
            }
        }

        const csrfInput = document.createElement('input');
        csrfInput.type = 'hidden';
        csrfInput.name = 'csrf_token';
        csrfInput.value = csrfToken;

        const actionInput = document.createElement('input');
        actionInput.type = 'hidden';
        actionInput.name = 'action';
        actionInput.value = 'delete';

        const projectIdInput = document.createElement('input');
        projectIdInput.type = 'hidden';
        projectIdInput.name = 'project_id';
        projectIdInput.value = projectId;

        form.appendChild(csrfInput);
        form.appendChild(actionInput);
        form.appendChild(projectIdInput);

        document.body.appendChild(form);
        form.submit();
    }
}

function closeDeleteModal() {
    document.getElementById('deleteModal').classList.add('hidden');
    document.body.style.overflow = 'auto';
}

function toggleDropdown(feedbackId) {
    const dropdown = document.getElementById(`dropdown-${feedbackId}`);
    const isHidden = dropdown.classList.contains('hidden');

    // Close all other dropdowns
    document.querySelectorAll('[id^="dropdown-"]').forEach(d => {
        d.classList.add('hidden');
    });

    if (isHidden) {
        dropdown.classList.remove('hidden');
    }
}

function showResponseForm(feedbackId, subject) {
    document.getElementById('responseFeedbackId').value = feedbackId;
    document.getElementById('responseModalTitle').textContent = `Respond to: ${subject}`;
    document.getElementById('responseModal').classList.remove('hidden');
    document.body.style.overflow = 'hidden';
}

function closeResponseModal() {
    if (window.adminManager) {
        window.adminManager.closeResponseModal();
    }
}

function updateStatus(feedbackId, status) {
    document.getElementById('statusFeedbackId').value = feedbackId;
    document.getElementById('newStatus').value = status;
    document.getElementById('statusForm').submit();
}

function deleteFeedback(feedbackId, subject) {
    if (confirm(`Are you sure you want to delete the feedback "${subject}"? This action cannot be undone.`)) {
        document.getElementById('deleteFeedbackId').value = feedbackId;
        document.getElementById('deleteForm').submit();
    }
}

function showErrorDetails(errorDetails) {
    document.getElementById('errorContent').textContent = errorDetails;
    document.getElementById('errorModal').classList.remove('hidden');
    document.body.style.overflow = 'hidden';
}

function closeErrorModal() {
    document.getElementById('errorModal').classList.add('hidden');
    document.body.style.overflow = 'auto';
}

// Admin dashboard functionality
function updateStats() {
    const baseUrl = window.BASE_URL || '../';
    fetch(baseUrl + 'api/dashboardStats.php')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                const stats = data.stats;
                if (document.getElementById('totalProjects')) {
                    document.getElementById('totalProjects').textContent = stats.total_projects || '0';
                }
                if (document.getElementById('ongoingProjects')) {
                    document.getElementById('ongoingProjects').textContent = stats.ongoing_projects || '0';
                }
                if (document.getElementById('completedProjects')) {
                    document.getElementById('completedProjects').textContent = stats.completed_projects || '0';
                }
            }
        })
        .catch(error => {
            console.error('Error updating stats:', error);
        });
}

document.addEventListener('DOMContentLoaded', function() {
    // Initialize dashboard components only if we're on admin dashboard
    const totalProjectsElement = document.getElementById('totalProjects');
    const ongoingProjectsElement = document.getElementById('ongoingProjects');

    if (totalProjectsElement || ongoingProjectsElement) {
        updateStats();
        // Refresh stats every 30 seconds
        setInterval(updateStats, 30000);
    }
});

// Generate project steps for projects that don't have them
function generateProjectSteps() {
    if (!confirm('This will generate default project steps for all projects that don\'t have steps defined. Continue?')) {
        return;
    }

    const button = event.target;
    const originalText = button.textContent;
    button.textContent = 'Generating...';
    button.disabled = true;

    fetch('../api/generateSteps.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert(data.message);
            // Refresh the page to show updated stats
            location.reload();
        } else {
            alert('Error: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred while generating project steps');
    })
    .finally(() => {
        button.textContent = originalText;
        button.disabled = false;
    });
}

// Mobile menu functionality
document.addEventListener('DOMContentLoaded', function() {
    const mobileMenuToggle = document.querySelector('.mobile-menu-toggle');
    const mobileMenuClose = document.querySelector('.mobile-menu-close');
    const mobileSidebar = document.getElementById('mobile-sidebar');
    const overlay = document.createElement('div');

    overlay.className = 'fixed inset-0 bg-black bg-opacity-50 z-40 lg:hidden';
    overlay.style.display = 'none';
    document.body.appendChild(overlay);

    // Mobile navigation is now directly in the template, no need to clone

    if (mobileMenuToggle) {
        mobileMenuToggle.addEventListener('click', function() {
            mobileSidebar.classList.remove('-translate-x-full');
            overlay.style.display = 'block';
            document.body.style.overflow = 'hidden';
        });
    }

    function closeMobileMenu() {
        mobileSidebar.classList.add('-translate-x-full');
        overlay.style.display = 'none';
        document.body.style.overflow = '';
    }

    if (mobileMenuClose) {
        mobileMenuClose.addEventListener('click', closeMobileMenu);
    }

    overlay.addEventListener('click', closeMobileMenu);

    // Close mobile menu when clicking on navigation links
    const mobileNavLinks = document.querySelectorAll('#mobile-nav a');
    mobileNavLinks.forEach(link => {
        link.addEventListener('click', closeMobileMenu);
    });
});

// Initialize admin manager when DOM is loaded
let adminManager;
document.addEventListener('DOMContentLoaded', function() {
    adminManager = new AdminManager();
    window.adminManager = adminManager;
});