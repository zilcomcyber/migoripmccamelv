<?php
$page_title = "Import Projects from CSV";
require_once 'includes/pageSecurity.php';
require_once '../includes/functions.php';

// Only super admin can import CSV
checkPagePermission('csv_import');

$current_admin = get_current_admin();

// Log access
log_activity('csv_import_access', 'Accessed CSV import page', $current_admin['id']);
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
            <li class="text-gray-600 font-medium">
                <a href="projects.php" class="text-gray-600 hover:text-gray-800">Projects</a>
            </li>
            <li class="text-gray-400">/</li>
            <li class="text-gray-600 font-medium">Import CSV</li>
        </ol>
    </nav>
</div>
 
<!-- Page Header -->
<div class="mb-8">
    <div class="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
        <div class="flex flex-col md:flex-row items-start justify-between">
            <div class="mb-4 md:mb-0">
                <h1 class="text-2xl font-bold text-gray-900 mb-2">Import Projects from CSV</h1>
                <p class="text-gray-600">Bulk import projects using CSV format</p>
                <p class="text-sm text-gray-500 mt-2">Upload CSV files to import multiple projects at once</p>
            </div>
            <div class="text-center md:text-right">
                <div class="text-3xl font-bold text-blue-600 mb-1">
                    <i class="fas fa-file-csv"></i>
                </div>
                <div class="text-sm text-gray-600 mb-3">CSV Import</div>
                <div class="text-xs text-gray-500">Bulk upload</div>
            </div>
        </div>
    </div>
</div>

<div class="bg-white shadow-sm rounded-lg border border-gray-200">

    <!-- Messages -->
    <?php if (isset($_GET['success'])): ?>
        <div class="mb-6 rounded-md bg-green-50 p-4 border border-green-200">
            <div class="flex">
                <div class="flex-shrink-0">
                    <i class="fas fa-check-circle text-green-400"></i>
                </div>
                <div class="ml-3">
                    <p class="text-sm text-green-700"><?php echo htmlspecialchars($_GET['success']); ?></p>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <?php if (isset($_GET['error'])): ?>
        <div class="mb-6 rounded-md bg-red-50 p-4 border border-red-200">
            <div class="flex">
                <div class="flex-shrink-0">
                    <i class="fas fa-exclamation-circle text-red-400"></i>
                </div>
                <div class="ml-3">
                    <p class="text-sm text-red-700"><?php echo htmlspecialchars($_GET['error']); ?></p>
                </div>
            </div>
        </div>
    <?php endif; ?>

    <!-- Import Instructions -->
    <div class="bg-blue-50 rounded-lg p-6 mb-6 border border-blue-200">
        <div class="flex">
            <div class="flex-shrink-0">
                <i class="fas fa-info-circle text-blue-400"></i>
            </div>
            <div class="ml-3">
                <h3 class="text-sm font-medium text-blue-800">CSV Import Instructions</h3>
                <div class="mt-2 text-sm text-blue-700">
                    <ul class="list-disc list-inside space-y-1">
                        <li>Download the CSV template to see the required format</li>
                        <li>Projects imported from CSV will be in "draft" status initially</li>
                        <li>Each project will have one default step created</li>
                        <li>You can add more steps after import</li>
                        <li>Location coordinates should be in "latitude,longitude" format</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <!-- Template Download -->
    <div class="bg-white rounded-lg shadow-sm border border-gray-200 mb-6">
        <div class="px-6 py-4 border-b border-gray-200">
            <h2 class="text-xl font-semibold text-gray-900">CSV Template</h2>
            <p class="text-sm text-gray-600 mt-1">Download the template to ensure proper formatting</p>
        </div>
        <div class="p-6">
            <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div>
                    <h3 class="text-lg font-medium text-gray-900">Project Import Template</h3>
                    <p class="text-sm text-gray-600">Includes sample data and all required columns</p>
                </div>
                <a href="<?php echo BASE_URL; ?>uploads/Migori_Projects_Realistic.csv" 
                   class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 transition-colors w-full sm:w-auto justify-center"
                   download="Migori_Projects_Template.csv">
                    <i class="fas fa-download mr-2"></i>
                    Download Template
                </a>
            </div>
        </div>
    </div>

    <!-- Upload Form -->
    <div class="bg-white rounded-lg shadow-sm border border-gray-200">
        <div class="px-6 py-4 border-b border-gray-200">
            <h2 class="text-xl font-semibold text-gray-900">Upload CSV File</h2>
            <p class="text-sm text-gray-600 mt-1">Select your CSV file to import projects</p>
        </div>

        <form id="csvUploadForm" method="POST" action="<?php echo BASE_URL; ?>admin/import_csv" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">

            <div class="p-6">
                <!-- File Upload Area -->
                <div class="mb-4">
                    <label for="csvFile" class="block text-sm font-medium text-gray-700">Select CSV File</label>
                    <div class="mt-1 flex rounded-md shadow-sm">
                        <input type="file" name="csv_file" id="csvFile" accept=".csv" class="flex-grow focus:ring-blue-500 focus:border-blue-500 block w-full min-w-0 rounded-none rounded-l-md sm:text-sm border-gray-300">
                        <span class="inline-flex items-center px-3 rounded-r-md border border-l-0 border-gray-300 bg-gray-50 text-gray-500 sm:text-sm">.csv</span>
                    </div>
                </div>

                <!-- File Information and Progress -->
                <div class="mb-4">
                    <div class="flex items-center justify-between text-sm text-gray-600">
                        <span id="fileName">No file selected</span>
                        <span id="fileSize">0.00 MB</span>
                    </div>
                    <div class="w-full bg-gray-200 rounded-full h-2 mt-2" style="display: none;" id="progressContainer">
                        <div id="uploadProgress" class="bg-blue-600 h-2 rounded-full transition-all duration-300" style="width: 0%"></div>
                    </div>
                    <div id="uploadStatus" class="text-sm text-gray-500 mt-1">Ready to upload</div>
                </div>
            </div>

            <div class="px-6 py-4 border-t border-gray-200 flex flex-col sm:flex-row justify-end space-y-3 sm:space-y-0 sm:space-x-3">
                <a href="projects.php" 
                   class="px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 transition-colors text-center">
                    Cancel
                </a>
                <button type="submit" id="uploadBtn" disabled
                        class="px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors">
                    <i class="fas fa-upload mr-2"></i>
                    Import Projects
                </button>
            </div>
        </form>
    </div>

    <!-- Import Results -->
    <div id="importResults" class="hidden mt-6 bg-white rounded-lg shadow-sm border border-gray-200">
        <div class="px-6 py-4 border-b border-gray-200">
            <h3 class="text-lg font-semibold text-gray-900">Import Results</h3>
        </div>
        <div class="p-6">
            <div id="importStats" class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                <!-- Stats will be populated here -->
            </div>
            <div id="importErrors" class="hidden">
                <div class="flex items-center justify-between mb-3">
                    <h4 class="font-medium text-gray-900">Import Errors:</h4>
                    <button id="copyErrorsBtn" onclick="copyErrorDetails()" class="hidden inline-flex items-center px-3 py-1 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 transition-colors">
                        <i class="fas fa-copy mr-1"></i>
                        Copy Details
                    </button>
                </div>
                <div class="bg-red-50 rounded-lg p-4 border border-red-200">
                    <ul id="errorList" class="text-sm text-red-700 space-y-1">
                        <!-- Errors will be listed here -->
                    </ul>
                </div>
                <p class="text-xs text-gray-500 mt-2">
                    <i class="fas fa-info-circle mr-1"></i>
                    Use the "Copy Details" button to get technical information for troubleshooting.
                </p>
            </div>
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const uploadForm = document.getElementById('csvUploadForm');
    const fileInput = document.getElementById('csvFile');
    const uploadBtn = document.getElementById('uploadBtn');

    // File input handling
    fileInput.addEventListener('change', function() {
        const file = this.files[0];
        if (file) {
            document.getElementById('fileName').textContent = file.name;

            // Calculate file size
            let fileSize;
            if (file.size === 0) {
                fileSize = '0.00 KB';
            } else if (file.size < 1024) {
                fileSize = file.size + ' B';
            } else if (file.size < 1024 * 1024) {
                fileSize = (file.size / 1024).toFixed(2) + ' KB';
            } else {
                fileSize = (file.size / (1024 * 1024)).toFixed(2) + ' MB';
            }
            document.getElementById('fileSize').textContent = fileSize;

            uploadBtn.disabled = false;
            uploadBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        } else {
            document.getElementById('fileName').textContent = 'No file selected';
            document.getElementById('fileSize').textContent = '0.00 MB';
            uploadBtn.disabled = true;
            uploadBtn.classList.add('opacity-50', 'cursor-not-allowed');
        }
    });

    // Upload form submission
    uploadForm.addEventListener('submit', function(e) {
        e.preventDefault();

        const formData = new FormData(this);
        const progressContainer = document.getElementById('progressContainer');
        const progressBar = document.getElementById('uploadProgress');
        const statusElement = document.getElementById('uploadStatus');
        const resultsContainer = document.getElementById('importResults');

        uploadBtn.disabled = true;
        uploadBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Processing...';
        progressContainer.style.display = 'block';

        const xhr = new XMLHttpRequest();

        // Track upload progress
        xhr.upload.addEventListener('progress', function(e) {
            if (e.lengthComputable) {
                const percentComplete = (e.loaded / e.total) * 100;
                progressBar.style.width = percentComplete + '%';
                statusElement.innerHTML = 'Uploading... ' + Math.round(percentComplete) + '%';
            }
        });

        xhr.addEventListener('load', function() {
            try {
                const data = JSON.parse(xhr.responseText);

                // Show results
                resultsContainer.classList.remove('hidden');

                if (data.success) {
                    progressBar.style.width = '100%';

                    // Determine status message color based on error count
                    if (data.error_count === 0) {
                        statusElement.innerHTML = `<span class="text-green-600">${data.imported_count} projects imported successfully with no errors.</span>`;
                    } else {
                        statusElement.innerHTML = `<span class="text-green-600">${data.imported_count} projects imported successfully, </span><span class="text-red-600">${data.error_count} error(s) found. Check below!</span>`;
                    }

                    // Show import stats
                    document.getElementById('importStats').innerHTML = `
                        <div class="bg-green-50 rounded-lg p-4 text-center border border-green-200">
                            <div class="text-2xl font-bold text-green-600">${data.imported_count}</div>
                            <div class="text-sm text-green-700">Projects Imported</div>
                        </div>
                        <div class="${data.error_count > 0 ? 'bg-red-50 border-red-200' : 'bg-green-50 border-green-200'} rounded-lg p-4 text-center border">
                            <div class="text-2xl font-bold ${data.error_count > 0 ? 'text-red-600' : 'text-green-600'}">${data.error_count}</div>
                            <div class="text-sm ${data.error_count > 0 ? 'text-red-700' : 'text-green-700'}">Errors Found</div>
                        </div>
                    `;

                    // Show errors if any
                    if (data.errors && data.errors.length > 0) {
                        document.getElementById('importErrors').classList.remove('hidden');
                        
                        let errorHtml = '';
                        let technicalDetails = [];
                        
                        data.errors.forEach(error => {
                            if (typeof error === 'object') {
                                errorHtml += `<li>• ${error.user_message}</li>`;
                                technicalDetails.push(error.technical_details || error.user_message);
                            } else {
                                errorHtml += `<li>• ${error}</li>`;
                                technicalDetails.push(error);
                            }
                        });
                        
                        document.getElementById('errorList').innerHTML = errorHtml;
                        
                        // Store technical details for copying
                        window.csvTechnicalDetails = technicalDetails.join('\n');
                        
                        // Show copy button
                        document.getElementById('copyErrorsBtn').classList.remove('hidden');
                    } else {
                        document.getElementById('importErrors').classList.add('hidden');
                        document.getElementById('copyErrorsBtn').classList.add('hidden');
                    }
                } else {
                    // Complete failure case
                    statusElement.innerHTML = `<span class="text-red-600">Import failed: ${data.message}. Check below!</span>`;

                    document.getElementById('importStats').innerHTML = `
                        <div class="bg-red-50 rounded-lg p-4 text-center border border-red-200">
                            <div class="text-lg font-bold text-red-600">Import Failed!</div>
                            <div class="text-sm text-red-700">${data.message}</div>
                        </div>
                    `;

                    if (data.errors && data.errors.length > 0) {
                        document.getElementById('importErrors').classList.remove('hidden');
                        
                        let errorHtml = '';
                        let technicalDetails = [];
                        
                        data.errors.forEach(error => {
                            if (typeof error === 'object') {
                                errorHtml += `<li>• ${error.user_message}</li>`;
                                technicalDetails.push(error.technical_details || error.user_message);
                            } else {
                                errorHtml += `<li>• ${error}</li>`;
                                technicalDetails.push(error);
                            }
                        });
                        
                        document.getElementById('errorList').innerHTML = errorHtml;
                        
                        // Store technical details for copying
                        window.csvTechnicalDetails = technicalDetails.join('\n');
                        
                        // Show copy button
                        document.getElementById('copyErrorsBtn').classList.remove('hidden');
                    }
                }

                // Reset form
                uploadBtn.disabled = false;
                uploadBtn.innerHTML = '<i class="fas fa-upload mr-2"></i>Import Projects';
                progressContainer.style.display = 'none';
                progressBar.style.width = '0%';

            } catch (error) {
                statusElement.innerHTML = '<span class="text-red-600">Processing failed: Invalid response</span>';
                uploadBtn.disabled = false;
                uploadBtn.innerHTML = '<i class="fas fa-upload mr-2"></i>Import Projects';
                progressContainer.style.display = 'none';
                progressBar.style.width = '0%';
            }
        });

        xhr.addEventListener('error', function() {
            statusElement.innerHTML = '<span class="text-red-600">Upload failed: Network error</span>';
            uploadBtn.disabled = false;
            uploadBtn.innerHTML = '<i class="fas fa-upload mr-2"></i>Import Projects';
            progressContainer.style.display = 'none';
            progressBar.style.width = '0%';
        });

        xhr.open('POST', '../api/uploadCsv.php');
        xhr.send(formData);
    });
});

// Copy error details function
function copyErrorDetails() {
    if (window.csvTechnicalDetails) {
        const timestamp = new Date().toLocaleString();
        const content = `CSV Import Error Details\nTimestamp: ${timestamp}\n\n${window.csvTechnicalDetails}`;
        
        if (navigator.clipboard) {
            navigator.clipboard.writeText(content).then(() => {
                showCopySuccess();
            }).catch(() => {
                fallbackCopy(content);
            });
        } else {
            fallbackCopy(content);
        }
    }
}

function fallbackCopy(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        document.execCommand('copy');
        showCopySuccess();
    } catch (err) {
        console.error('Copy failed:', err);
        alert('Copy failed. Please manually select and copy the error details.');
    }
    
    document.body.removeChild(textArea);
}

function showCopySuccess() {
    const button = document.getElementById('copyErrorsBtn');
    const originalText = button.innerHTML;
    button.innerHTML = '<i class="fas fa-check mr-1"></i>Copied!';
    button.classList.add('bg-green-50', 'text-green-700', 'border-green-300');
    
    setTimeout(() => {
        button.innerHTML = originalText;
        button.classList.remove('bg-green-50', 'text-green-700', 'border-green-300');
    }, 2000);
}
</script>

<?php include 'includes/adminFooter.php'; ?>
