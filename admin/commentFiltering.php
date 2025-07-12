<?php
require_once 'includes/pageSecurity.php';
require_once '../config.php';
require_once '../includes/auth.php';
require_once '../includes/functions.php';
require_once '../includes/rbac.php';
require_once '../includes/commentFilter.php';

require_role('admin');
$current_admin = get_current_admin();
$page_title = "Comment Filtering Management";

// Restrict to super admin only
if ($current_admin['role'] !== 'super_admin') {
    $_SESSION['access_denied'] = "Only super administrators can access comment filtering management.";
    header('Location: index.php');
    exit;
}

// Handle AJAX requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax'])) {
    header('Content-Type: application/json');

    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        echo json_encode(['success' => false, 'message' => 'Invalid security token']);
        exit;
    }

    $action = $_POST['action'] ?? '';

    if ($action === 'update_words') {
        $banned_words = array_filter(array_map('trim', explode("\n", $_POST['banned_words'] ?? '')));
        $flagged_words = array_filter(array_map('trim', explode("\n", $_POST['flagged_words'] ?? '')));

        $word_data = [
            'banned_words' => $banned_words,
            'flagged_words' => $flagged_words
        ];

        $json_file = __DIR__ . '/../banned_and_flagged_words.json';
        if (file_put_contents($json_file, json_encode($word_data, JSON_PRETTY_PRINT))) {
            log_activity('word_list_updated', 'Updated banned and flagged words list', $current_admin['id']);
            echo json_encode(['success' => true, 'message' => 'Word lists updated successfully']);
        } else {
            echo json_encode(['success' => false, 'message' => 'Failed to update word lists']);
        }
        exit;
    }
}

// Load current word lists
$json_file = __DIR__ . '/../banned_and_flagged_words.json';
$word_data = ['banned_words' => [], 'flagged_words' => []];

if (file_exists($json_file)) {
    $loaded_data = json_decode(file_get_contents($json_file), true);
    if ($loaded_data) {
        $word_data = $loaded_data;
    }
}

// Get filtering statistics
try {
    // Auto-approved comments (clean content)
    $stmt = $pdo->query("
        SELECT COUNT(*) FROM feedback 
        WHERE status = 'approved' 
        AND filtering_metadata IS NOT NULL 
        AND JSON_EXTRACT(filtering_metadata, '$.reason') = 'clean_content'
        AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    ");
    $auto_approved = $stmt->fetchColumn();

    // Flagged for review (flagged words or language review)
    $stmt = $pdo->query("
        SELECT COUNT(*) FROM feedback 
        WHERE status = 'pending' 
        AND filtering_metadata IS NOT NULL 
        AND JSON_EXTRACT(filtering_metadata, '$.reason') IN ('flagged_words', 'language_review')
        AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    ");
    $flagged_for_review = $stmt->fetchColumn();

    // Auto-rejected comments (banned words or invalid length)
    $stmt = $pdo->query("
        SELECT COUNT(*) FROM feedback 
        WHERE status = 'rejected' 
        AND filtering_metadata IS NOT NULL 
        AND JSON_EXTRACT(filtering_metadata, '$.reason') IN ('banned_words', 'invalid_length')
        AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    ");
    $auto_rejected = $stmt->fetchColumn();
} catch (Exception $e) {
    error_log("Filter stats error: " . $e->getMessage());
    $auto_approved = 0;
    $flagged_for_review = 0;
    $auto_rejected = 0;
}

include 'includes/adminHeader.php';
?>

<div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
    <!-- Breadcrumb -->
    <div class="mb-6">
        <nav class="flex" aria-label="Breadcrumb">
            <ol class="flex items-center space-x-2 text-sm">
                <li class="text-gray-600 font-medium">
                    <i class="fas fa-home mr-1"></i> Dashboard
                </li>
                <li class="text-gray-400">/</li>
                <li class="text-gray-600 font-medium">Comment Filtering</li>
            </ol>
        </nav>
    </div>

    <!-- Page Header -->
    <div class="mb-8">
        <div class="bg-white shadow-sm rounded-lg border border-gray-200 p-6">
            <h1 class="text-2xl font-bold text-gray-900 mb-2">Comment Filtering Management</h1>
            <p class="text-gray-600">Manage word lists and filtering rules for community comments</p>
            <div class="mt-2 text-sm text-blue-600">
                <i class="fas fa-info-circle mr-1"></i>
                Super Admin Access Only - Manage banned and flagged words for automatic comment moderation
            </div>
        </div>
    </div>

    <!-- Filtering Statistics -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div class="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
            <div class="text-3xl font-bold text-green-600"><?php echo $auto_approved; ?></div>
            <div class="text-sm text-gray-600">Auto-Approved (30 days)</div>
        </div>
        <div class="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
            <div class="text-3xl font-bold text-yellow-600"><?php echo $flagged_for_review; ?></div>
            <div class="text-sm text-gray-600">Flagged for Review (30 days)</div>
        </div>
        <div class="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
            <div class="text-3xl font-bold text-red-600"><?php echo $auto_rejected; ?></div>
            <div class="text-sm text-gray-600">Auto-Rejected (30 days)</div>
        </div>
        <div class="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
            <div class="text-3xl font-bold text-blue-600"><?php echo count($word_data['banned_words']) + count($word_data['flagged_words']); ?></div>
            <div class="text-sm text-gray-600">Total Filter Words</div>
        </div>
    </div>

    <!-- Word Lists Management -->
    <div class="bg-white rounded-lg shadow-sm border border-gray-200">
        <div class="p-6 border-b border-gray-200">
            <h3 class="text-lg font-semibold text-gray-900">Word Lists Management</h3>
            <p class="text-sm text-gray-600 mt-1">Update banned and flagged words for automatic filtering</p>
        </div>
        <div class="p-6">
            <form id="wordListForm">
                <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                <input type="hidden" name="action" value="update_words">
                <input type="hidden" name="ajax" value="1">

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">
                            <i class="fas fa-ban text-red-500 mr-1"></i>
                            Banned Words (Auto-reject)
                        </label>
                        <div class="relative">
                            <textarea id="banned_words_input" name="banned_words" rows="12" 
                                      class="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                                      placeholder="Enter one word per line..."><?php echo implode("\n", $word_data['banned_words']); ?></textarea>
                            <div id="banned_words_display" class="absolute inset-0 px-3 py-2 pointer-events-none bg-white rounded-md" style="color: rgba(0,0,0,0.3); filter: blur(1px); text-shadow: 0 0 5px rgba(0,0,0,0.5);">
                                <?php echo implode("\n", array_map(function($word) { return str_repeat('*', strlen($word)); }, $word_data['banned_words'])); ?>
                            </div>
                        </div>
                        <div id="banned_duplicates_alert" class="hidden text-xs text-orange-600 mt-1 p-2 bg-orange-50 border border-orange-200 rounded"></div>
                        <p class="text-xs text-gray-500 mt-1">Comments containing these words will be automatically rejected</p>
                    </div>

                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">
                            <i class="fas fa-flag text-yellow-500 mr-1"></i>
                            Flagged Words (Manual review)
                        </label>
                        <textarea id="flagged_words_input" name="flagged_words" rows="12" 
                                  class="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                                  placeholder="Enter one word per line..."><?php echo implode("\n", $word_data['flagged_words']); ?></textarea>
                        <div id="flagged_duplicates_alert" class="hidden text-xs text-orange-600 mt-1 p-2 bg-orange-50 border border-orange-200 rounded"></div>
                        <p class="text-xs text-gray-500 mt-1">Comments containing these words will be sent for manual review</p>
                    </div>
                </div>

                <button type="submit" class="w-full px-4 py-2 bg-blue-600 text-white font-medium rounded-md hover:bg-blue-700">
                    <i class="fas fa-save mr-2"></i>Update Word Lists
                </button>
            </form>
        </div>
    </div>
</div>

<script>
// Get current words for duplicate checking
const currentBannedWords = <?php echo json_encode($word_data['banned_words']); ?>;
const currentFlaggedWords = <?php echo json_encode($word_data['flagged_words']); ?>;

// Handle banned words input protection
const bannedInput = document.getElementById('banned_words_input');
const bannedDisplay = document.getElementById('banned_words_display');

// Show distorted overlay when not focused
bannedInput.addEventListener('blur', function() {
    bannedDisplay.style.display = 'block';
});

bannedInput.addEventListener('focus', function() {
    bannedDisplay.style.display = 'none';
});

// Check for duplicates
function checkDuplicates(textarea, currentWords, alertElement) {
    const newWords = textarea.value.split('\n').map(w => w.trim().toLowerCase()).filter(w => w.length > 0);
    const duplicates = newWords.filter(word => currentWords.map(w => w.toLowerCase()).includes(word));
    
    if (duplicates.length > 0) {
        alertElement.textContent = `Duplicate words found: ${duplicates.join(', ')}`;
        alertElement.classList.remove('hidden');
    } else {
        alertElement.classList.add('hidden');
    }
}

// Add event listeners for duplicate checking
bannedInput.addEventListener('input', function() {
    checkDuplicates(this, currentBannedWords, document.getElementById('banned_duplicates_alert'));
});

document.getElementById('flagged_words_input').addEventListener('input', function() {
    checkDuplicates(this, currentFlaggedWords, document.getElementById('flagged_duplicates_alert'));
});

document.getElementById('wordListForm').addEventListener('submit', function(e) {
    e.preventDefault();

    const formData = new FormData(this);
    const submitBtn = this.querySelector('button[type="submit"]');

    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Updating...';

    fetch('commentFiltering.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Show success message
            const successDiv = document.createElement('div');
            successDiv.className = 'bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded mb-4';
            successDiv.textContent = data.message;
            this.parentNode.insertBefore(successDiv, this);

            setTimeout(() => {
                successDiv.remove();
                // Reload page to update current words for duplicate checking
                window.location.reload();
            }, 2000);
        } else {
            alert('Error: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred while updating word lists');
    })
    .finally(() => {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-save mr-2"></i>Update Word Lists';
    });
});

// Initial setup - show distorted overlay
bannedDisplay.style.display = 'block';
</script>

<?php include 'includes/adminFooter.php'; ?>

