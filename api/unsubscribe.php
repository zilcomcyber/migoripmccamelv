<?php
require_once '../config.php';
require_once '../includes/functions.php';
require_once '../includes/projectSubscriptions.php';

$token = $_GET['token'] ?? '';

if (!$token) {
    http_response_code(400);
    die('Invalid unsubscribe link');
}

try {
    $subscription_manager = new ProjectSubscriptionManager($pdo);
    $result = $subscription_manager->unsubscribe($token);
    
    $message = $result['message'];
    $success = $result['success'];
    
} catch (Exception $e) {
    error_log("Unsubscribe error: " . $e->getMessage());
    $message = 'Unsubscribe failed. Please try again.';
    $success = false;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unsubscribe - Migori County</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100">
    <div class="min-h-screen flex items-center justify-center">
        <div class="max-w-md w-full bg-white rounded-lg shadow-md p-8">
            <div class="text-center">
                <img src="<?php echo BASE_URL; ?>migoriLogo.png" alt="Migori County" class="h-16 mx-auto mb-4">
                <h1 class="text-2xl font-bold text-gray-900 mb-4">Unsubscribe</h1>
                
                <?php if ($success): ?>
                    <div class="bg-green-50 border border-green-200 rounded-md p-4 mb-4">
                        <div class="flex">
                            <svg class="h-5 w-5 text-green-400" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
                            </svg>
                            <div class="ml-3">
                                <p class="text-sm text-green-800"><?php echo htmlspecialchars($message); ?></p>
                            </div>
                        </div>
                    </div>
                    <p class="text-gray-600 text-sm mb-4">
                        We're sorry to see you go. You can always resubscribe to project updates anytime.
                    </p>
                <?php else: ?>
                    <div class="bg-red-50 border border-red-200 rounded-md p-4 mb-4">
                        <div class="flex">
                            <svg class="h-5 w-5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/>
                            </svg>
                            <div class="ml-3">
                                <p class="text-sm text-red-800"><?php echo htmlspecialchars($message); ?></p>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
                
                <a href="<?php echo BASE_URL; ?>" class="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                    Return to Home
                </a>
            </div>
        </div>
    </div>
</body>
</html>
