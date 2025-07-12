<?php
require_once 'config.php';
require_once 'includes/functions.php';
require_once 'includes/passwordRecovery.php';

// Redirect if already logged in
if (is_logged_in()) {
    header('Location: admin/');
    exit;
}

$token = sanitize_input($_GET['token'] ?? '', 'alphanumeric');
$message = '';
$message_type = '';
$processed = false;

if ($token) {
    // Rate limiting
    if (!enhanced_rate_limit('account_activation', 3, 300)) {
        $message = 'Too many activation attempts. Please try again later.';
        $message_type = 'error';
    } else {
        $result = activate_account_with_token($token);
        $message = $result['message'];
        $message_type = $result['success'] ? 'success' : 'error';
    }
    $processed = true;
} else {
    $message = 'No activation token provided. Please check your email for the correct link.';
    $message_type = 'error';
    $processed = true;
}
?>
<!DOCTYPE html>
<html lang="en" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Activation - <?php echo APP_NAME; ?></title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="assets/css/style.css?v=<?php echo filemtime(__DIR__ . '/assets/css/style.css'); ?>">    
    
    <script>
        tailwind.config = {
            darkMode: 'class'
        }
    </script>
</head>
<body class="h-full bg-gray-50 dark:bg-gray-900">
    <div class="min-h-full flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
        <div class="max-w-md w-full space-y-8">
            <div>
                <div class="mx-auto h-12 w-12 flex items-center justify-center rounded-full <?php echo $message_type === 'success' ? 'bg-green-100 dark:bg-green-900' : 'bg-red-100 dark:bg-red-900'; ?>">
                    <i class="fas <?php echo $message_type === 'success' ? 'fa-check-circle text-green-600 dark:text-green-400' : 'fa-exclamation-triangle text-red-600 dark:text-red-400'; ?> text-xl"></i>
                </div>
                <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-white">
                    Account Activation
                </h2>
                <p class="mt-2 text-center text-sm text-gray-600 dark:text-gray-400">
                    <?php echo $message_type === 'success' ? 'Your account has been activated!' : 'Activation failed'; ?>
                </p>
            </div>

            <?php if ($processed): ?>
                <div class="rounded-md <?php echo $message_type === 'success' ? 'bg-green-50 dark:bg-green-900' : 'bg-red-50 dark:bg-red-900'; ?> p-4">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <i class="fas <?php echo $message_type === 'success' ? 'fa-check-circle text-green-400' : 'fa-exclamation-circle text-red-400'; ?>"></i>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm <?php echo $message_type === 'success' ? 'text-green-700 dark:text-green-300' : 'text-red-700 dark:text-red-300'; ?>">
                                <?php echo htmlspecialchars($message); ?>
                            </p>
                        </div>
                    </div>
                </div>

                <?php if ($message_type === 'success'): ?>
                <div class="bg-blue-50 dark:bg-blue-900 border border-blue-200 dark:border-blue-700 rounded-md p-4">
                    <h4 class="text-sm font-medium text-blue-800 dark:text-blue-200 mb-2">What's Next?</h4>
                    <ul class="text-xs text-blue-700 dark:text-blue-300 space-y-1">
                        <li>• Your account is now active and ready to use</li>
                        <li>• You can login with your assigned credentials</li>
                        <li>• Access the PMC System dashboard</li>
                        <li>• Start managing projects and administrative tasks</li>
                    </ul>
                </div>

                <div class="space-y-3">
                    <a href="login.php" 
                       class="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 transition-colors">
                        <span class="absolute left-0 inset-y-0 flex items-center pl-3">
                            <i class="fas fa-sign-in-alt text-green-500 group-hover:text-green-400"></i>
                        </span>
                        Login to PMC System
                    </a>
                    
                    <a href="<?php echo BASE_URL; ?>" 
                       class="group relative w-full flex justify-center py-2 px-4 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors">
                        <span class="absolute left-0 inset-y-0 flex items-center pl-3">
                            <i class="fas fa-home text-gray-500 group-hover:text-gray-400"></i>
                        </span>
                        Visit Public Portal
                    </a>
                </div>
                <?php else: ?>
                <div class="space-y-3">
                    <a href="forgotPassword.php" 
                       class="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-orange-600 hover:bg-orange-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-500 transition-colors">
                        <span class="absolute left-0 inset-y-0 flex items-center pl-3">
                            <i class="fas fa-key text-orange-500 group-hover:text-orange-400"></i>
                        </span>
                        Request New Activation
                    </a>
                    
                    <a href="login.php" 
                       class="group relative w-full flex justify-center py-2 px-4 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors">
                        <span class="absolute left-0 inset-y-0 flex items-center pl-3">
                            <i class="fas fa-arrow-left text-gray-500 group-hover:text-gray-400"></i>
                        </span>
                        Back to Login
                    </a>
                </div>
                <?php endif; ?>
            <?php else: ?>
                <div class="text-center">
                    <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
                    <p class="mt-2 text-sm text-gray-600 dark:text-gray-400">Processing activation...</p>
                </div>
            <?php endif; ?>

            <div class="mt-6 text-center">
                <div class="text-xs text-gray-500 dark:text-gray-400">
                    <p>If you continue to experience issues, please contact your system administrator.</p>
                    <p class="mt-2">Need help? Contact support for assistance.</p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
