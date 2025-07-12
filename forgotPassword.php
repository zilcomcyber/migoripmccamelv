<?php
require_once 'config.php';
require_once 'includes/auth.php';
require_once 'includes/functions.php';
require_once 'includes/passwordRecovery.php';

// Redirect if already logged in
if (is_logged_in()) {
    header('Location: admin/');
    exit;
}

$message = '';
$message_type = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $message = 'Security token mismatch. Please try again.';
        $message_type = 'error';
    } else {
        $email = sanitize_input($_POST['email'] ?? '', 'email');
        
        if (empty($email)) {
            $message = 'Please enter your email address';
            $message_type = 'error';
        } else {
            // Rate limiting
            if (!enhanced_rate_limit('forgot_password', 3, 300)) {
                $message = 'Too many password reset attempts. Please try again later.';
                $message_type = 'error';
            } else {
                $result = send_password_reset_email($email);
                $message = $result['message'];
                $message_type = $result['success'] ? 'success' : 'error';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password - <?php echo APP_NAME; ?></title>
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
                <div class="mx-auto h-12 w-12 flex items-center justify-center rounded-full bg-orange-100 dark:bg-orange-900">
                    <i class="fas fa-key text-orange-600 dark:text-orange-400 text-xl"></i>
                </div>
                <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-white">
                    Forgot Password
                </h2>
                <p class="mt-2 text-center text-sm text-gray-600 dark:text-gray-400">
                    Enter your email address and we'll send you a password reset link
                </p>
            </div>

            <?php if ($message): ?>
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
            <?php endif; ?>

            <form class="mt-8 space-y-6" method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                
                <div class="rounded-md shadow-sm">
                    <div>
                        <label for="email" class="sr-only">Email Address</label>
                        <input id="email" name="email" type="email" required 
                               class="appearance-none relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm dark:bg-gray-700" 
                               placeholder="Enter your email address"
                               value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>">
                    </div>
                </div>

                <div>
                    <button type="submit" 
                            class="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-orange-600 hover:bg-orange-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-500 transition-colors">
                        <span class="absolute left-0 inset-y-0 flex items-center pl-3">
                            <i class="fas fa-paper-plane text-orange-500 group-hover:text-orange-400"></i>
                        </span>
                        Send Reset Link
                    </button>
                </div>

                <div class="flex items-center justify-between">
                    <div class="text-sm">
                        <a href="login.php" class="text-blue-600 dark:text-blue-400 hover:text-blue-500 dark:hover:text-blue-300 transition-colors">
                            <i class="fas fa-arrow-left mr-1"></i>
                            Back to Login
                        </a>
                    </div>
                    <div class="text-sm">
                        <a href="<?php echo BASE_URL; ?>" class="text-blue-600 dark:text-blue-400 hover:text-blue-500 dark:hover:text-blue-300 transition-colors">
                            <i class="fas fa-home mr-1"></i>
                            Public Portal
                        </a>
                    </div>
                </div>
            </form>

            <div class="mt-6 text-center">
                <div class="text-xs text-gray-500 dark:text-gray-400">
                    <p>If you don't receive an email within a few minutes, please check your spam folder.</p>
                    <p class="mt-2">For technical support, contact your system administrator.</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Focus on email field
        document.getElementById('email').focus();
    </script>
</body>
</html>
