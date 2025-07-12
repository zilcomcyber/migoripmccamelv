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

$token = sanitize_input($_GET['token'] ?? '', 'alphanumeric');
$message = '';
$message_type = '';
$token_valid = false;

// Verify token on page load
if ($token) {
    $token_data = verify_reset_token($token);
    if ($token_data) {
        $token_valid = true;
    } else {
        $message = 'Invalid or expired reset token. Please request a new password reset.';
        $message_type = 'error';
    }
} else {
    $message = 'No reset token provided. Please check your email for the correct link.';
    $message_type = 'error';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $token_valid) {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $message = 'Security token mismatch. Please try again.';
        $message_type = 'error';
    } else {
        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';
        
        // Validation
        if (empty($new_password) || empty($confirm_password)) {
            $message = 'Please fill in all fields';
            $message_type = 'error';
        } elseif (strlen($new_password) < 8) {
            $message = 'Password must be at least 8 characters long';
            $message_type = 'error';
        } elseif ($new_password !== $confirm_password) {
            $message = 'Passwords do not match';
            $message_type = 'error';
        } elseif (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/', $new_password)) {
            $message = 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character';
            $message_type = 'error';
        } else {
            // Rate limiting
            if (!enhanced_rate_limit('password_reset', 3, 300)) {
                $message = 'Too many reset attempts. Please try again later.';
                $message_type = 'error';
            } else {
                $result = reset_password_with_token($token, $new_password);
                $message = $result['message'];
                $message_type = $result['success'] ? 'success' : 'error';
                
                if ($result['success']) {
                    $token_valid = false; // Prevent further attempts
                }
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
    <title>Reset Password - <?php echo APP_NAME; ?></title>
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
                <div class="mx-auto h-12 w-12 flex items-center justify-center rounded-full <?php echo $token_valid ? 'bg-green-100 dark:bg-green-900' : 'bg-red-100 dark:bg-red-900'; ?>">
                    <i class="fas <?php echo $token_valid ? 'fa-lock text-green-600 dark:text-green-400' : 'fa-exclamation-triangle text-red-600 dark:text-red-400'; ?> text-xl"></i>
                </div>
                <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-white">
                    Reset Password
                </h2>
                <p class="mt-2 text-center text-sm text-gray-600 dark:text-gray-400">
                    <?php echo $token_valid ? 'Enter your new password below' : 'Token verification failed'; ?>
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
                            <?php if ($message_type === 'success'): ?>
                                <div class="mt-4">
                                    <a href="login.php" class="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-green-700 bg-green-100 hover:bg-green-200 dark:text-green-200 dark:bg-green-800 dark:hover:bg-green-700 transition-colors">
                                        <i class="fas fa-sign-in-alt mr-2"></i>
                                        Login Now
                                    </a>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

            <?php if ($token_valid): ?>
            <form class="mt-8 space-y-6" method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                
                <div class="rounded-md shadow-sm space-y-4">
                    <div>
                        <label for="new_password" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">New Password</label>
                        <div class="relative">
                            <input id="new_password" name="new_password" type="password" required 
                                   class="appearance-none relative block w-full px-3 py-2 pr-10 border border-gray-300 dark:border-gray-600 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm dark:bg-gray-700" 
                                   placeholder="Enter new password">
                            <button type="button" onclick="togglePassword('new_password')" class="absolute inset-y-0 right-0 pr-3 flex items-center">
                                <i class="fas fa-eye text-gray-400 hover:text-gray-600" id="new_password_icon"></i>
                            </button>
                        </div>
                    </div>
                    
                    <div>
                        <label for="confirm_password" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Confirm Password</label>
                        <div class="relative">
                            <input id="confirm_password" name="confirm_password" type="password" required 
                                   class="appearance-none relative block w-full px-3 py-2 pr-10 border border-gray-300 dark:border-gray-600 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm dark:bg-gray-700" 
                                   placeholder="Confirm new password">
                            <button type="button" onclick="togglePassword('confirm_password')" class="absolute inset-y-0 right-0 pr-3 flex items-center">
                                <i class="fas fa-eye text-gray-400 hover:text-gray-600" id="confirm_password_icon"></i>
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Password Requirements -->
                <div class="bg-blue-50 dark:bg-blue-900 border border-blue-200 dark:border-blue-700 rounded-md p-4">
                    <h4 class="text-sm font-medium text-blue-800 dark:text-blue-200 mb-2">Password Requirements:</h4>
                    <ul class="text-xs text-blue-700 dark:text-blue-300 space-y-1">
                        <li>• At least 8 characters long</li>
                        <li>• Contains uppercase and lowercase letters</li>
                        <li>• Contains at least one number</li>
                        <li>• Contains at least one special character (@$!%*?&)</li>
                    </ul>
                </div>

                <div>
                    <button type="submit" 
                            class="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 transition-colors">
                        <span class="absolute left-0 inset-y-0 flex items-center pl-3">
                            <i class="fas fa-check text-green-500 group-hover:text-green-400"></i>
                        </span>
                        Reset Password
                    </button>
                </div>
            </form>
            <?php endif; ?>

            <div class="text-center">
                <a href="login.php" class="text-blue-600 dark:text-blue-400 hover:text-blue-500 dark:hover:text-blue-300 text-sm transition-colors">
                    <i class="fas fa-arrow-left mr-1"></i>
                    Back to Login
                </a>
            </div>
        </div>
    </div>

    <script>
        function togglePassword(fieldId) {
            const field = document.getElementById(fieldId);
            const icon = document.getElementById(fieldId + '_icon');
            
            if (field.type === 'password') {
                field.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                field.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        }

        // Focus on first password field
        <?php if ($token_valid): ?>
        document.getElementById('new_password').focus();
        <?php endif; ?>
    </script>
</body>
</html>
