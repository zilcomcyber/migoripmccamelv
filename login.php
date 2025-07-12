<?php
require_once 'config.php';
require_once 'includes/functions.php';
require_once 'includes/auth.php';

// Redirect if already logged in
if (is_logged_in()) {
    header('Location: admin/');
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = sanitize_input($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (empty($email) || empty($password)) {
        $error = 'Please enter both Email and password';
    } else {
        try {
            $result = login_user($email, $password);
            if ($result['success']) {
                // Add debugging for production
                error_log("Login successful for user: " . $email);
                
                // Ensure session is started before redirect
                if (session_status() === PHP_SESSION_NONE) {
                    init_secure_session();
                }
                
                // Use absolute URL for redirect in production
                $redirect_url = BASE_URL . 'admin/';
                
                // Add debugging for production
                error_log("Redirecting to: " . $redirect_url);
                
                if (!headers_sent()) {
                    header('Location: ' . $redirect_url);
                    exit;
                } else {
                    echo '<script>window.location.href="' . $redirect_url . '";</script>';
                    exit;
                }
            } else {
                $error = $result['message'];
                error_log("Login failed for user: " . $email . " - " . $result['message']);
            }
        } catch (Exception $e) {
            error_log("Login error: " . $e->getMessage());
            $error = 'Login system error. Please try again.';
        }
    }
}

$timeout = isset($_GET['timeout']);
$logged_out = isset($_GET['logged_out']);
?>
<!DOCTYPE html>
<html lang="en" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - <?php echo APP_NAME; ?></title>
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
                <div class="mx-auto h-12 w-12 flex items-center justify-center rounded-full bg-blue-100 dark:bg-blue-900">
                    <i class="fas fa-user-shield text-blue-600 dark:text-blue-400 text-xl"></i>
                </div>
                <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-white">
                    Admin Portal
                </h2>
                <p class="mt-2 text-center text-sm text-gray-600 dark:text-gray-400">
                    <?php echo APP_NAME; ?>
                </p>
            </div>

            <?php if ($logged_out): ?>
                <div class="rounded-md bg-green-50 dark:bg-green-900 p-4">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <i class="fas fa-check-circle text-green-400"></i>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm text-green-700 dark:text-green-300">
                                You have been successfully logged out. Please log in again to continue.
                            </p>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

            <?php if ($timeout): ?>
                <div class="rounded-md bg-yellow-50 dark:bg-yellow-900 p-4">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <i class="fas fa-exclamation-triangle text-yellow-400"></i>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm text-yellow-700 dark:text-yellow-300">
                                Your session has expired. Please log in again.
                            </p>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

            <?php if ($error): ?>
                <div class="rounded-md bg-red-50 dark:bg-red-900 p-4">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <i class="fas fa-exclamation-circle text-red-400"></i>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm text-red-700 dark:text-red-300"><?php echo htmlspecialchars($error); ?></p>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

            <form class="mt-8 space-y-6" method="POST">
                <div class="rounded-md shadow-sm -space-y-px">
                    <div>
                        <label for="email" class="sr-only">Email</label>
                        <input id="email" name="email" type="text" required 
                               class="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white rounded-t-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm dark:bg-gray-700" 
                               placeholder="Email" 
                               value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>">
                    </div>
                    <div>
                        <label for="password" class="sr-only">Password</label>
                        <input id="password" name="password" type="password" required 
                               class="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white rounded-b-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm dark:bg-gray-700" 
                               placeholder="Password">
                    </div>
                </div>

                <div>
                    <button type="submit" 
                            class="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors">
                        <span class="absolute left-0 inset-y-0 flex items-center pl-3">
                            <i class="fas fa-lock text-blue-500 group-hover:text-blue-400"></i>
                        </span>
                        Sign in
                    </button>
                </div>

                <div class="flex items-center justify-between">
                    <div class="text-sm">
                        <a href="forgotPassword.php" class="text-blue-600 dark:text-blue-400 hover:text-blue-500 dark:hover:text-blue-300 transition-colors">
                            <i class="fas fa-key mr-1"></i>
                            Forgot your password?
                        </a>
                    </div>
                    <div class="text-sm">
                        <a href="<?php echo BASE_URL; ?>" class="text-blue-600 dark:text-blue-400 hover:text-blue-500 dark:hover:text-blue-300 transition-colors">
                            <i class="fas fa-arrow-left mr-1"></i>
                            Back to Portal
                        </a>
                    </div>
                </div>
            </form>

            <div class="mt-6 text-center">
                <div class="text-xs text-gray-500 dark:text-gray-400">
                    Please contact your system administrator for login credentials.
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
