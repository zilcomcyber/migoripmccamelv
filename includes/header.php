<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars(isset($page_title) ? $page_title . ' - ' . APP_NAME : APP_NAME); ?></title>
    <meta name="description" content="<?php echo htmlspecialchars(isset($page_description) ? $page_description : 'Track county development projects and stay informed about ongoing and completed projects in your area'); ?>">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="robots" content="index, follow">

    <link rel="icon" type="image/png" href="<?php echo htmlspecialchars(BASE_URL); ?>migoriLogo.png">

    <!-- Preload critical resources -->
    <link rel="preload" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" as="style" crossorigin="anonymous">
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', 'ui-sans-serif', 'system-ui'],
                    },
                    colors: {
                        primary: {
                            600: '#2563eb',
                            700: '#1d4ed8',
                        },
                        danger: {
                            500: '#ef4444',
                            600: '#dc2626'
                        }
                    }
                }
            }
        }
    </script>

    <!-- FontAwesome and Main Styles -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" crossorigin="anonymous" referrerpolicy="no-referrer">
    <link rel="stylesheet" href="<?php echo htmlspecialchars(BASE_URL); ?>assets/css/styles.css?v=<?php echo time(); ?>">
    <script>
        window.BASE_URL = '<?php echo htmlspecialchars(BASE_URL); ?>';
    </script>
</head>
<body class="bg-gray-50 font-sans antialiased">
    <!-- Header -->
    <header class="bg-white shadow-sm fixed top-0 left-0 right-0 z-50 border-b border-gray-200">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between items-center h-16">
                <!-- Logo and mobile menu button -->
                <div class="flex items-center">
                    <?php if (isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in']): ?>
                    <button id="mobile-menu-button" class="lg:hidden p-2 rounded-md text-gray-500 hover:text-gray-600 hover:bg-gray-100">
                        <i class="fas fa-bars"></i>
                    </button>
                    <?php endif; ?>

                    <a href="<?php echo htmlspecialchars(BASE_URL); ?>" class="flex items-center ml-2 lg:ml-0">
                        <img src="<?php echo htmlspecialchars(BASE_URL); ?>migoriLogo.png" 
                             alt="County Logo" 
                             class="h-10 w-10 rounded-lg"
                             width="40"
                             height="40"
                             loading="eager">
                        <div class="ml-3">
                            <h1 class="text-lg font-bold text-gray-900"><?php echo htmlspecialchars(APP_NAME); ?></h1>
                            <p class="text-xs text-gray-500">Migori County Government</p>
                        </div>
                    </a>
                </div>

                <!-- Desktop navigation -->
                <div class="hidden lg:flex items-center space-x-6">
                    <?php if (isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in']): ?>
                    <div class="flex items-center space-x-4">
                        <a href="<?php echo htmlspecialchars(BASE_URL); ?>admin/dashboard.php" 
                           class="px-3 py-1.5 text-sm font-medium text-gray-700 hover:text-primary-600 rounded-md transition-colors">
                            Dashboard
                        </a>

                        <div class="flex items-center">
                            <div class="text-right mr-3">
                                <p class="text-sm font-medium text-gray-900"><?php echo htmlspecialchars($_SESSION['admin_name'] ?? 'Admin'); ?></p>
                                <p class="text-xs text-gray-500">Administrator</p>
                            </div>
                            <a href="<?php echo htmlspecialchars(BASE_URL); ?>logout.php" 
                               class="flex items-center justify-center w-9 h-9 rounded-full bg-danger-500 text-white hover:bg-danger-600 transition-colors"
                               aria-label="Logout"
                               title="Logout">
                                <i class="fas fa-sign-out-alt text-sm"></i>
                            </a>
                        </div>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Mobile menu -->
        <?php if (isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in']): ?>
        <div id="mobile-menu" class="lg:hidden hidden border-t border-gray-200 bg-white">
            <div class="px-4 py-3 space-y-1">
                <a href="<?php echo htmlspecialchars(BASE_URL); ?>admin/dashboard.php" 
                   class="block px-3 py-2 rounded-md text-base font-medium text-gray-700 hover:text-primary-600 hover:bg-gray-50">
                    Dashboard
                </a>
                <div class="border-t border-gray-200 pt-3 mt-2">
                    <div class="px-3 py-2 text-sm text-gray-500">
                        Logged in as <span class="font-medium text-gray-900"><?php echo htmlspecialchars($_SESSION['admin_name'] ?? 'Admin'); ?></span>
                    </div>
                    <a href="<?php echo htmlspecialchars(BASE_URL); ?>logout.php" 
                       class="block px-3 py-2 rounded-md text-base font-medium text-danger-600 hover:bg-danger-50">
                        Logout
                    </a>
                </div>
            </div>
        </div>
        <?php endif; ?>
    </header>

    <main class="pt-16">