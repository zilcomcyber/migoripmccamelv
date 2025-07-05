<?php
// Check if this is a project-specific 404
$is_project_404 = isset($_GET['type']) && $_GET['type'] === 'project';
$project_id = isset($_GET['id']) ? intval($_GET['id']) : null;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $is_project_404 ? 'Project Not Found' : 'Page Not Found'; ?> - Migori County</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .error-highlight {
            background: linear-gradient(120deg, #f59e0b30 0%, #ef444430 100%);
            background-repeat: no-repeat;
            background-size: 100% 30%;
            background-position: 0 88%;
        }
    </style>
</head>
<body class="bg-gray-50 min-h-screen flex flex-col">
    <!-- Minimal Header -->
    <header class="bg-white shadow-sm">
        <div class="container mx-auto px-4 py-3 flex items-center">
            <a href="#" class="flex items-center">
                <img src="../migoriLogo.png" alt="Logo" class="h-8 w-8 mr-2">
                <span class="font-semibold text-gray-800">Migori County</span>
            </a>
        </div>
    </header>

    <!-- Main Content -->
    <main class="flex-grow flex items-center">
        <div class="container mx-auto px-4 py-8 max-w-md text-center">
            <div class="mb-6">
                <span class="inline-block text-6xl font-bold text-red-600">404</span>
                <h1 class="mt-2 text-2xl font-bold text-gray-800 error-highlight">
                    <?php echo $is_project_404 ? 'Project Not Found' : 'Page Not Found'; ?>
                </h1>
            </div>

            <p class="text-gray-600 mb-6">
                <?php if ($is_project_404): ?>
                    The requested project <?php echo $project_id ? "(ID: $project_id)" : ''; ?> could not be found.
                <?php else: ?>
                    The page you're looking for doesn't exist or may have been moved.
                <?php endif; ?>
            </p>

            <div class="flex flex-col sm:flex-row gap-3 justify-center">
                <a href="../index.php" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition">
                    <i class="fas fa-home mr-1"></i> Home
                </a>
                <a href="../index.php" class="px-4 py-2 border border-gray-300 rounded hover:bg-gray-50 transition">
                    <i class="fas fa-search mr-1"></i> Browse Projects
                </a>
            </div>
        </div>
    </main>

    <!-- Simple Footer -->
    <footer class="bg-white py-4 border-t">
        <div class="container mx-auto px-4 text-center text-sm text-gray-500">
            &copy; <?php echo date('Y'); ?> Migori County Government
        </div>
    </footer>

    <!-- Font Awesome -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</body>
</html>