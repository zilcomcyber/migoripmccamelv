<?php
require_once 'config.php';
require_once 'includes/functions.php';

// Get filter parameters for search functionality
$search_query = $_GET['search'] ?? '';
$view_mode = $_GET['view'] ?? 'grid'; // grid, list, map
$status_filter = $_GET['status'] ?? ''; // Filter by specific status

// Function to get projects by status with pagination
function get_projects_by_status($status, $search_query = '', $limit = 6, $offset = 0) {
    global $pdo;
    $sql = "SELECT p.*, d.name as department_name, w.name as ward_name, 
                   sc.name as sub_county_name, c.name as county_name
            FROM projects p
            JOIN departments d ON p.department_id = d.id
            JOIN wards w ON p.ward_id = w.id
            JOIN sub_counties sc ON p.sub_county_id = sc.id
            JOIN counties c ON p.county_id = c.id
            WHERE p.visibility = 'published' AND p.status = ?";

    $params = [$status];

    if (!empty($search_query)) {
        $sql .= " AND (p.project_name LIKE ? OR p.description LIKE ? OR sc.name LIKE ?)";
        $search_param = "%$search_query%";
        $params[] = $search_param;
        $params[] = $search_param;
        $params[] = $search_param;
    }

    $sql .= " ORDER BY p.created_at DESC LIMIT ? OFFSET ?";
    $params[] = $limit;
    $params[] = $offset;

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

// Function to get total count of projects by status
function get_projects_count_by_status($status, $search_query = '') {
    global $pdo;
    $sql = "SELECT COUNT(*) FROM projects p
            JOIN departments d ON p.department_id = d.id
            JOIN wards w ON p.ward_id = w.id
            JOIN sub_counties sc ON p.sub_county_id = sc.id
            JOIN counties c ON p.county_id = c.id
            WHERE p.visibility = 'published' AND p.status = ?";

    $params = [$status];

    if (!empty($search_query)) {
        $sql .= " AND (p.project_name LIKE ? OR p.description LIKE ? OR sc.name LIKE ?)";
        $search_param = "%$search_query%";
        $params[] = $search_param;
        $params[] = $search_param;
        $params[] = $search_param;
    }

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchColumn();
}

// Pagination parameters
$items_per_page = 6;
$ongoing_page = max(1, (int)($_GET['ongoing_page'] ?? 1));
$completed_page = max(1, (int)($_GET['completed_page'] ?? 1));
$planning_page = max(1, (int)($_GET['planning_page'] ?? 1));

// Calculate offsets
$ongoing_offset = ($ongoing_page - 1) * $items_per_page;
$completed_offset = ($completed_page - 1) * $items_per_page;
$planning_offset = ($planning_page - 1) * $items_per_page;

// Get projects for each category with pagination based on status filter
if ($status_filter) {
    // If status filter is set, only show that category
    $ongoing_projects = $status_filter === 'ongoing' ? get_projects_by_status('ongoing', $search_query, $items_per_page, $ongoing_offset) : [];
    $completed_projects = $status_filter === 'completed' ? get_projects_by_status('completed', $search_query, $items_per_page, $completed_offset) : [];
    $planning_projects = $status_filter === 'planning' ? get_projects_by_status('planning', $search_query, $items_per_page, $planning_offset) : [];

    // Get total counts for pagination
    $total_ongoing = $status_filter === 'ongoing' ? get_projects_count_by_status('ongoing', $search_query) : 0;
    $total_completed = $status_filter === 'completed' ? get_projects_count_by_status('completed', $search_query) : 0;
    $total_planning = $status_filter === 'planning' ? get_projects_count_by_status('planning', $search_query) : 0;
} else {
    // Show all categories
    $ongoing_projects = get_projects_by_status('ongoing', $search_query, $items_per_page, $ongoing_offset);
    $completed_projects = get_projects_by_status('completed', $search_query, $items_per_page, $completed_offset);
    $planning_projects = get_projects_by_status('planning', $search_query, $items_per_page, $planning_offset);

    // Get total counts for pagination
    $total_ongoing = get_projects_count_by_status('ongoing', $search_query);
    $total_completed = get_projects_count_by_status('completed', $search_query);
    $total_planning = get_projects_count_by_status('planning', $search_query);
}

// Calculate total pages
$total_ongoing_pages = ceil($total_ongoing / $items_per_page);
$total_completed_pages = ceil($total_completed / $items_per_page);
$total_planning_pages = ceil($total_planning / $items_per_page);

// Get all projects for view switching
$all_projects = array_merge($planning_projects, $ongoing_projects, $completed_projects);

// Get filter options
$departments = get_departments();
$project_years = get_project_years();
$sub_counties = get_migori_sub_counties();
$migori_wards = get_wards();

// Function to generate pagination HTML
function render_pagination($current_page, $total_pages, $category, $search_query = '') {
    if ($total_pages <= 1) return '';

    $pagination_html = '<div class="flex items-center justify-between px-4 py-3 sm:px-6">';
    $pagination_html .= '<div class="flex flex-1 justify-between sm:hidden">';

    // Mobile pagination
    if ($current_page > 1) {
        $prev_page = $current_page - 1;
        $pagination_html .= '<a href="?' . http_build_query(array_merge($_GET, [$category . '_page' => $prev_page])) . '" class="relative inline-flex items-center rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">Previous</a>';
    } else {
        $pagination_html .= '<span class="relative inline-flex items-center rounded-md border border-gray-300 bg-gray-100 px-4 py-2 text-sm font-medium text-gray-400">Previous</span>';
    }

    if ($current_page < $total_pages) {
        $next_page = $current_page + 1;
        $pagination_html .= '<a href="?' . http_build_query(array_merge($_GET, [$category . '_page' => $next_page])) . '" class="relative ml-3 inline-flex items-center rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50">Next</a>';
    } else {
        $pagination_html .= '<span class="relative ml-3 inline-flex items-center rounded-md border border-gray-300 bg-gray-100 px-4 py-2 text-sm font-medium text-gray-400">Next</span>';
    }

    $pagination_html .= '</div>';

    // Desktop pagination
    $pagination_html .= '<div class="hidden sm:flex sm:flex-1 sm:items-center sm:justify-between">';
    $pagination_html .= '<div><p class="text-sm text-gray-700">Showing page <span class="font-medium">' . $current_page . '</span> of <span class="font-medium">' . $total_pages . '</span></p></div>';
    $pagination_html .= '<div><nav class="isolate inline-flex -space-x-px rounded-md shadow-sm" aria-label="Pagination">';

    // Previous button
    if ($current_page > 1) {
        $prev_page = $current_page - 1;
        $pagination_html .= '<a href="?' . http_build_query(array_merge($_GET, [$category . '_page' => $prev_page])) . '" class="relative inline-flex items-center rounded-l-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0"><i class="fas fa-chevron-left"></i></a>';
    } else {
        $pagination_html .= '<span class="relative inline-flex items-center rounded-l-md px-2 py-2 text-gray-300 ring-1 ring-inset ring-gray-300"><i class="fas fa-chevron-left"></i></span>';
    }

    // Page numbers
    $start = max(1, $current_page - 2);
    $end = min($total_pages, $current_page + 2);

    if ($start > 1) {
        $pagination_html .= '<a href="?' . http_build_query(array_merge($_GET, [$category . '_page' => 1])) . '" class="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-900 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0">1</a>';
        if ($start > 2) {
            $pagination_html .= '<span class="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-700 ring-1 ring-inset ring-gray-300 focus:outline-offset-0">...</span>';
        }
    }

    for ($i = $start; $i <= $end; $i++) {
        if ($i == $current_page) {
            $pagination_html .= '<span class="relative z-10 inline-flex items-center bg-blue-600 px-4 py-2 text-sm font-semibold text-white focus:z-20 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600">' . $i . '</span>';
        } else {
            $pagination_html .= '<a href="?' . http_build_query(array_merge($_GET, [$category . '_page' => $i])) . '" class="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-900 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0">' . $i . '</a>';
        }
    }

    if ($end < $total_pages) {
        if ($end < $total_pages - 1) {
            $pagination_html .= '<span class="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-700 ring-1 ring-inset ring-gray-300 focus:outline-offset-0">...</span>';
        }
        $pagination_html .= '<a href="?' . http_build_query(array_merge($_GET, [$category . '_page' => $total_pages])) . '" class="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-900 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0">' . $total_pages . '</a>';
    }

    // Next button
    if ($current_page < $total_pages) {
        $next_page = $current_page + 1;
        $pagination_html .= '<a href="?' . http_build_query(array_merge($_GET, [$category . '_page' => $next_page])) . '" class="relative inline-flex items-center rounded-r-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0"><i class="fas fa-chevron-right"></i></a>';
    } else {
        $pagination_html .= '<span class="relative inline-flex items-center rounded-r-md px-2 py-2 text-gray-300 ring-1 ring-inset ring-gray-300"><i class="fas fa-chevron-right"></i></span>';
    }

    $pagination_html .= '</nav></div></div></div>';

    return $pagination_html;
}



$page_title = "Track County Development Projects";
$page_description = "Track county development projects and stay informed about ongoing and completed projects in your area";
$show_nav = true;
include 'includes/header.php';
?>
<!-- Leaflet CSS -->
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin=""/>

<!-- Leaflet JS -->
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" crossorigin=""></script>

<!-- Animated Background -->
<div class="animated-bg"></div>

<!-- Modern Hero Section -->
<section class="hero-modern">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="hero-content">
            <h1 class="hero-title text-white">
                Transform Communities
                <br>
                Track Progress
            </h1>
            <p class="hero-subtitle text-white">
                Discover, monitor, and engage with county development projects 
                that are shaping the future of Migori County
            </p>

            <!-- Modern Search Bar -->
            <div class="search-modern">
                <form method="GET" action="index" class="relative">
                    <?php if (!empty($view_mode) && $view_mode !== 'grid'): ?>
                        <input type="hidden" name="view" value="<?php echo htmlspecialchars($view_mode); ?>">
                    <?php endif; ?>
                    <?php if (!empty($status_filter)): ?>
                        <input type="hidden" name="status" value="<?php echo htmlspecialchars($status_filter); ?>">
                    <?php endif; ?>

                    <i class="fas fa-search search-icon"></i>
                    <input type="text" name="search" value="<?php echo htmlspecialchars($search_query); ?>" 
                           placeholder="Search projects by name, location, or department..." 
                           class="search-input">
                    <button type="submit" class="search-btn">
                        <i class="fas fa-search mr-2"></i>
                        Search
                    </button>
                </form>
            </div>
        </div>
    </div>
</section>

<!-- Filters and View Controls -->
<section class="py-2 relative z-10">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="filter-section-modern">
            <div class="filter-grid-modern">
                <!-- View Toggle -->
                <div class="view-toggle-modern">
                    <button id="gridView" onclick="switchView('grid')" class="view-btn-modern active">
                        <i class="fas fa-th-large"></i>
                        <span>Grid</span>
                    </button>
                    <button id="listView" onclick="switchView('list')" class="view-btn-modern">
                        <i class="fas fa-list"></i>
                        <span>List</span>
                    </button>
                    <button id="mapView" onclick="switchView('map')" class="view-btn-modern">
                        <i class="fas fa-map"></i>
                        <span>Map</span>
                    </button>
                </div>
            </div>
        </div>
    </div>
</section>

<main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pb-4 relative z-10">
    <!-- Categorized Projects Grid View -->
    <section id="gridContainer">
        <!-- Ongoing Projects Section -->
        <?php if (!empty($ongoing_projects)): ?>
        <div class="mb-4 fade-in-up">
            <div class="category-header-modern">
                <div class="category-title-modern">
                    Active Projects
                </div>
            </div>
            <div class="grid-modern">
                <?php foreach ($ongoing_projects as $index => $project): ?>
                    <div class="project-card-modern fade-in-up" style="--stagger-delay: <?php echo $index * 0.1; ?>s">
                        <!-- Map Preview -->
                        <?php if (!empty($project['location_coordinates'])): ?>
                            <div class="h-32 bg-gray-200 relative cursor-pointer" onclick="window.location.href='<?php echo BASE_URL; ?>projectDetails/<?php echo $project['id']; ?>'">
                                <div id="map-preview-<?php echo $project['id']; ?>" class="w-full h-full"></div>
                                <div class="absolute top-2 right-2 bg-black bg-opacity-50 text-white px-2 py-1 rounded text-xs">
                                    <i class="fas fa-map-marker-alt mr-1"></i>
                                    Location
                                </div>
                            </div>
                        <?php else: ?>
                            <div class="h-32 bg-gray-200 flex items-center justify-center cursor-pointer" onclick="window.location.href='<?php echo BASE_URL; ?>projectDetails/<?php echo $project['id']; ?>'">
                                <div class="text-center text-gray-500">
                                    <i class="fas fa-map-marker-alt text-2xl mb-2"></i>
                                    <p class="text-sm">No location data</p>
                                </div>
                            </div>
                        <?php endif; ?>

                        <div class="p-6">
                            <div class="project-header">
                                <div>
                                    <h3 class="project-title"><?php echo htmlspecialchars($project['project_name']); ?></h3>
                                    <div class="project-location">
                                        <i class="fas fa-map-marker-alt"></i>
                                        <?php echo htmlspecialchars($project['ward_name'] . ', ' . $project['sub_county_name']); ?>
                                    </div>
                                </div>
                                <span class="status-badge-modern status-ongoing">
                                    Ongoing
                                </span>
                            </div>

                            <!-- Actions -->
                            <div class="flex gap-2 mt-4">
                                <a href="<?php echo generate_project_url($project['id'], $project['project_name']); ?>" 
                                   class="text-blue-600 hover:text-blue-800 font-medium text-sm transition-colors duration-200 flex items-center justify-center flex-1 px-4 py-2 border border-blue-200 rounded-lg hover:bg-blue-50">
                                    <i class="fas fa-eye mr-2"></i>
                                    View Details
                                </a>
                                <a href="#" onclick="openFeedbackModal(<?php echo $project['id']; ?>); return false;" 
                                   class="btn-modern btn-secondary-modern">
                                    <i class="fas fa-comment"></i>
                                </a>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>

            <!-- Ongoing Projects Pagination -->
            <?php if ($total_ongoing_pages > 1): ?>
                <div class="glass-card mt-4">
                    <?php echo render_pagination($ongoing_page, $total_ongoing_pages, 'ongoing', $search_query); ?>
                </div>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <!-- Completed Projects Section -->
        <?php if (!empty($completed_projects)): ?>
        <div class="mb-4 fade-in-up">
            <div class="category-header-modern">
                <div class="category-title-modern">
                    Completed Projects
                </div>
            </div>
            <div class="grid-modern">
                <?php foreach ($completed_projects as $index => $project): ?>
                    <div class="project-card-modern fade-in-up" style="--stagger-delay: <?php echo $index * 0.1; ?>s">
                        <!-- Map Preview -->
                        <?php if (!empty($project['location_coordinates'])): ?>
                            <div class="h-32 bg-gray-200 relative cursor-pointer" onclick="window.location.href='<?php echo BASE_URL; ?>projectDetails/<?php echo $project['id']; ?>'">
                                <div id="map-preview-<?php echo $project['id']; ?>" class="w-full h-full"></div>
                                <div class="absolute top-2 right-2 bg-black bg-opacity-50 text-white px-2 py-1 rounded text-xs">
                                    <i class="fas fa-map-marker-alt mr-1"></i>
                                    Location
                                </div>
                            </div>
                        <?php else: ?>
                            <div class="h-32 bg-gray-200 flex items-center justify-center cursor-pointer" onclick="window.location.href='<?php echo BASE_URL; ?>projectDetails/<?php echo $project['id']; ?>'">
                                <div class="text-center text-gray-500">
                                    <i class="fas fa-map-marker-alt text-2xl mb-2"></i>
                                    <p class="text-sm">No location data</p>
                                </div>
                            </div>
                        <?php endif; ?>

                        <div class="p-6">
                            <div class="project-header">
                                <div>
                                    <h3 class="project-title"><?php echo htmlspecialchars($project['project_name']); ?></h3>
                                    <div class="project-location">
                                        <i class="fas fa-map-marker-alt"></i>
                                        <?php echo htmlspecialchars($project['ward_name'] . ', ' . $project['sub_county_name']); ?>
                                    </div>
                                </div>
                                <span class="status-badge-modern status-completed">
                                    Completed
                                </span>
                            </div>

                            <!-- Actions -->
                            <div class="flex gap-2 mt-4">
                                <a href="<?php echo generate_project_url($project['id'], $project['project_name']); ?>" 
                                   class="text-blue-600 hover:text-blue-800 font-medium text-sm transition-colors duration-200 flex items-center justify-center flex-1 px-4 py-2 border border-blue-200 rounded-lg hover:bg-blue-50">
                                    <i class="fas fa-eye mr-2"></i>
                                    View Details
                                </a>
                                <a href="#" onclick="openFeedbackModal(<?php echo $project['id']; ?>); return false;" 
                                   class="btn-modern btn-secondary-modern">
                                    <i class="fas fa-comment"></i>
                                </a>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>

            <!-- Completed Projects Pagination -->
            <?php if ($total_completed_pages > 1): ?>
                <div class="glass-card mt-4">
                    <?php echo render_pagination($completed_page, $total_completed_pages, 'completed', $search_query); ?>
                </div>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <!-- Planning Projects Section -->
        <?php if (!empty($planning_projects)): ?>
        <div class="mb-4 fade-in-up">
            <div class="category-header-modern">
                <div class="category-title-modern">
                    Planning Projects
                </div>
            </div>
            <div class="grid-modern">
                <?php foreach ($planning_projects as $index => $project): ?>
                    <div class="project-card-modern fade-in-up" style="--stagger-delay: <?php echo $index * 0.1; ?>s">
                        <!-- Map Preview -->
                        <?php if (!empty($project['location_coordinates'])): ?>
                            <div class="h-32 bg-gray-200 relative cursor-pointer" onclick="window.location.href='<?php echo BASE_URL; ?>projectDetails/<?php echo $project['id']; ?>'">
                                <div id="map-preview-<?php echo $project['id']; ?>" class="w-full h-full"></div>
                                <div class="absolute top-2 right-2 bg-black bg-opacity-50 text-white px-2 py-1 rounded text-xs">
                                    <i class="fas fa-map-marker-alt mr-1"></i>
                                    Location
                                </div>
                            </div>
                        <?php else: ?>
                            <div class="h-32 bg-gray-200 flex items-center justify-center cursor-pointer" onclick="window.location.href='<?php echo BASE_URL; ?>projectDetails/<?php echo $project['id']; ?>'">
                                <div class="text-center text-gray-500">
                                    <i class="fas fa-map-marker-alt text-2xl mb-2"></i>
                                    <p class="text-sm">No location data</p>
                                </div>
                            </div>
                        <?php endif; ?>

                        <div class="p-6">
                            <div class="project-header">
                                <div>
                                    <h3 class="project-title"><?php echo htmlspecialchars($project['project_name']); ?></h3>
                                    <div class="project-location">
                                        <i class="fas fa-map-marker-alt"></i>
                                        <?php echo htmlspecialchars($project['ward_name'] . ', ' . $project['sub_county_name']); ?>
                                    </div>
                                </div>
                                <span class="status-badge-modern status-planning">
                                    Planning
                                </span>
                            </div>

                            <!-- Actions -->
                            <div class="flex gap-2 mt-4">
                                <a href="<?php echo generate_project_url($project['id'], $project['project_name']); ?>" 
                                   class="text-blue-600 hover:text-blue-800 font-medium text-sm transition-colors duration-200 flex items-center justify-center flex-1 px-4 py-2 border border-blue-200 rounded-lg hover:bg-blue-50">
                                    <i class="fas fa-eye mr-2"></i>
                                    View Details
                                </a>
                                <a href="#" onclick="openFeedbackModal(<?php echo $project['id']; ?>); return false;" 
                                   class="btn-modern btn-secondary-modern">
                                    <i class="fas fa-comment"></i>
                                </a>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>

            <!-- Planning Projects Pagination -->
            <?php if ($total_planning_pages > 1): ?>
                <div class="glass-card mt-4">
                    <?php echo render_pagination($planning_page, $total_planning_pages, 'planning', $search_query); ?>
                </div>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <!-- No Projects Found -->
        <?php if (empty($all_projects)): ?>
        <div class="glass-card text-center py-16">
            <div class="text-gray-500">
                <i class="fas fa-search text-6xl mb-6 opacity-50"></i>
                <?php if (!empty($search_query)): ?>
                    <h3 class="text-2xl font-medium mb-4 text-gray-900">No projects found</h3>
                    <p class="text-lg mb-6 text-gray-600">
                        No projects match your search for "<span class="font-medium"><?php echo htmlspecialchars($search_query); ?></span>"
                    </p>
                    <a href="<?php echo BASE_URL; ?>" class="btn-modern btn-primary-modern">
                        <i class="fas fa-arrow-left"></i>
                        View All Projects
                    </a>
                <?php else: ?>
                    <h3 class="text-2xl font-medium mb-4 text-gray-900">No projects available</h3>
                    <p class="text-lg text-gray-600">There are currently no published projects to display.</p>
                <?php endif; ?>
            </div>
        </div>
        <?php endif; ?>
    </section>

    <!-- List View (Hidden by default) -->
    <section id="listContainer" class="hidden">
        <!-- Ongoing Projects List -->
        <?php if (!empty($ongoing_projects)): ?>
        <div class="mb-6">
            <div class="category-header-modern">
                <div class="category-title-modern" style="color: #000000 !important;">
                    Active Projects
                </div>
            </div>
            <div class="space-y-3">
                <?php foreach ($ongoing_projects as $project): ?>
                    <div class="bg-white rounded-lg p-4 border border-gray-200 hover:shadow-md transition-shadow cursor-pointer" onclick="window.location.href='<?php echo BASE_URL; ?>projectDetails/<?php echo $project['id']; ?>'">
                        <div class="space-y-2">
                            <!-- Title and Location Only -->
                            <div>
                                <h3 class="text-lg font-semibold mb-1 hover:text-blue-600 transition-colors" style="color: #000000 !important; line-height: 1.3; word-wrap: break-word; overflow-wrap: break-word; white-space: normal;">
                                    <?php echo htmlspecialchars($project['project_name']); ?>
                                </h3>
                                <p class="text-sm text-gray-600 flex items-center">
                                    <i class="fas fa-map-marker-alt mr-1 text-red-400"></i>
                                    <?php echo htmlspecialchars($project['ward_name'] . ', ' . $project['sub_county_name']); ?>
                                </p>
                            </div>

                            <!-- Description -->
                            <?php if (!empty($project['description'])): ?>
                            <div>
                                <p class="text-sm text-gray-600" style="display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;">
                                    <?php echo htmlspecialchars($project['description']); ?>
                                </p>
                            </div>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>

            <!-- Ongoing Projects Pagination -->
            <?php if ($total_ongoing_pages > 1): ?>
                <div class="mt-4 p-4 bg-white border border-gray-200 rounded-lg" style="display: block !important; visibility: visible !important; opacity: 1 !important; z-index: 1000 !important;">
                    <?php echo render_pagination($ongoing_page, $total_ongoing_pages, 'ongoing', $search_query); ?>
                </div>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <!-- Completed Projects List -->
        <?php if (!empty($completed_projects)): ?>
        <div class="mb-6">
            <div class="category-header-modern">
                <div class="category-title-modern" style="color: #000000 !important;">
                    Completed Projects
                </div>
            </div>
            <div class="space-y-3">
                <?php foreach ($completed_projects as $project): ?>
                    <div class="bg-white rounded-lg p-4 border border-gray-200 hover:shadow-md transition-shadow cursor-pointer" onclick="window.location.href='<?php echo BASE_URL; ?>projectDetails/<?php echo $project['id']; ?>'">
                        <div class="space-y-2">
                            <!-- Title and Location Only -->
                            <div>
                                <h3 class="text-lg font-semibold mb-1 hover:text-blue-600 transition-colors" style="color: #000000 !important; line-height: 1.3; word-wrap: break-word; overflow-wrap: break-word; white-space: normal;">
                                    <?php echo htmlspecialchars($project['project_name']); ?>
                                </h3>
                                <p class="text-sm text-gray-600 flex items-center">
                                    <i class="fas fa-map-marker-alt mr-1 text-red-400"></i>
                                    <?php echo htmlspecialchars($project['ward_name'] . ', ' . $project['sub_county_name']); ?>
                                </p>
                            </div>

                            <!-- Description -->
                            <?php if (!empty($project['description'])): ?>
                            <div>
                                <p class="text-sm text-gray-600 style="display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;">
                                    <?php echo htmlspecialchars($project['description']); ?>Final Answer:                                </p>
                            </div>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>

            <!-- Completed Projects Pagination -->
            <?php if ($total_completed_pages > 1): ?>
                <div class="mt-4 p-4 bg-white border border-gray-200 rounded-lg" style="display: block !important; visibility: visible !important; opacity: 1 !important; z-index: 1000 !important;">
                    <?php echo render_pagination($completed_page, $total_completed_pages, 'completed', $search_query); ?>
                </div>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <!-- Planning Projects List -->
        <?php if (!empty($planning_projects)): ?>
        <div class="mb-6">
            <div class="category-header-modern">
                <div class="category-title-modern" style="color: #000000 !important;">
                    Planning Projects
                </div>
            </div>
            <div class="space-y-3">
                <?php foreach ($planning_projects as $project): ?>
                    <div class="bg-white rounded-lg p-4 border border-gray-200 hover:shadow-md transition-shadow cursor-pointer" onclick="window.location.href='<?php echo BASE_URL; ?>projectDetails/<?php echo $project['id']; ?>'">
                        <div class="space-y-2">
                            <!-- Title and Location Only -->
                            <div>
                                <h3 class="text-lg font-semibold mb-1 hover:text-blue-600 transition-colors" style="color: #000000 !important; line-height: 1.3; word-wrap: break-word; overflow-wrap: break-word; white-space: normal;">
                                    <?php echo htmlspecialchars($project['project_name']); ?>
                                </h3>                                <p class="text-sm text-gray-600 flex items-center">
                                    <i class="fas fa-map-marker-alt mr-1 text-red-400"></i>
                                    <?php echo htmlspecialchars($project['ward_name'] . ', ' . $project['sub_county_name']); ?>
                                </p>
                            </div>

                            <!-- Description -->
                            <?php if (!empty($project['description'])): ?>
                            <div>
                                <p class="text-sm text-gray-600" style="display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;">
                                    <?php echo htmlspecialchars($project['description']); ?>
                                </p>
                            </div>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>

            <!-- Planning Projects Pagination -->
            <?php if ($total_planning_pages > 1): ?>
                <div class="mt-4 p-4 bg-white border border-gray-200 rounded-lg" style="display: block !important; visibility: visible !important; opacity: 1 !important; z-index: 1000 !important;">
                    <?php echo render_pagination($planning_page, $total_planning_pages, 'planning', $search_query); ?>
                </div>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <!-- No Projects Found -->
        <?php if (empty($all_projects)): ?>
        <div class="glass-card text-center py-16">
            <div class="text-gray-500">
                <i class="fas fa-search text-6xl mb-6 opacity-50"></i>
                <?php if (!empty($search_query)): ?>
                    <h3 class="text-2xl font-medium mb-4 text-gray-900">No projects found</h3>
                    <p class="text-lg mb-6 text-gray-600">
                        No projects match your search for "<span class="font-medium"><?php echo htmlspecialchars($search_query); ?></span>"
                    </p>
                    <a href="<?php echo BASE_URL; ?>" class="btn-modern btn-primary-modern">
                        <i class="fas fa-arrow-left"></i>
                        View All Projects
                    </a>
                <?php else: ?>
                    <h3 class="text-2xl font-medium mb-4 text-gray-900">No projects available</h3>
                    <p class="text-lg text-gray-600">There are currently no published projects to display.</p>
                <?php endif; ?>
            </div>
        </div>
        <?php endif; ?>
    </section>

    <!-- Map View (Hidden by default) -->

        <div id="mapContainer" class="hidden">
            <div class="map-view-container">
                <div class="mb-4">
                    <h2 class="text-2xl font-bold text-gray-900 mb-2">Project Locations</h2>
                </div>
                <div id="mainMapView"></div>
                <div id="mapProjectsList" class="hidden">
                    <!-- Hidden project list -->
                </div>
            </div>
        </div>
</main>

<!-- Scroll Progress Indicator -->
<div class="scroll-indicator"></div>

<!-- Feedback Modal -->
<div id="feedbackModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-[9999] backdrop-blur-sm">
    <div class="flex items-center justify-center min-h-screen p-4">
        <div class="glass-card max-w-2xl w-full">
            <form id="feedbackForm" action="api/feedback.php" method="POST">
                <input type="hidden" name="project_id" id="feedbackProjectId" value="">
                <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">

                <div class="flex items-center justify-between p-6 border-b border-gray-200">
                    <h3 class="text-xl font-semibold text-gray-900">Share Your Feedback</h3>
                    <button type="button" onclick="closeFeedbackModal()" class="text-gray-400 hover:text-gray-600 transition-colors">
                        <i class="fas fa-times text-xl"></i>
                    </button>
                </div>

                <div class="p-6 space-y-4">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label for="feedback_name" class="block text-sm font-medium text-gray-700 mb-2">
                                Your Name
                            </label>
                            <input type="text" id="feedback_name" name="name" 
                                   class="w-full px-4 py-3 border border-gray-300 rounded-lg bg-white text-gray-900 focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all">
                        </div>
                        <div>
                            <label for="feedback_email" class="block text-sm font-medium text-gray-700 mb-2">
                                Email (Optional)
                            </label>
                            <input type="email" id="feedback_email" name="email" 
                                   class="w-full px-4 py-3 border border-gray-300 rounded-lg bg-white text-gray-900 focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all">
                        </div>
                    </div>

                    <div>
                        <label for="feedback_message" class="block text-sm font-medium text-gray-700 mb-2">
                            Feedback <span class="text-red-500">*</span>
                        </label>
                        <textarea id="feedback_message" name="message" rows="4" required
                                  class="w-full px-4 py-3 border border-gray-300 rounded-lg bg-white text-gray-900 focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                                  placeholder="Share your thoughts about this project..."></textarea>
                    </div>
                </div>

                <div class="flex items-center justify-end space-x-3 p-6 border-t border-gray-200">
                    <button type="button" onclick="closeFeedbackModal()" 
                            class="btn-modern btn-secondary-modern">
                        Cancel
                    </button>
                    <button type="submit" 
                            class="btn-modern btn-primary-modern">
                        <i class="fas fa-paper-plane"></i>
                        Submit Feedback
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Scroll to Top Button -->
<button id="scrollToTop" class="fixed bottom-6 right-6 bg-blue-600 text-white p-3 rounded-full shadow-lg hover:bg-blue-700 transition-all z-50 opacity-0 invisible transform translate-y-4">
    <i class="fas fa-arrow-up"></i>
</button>

<!-- Feedback Modal -->
<div id="feedbackModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 hidden">
    <div class="bg-white rounded-lg p-6 w-full max-w-md mx-4">
        <div class="flex justify-between items-center mb-4">
            <h3 id="feedbackModalTitle" class="text-lg font-semibold text-gray-900">Leave Feedback</h3>
            <button type="button" onclick="closeFeedbackModal()" class="text-gray-400 hover:text-gray-600">
                <i class="fas fa-times"></i>
            </button>
        </div>
        
        <form id="feedbackForm" class="space-y-4">
            <input type="hidden" id="projectId" name="project_id" value="">
            <input type="hidden" id="parentCommentId" name="parent_comment_id" value="">
            
            <div>
                <label for="citizenName" class="block text-sm font-medium text-gray-700 mb-1">Name *</label>
                <input type="text" id="citizenName" name="citizen_name" required 
                       class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>
            
            <div>
                <label for="citizenEmail" class="block text-sm font-medium text-gray-700 mb-1">Email (optional)</label>
                <input type="email" id="citizenEmail" name="citizen_email"
                       class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>
            
            <div>
                <label for="feedbackMessage" class="block text-sm font-medium text-gray-700 mb-1">Message *</label>
                <textarea id="feedbackMessage" name="message" required rows="4"
                          class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                          placeholder="Share your thoughts about this project..."></textarea>
            </div>
            
            <div class="flex justify-end space-x-3">
                <button type="button" onclick="closeFeedbackModal()" 
                        class="px-4 py-2 text-gray-600 hover:text-gray-800">
                    Cancel
                </button>
                <button type="submit" id="submitFeedbackBtn"
                        class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500">
                    Submit Feedback
                </button>
            </div>
        </form>
    </div>
</div>

<?php include 'includes/footer.php'; ?>