<?php
// Function to generate clean project URLs
function generate_project_url($project_id, $project_name) {
    $slug = strtolower(trim(preg_replace('/[^A-Za-z0-9-]+/', '-', $project_name)));
    return "projectDetails/{$project_id}/{$slug}/";
}

// Function to get the status badge class
function get_status_badge_class($status) {
    switch ($status) {
        case 'complete':
            return 'bg-green-100 text-green-800';
        case 'in progress':
            return 'bg-blue-100 text-blue-800';
        case 'pending':
            return 'bg-yellow-100 text-yellow-800';
        case 'cancelled':
            return 'bg-red-100 text-red-800';
        default:
            return 'bg-gray-100 text-gray-800';
    }
}

// Function to generate star rating
function generate_star_rating($average_rating, $total_ratings) {
    $stars = '';
    for ($i = 1; $i <= 5; $i++) {
        if ($i <= $average_rating) {
            $stars .= '<i class="fas fa-star text-yellow-400"></i>';
        } else if ($i == ceil($average_rating) && ($average_rating - floor($average_rating) > 0)) {
            $stars .= '<i class="fas fa-star-half-alt text-yellow-400"></i>';
        } else {
            $stars .= '<i class="far fa-star text-gray-400"></i>';
        }
    }
    return '<div class="flex items-center">' . $stars . '<span class="ml-2 text-gray-500">(' . $total_ratings . ')</span></div>';
}

?>
<!-- Project Card -->
<div class="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden hover:shadow-lg transition-shadow relative group">
    <!-- Hover Tooltip -->
    <div class="absolute top-2 left-2 bg-blue-600 text-white px-3 py-2 rounded-lg shadow-lg opacity-0 group-hover:opacity-100 transition-opacity duration-300 z-20 pointer-events-none">
        <div class="text-xs font-semibold mb-1">Completion Rate</div>
        <div class="text-lg font-bold"><?php echo $project['progress_percentage'] ?? 0; ?>%</div>
        <div class="text-xs mt-1">Department: <?php echo htmlspecialchars($project['department_name']); ?></div>
    </div>

    <!-- Map Preview -->
    <?php if (!empty($project['location_coordinates'])): ?>
        <div class="h-32 bg-gray-200 relative cursor-pointer" onclick="window.location.href='<?php echo generate_project_url($project['id'], $project['project_name']); ?>'">
            <div id="map-preview-<?php echo $project['id']; ?>" class="w-full h-full"></div>
            <div class="absolute top-2 right-2 bg-black bg-opacity-50 text-white px-2 py-1 rounded text-xs">
                <i class="fas fa-map-marker-alt mr-1"></i>
                Location
            </div>
        </div>
    <?php else: ?>
        <div class="h-32 bg-gray-200 flex items-center justify-center cursor-pointer" onclick="window.location.href='<?php echo generate_project_url($project['id'], $project['project_name']); ?>'">
            <div class="text-center text-gray-500">
                <i class="fas fa-map-marker-alt text-2xl mb-2"></i>
                <p class="text-sm">No location data</p>
            </div>
        </div>
    <?php endif; ?>

    <div class="p-6">
        <!-- Project Header -->
        <div class="flex items-start justify-between mb-4">
            <div class="flex-1">
                <a href="<?php echo generate_project_url($project['id'], $project['project_name']); ?>" class="block hover:text-blue-600 transition-colors">
                    <h3 class="text-lg font-semibold text-gray-900 mb-2 project-title">
                        <?php echo htmlspecialchars($project['project_name']); ?>
                    </h3>
                </a>
            </div>
        </div>

        <!-- Project Information -->
        <div class="space-y-3 mb-4">
            <div class="flex items-center text-sm text-gray-600 project-location">
                <i class="fas fa-map-marker-alt mr-2 text-red-500"></i>
                <?php echo htmlspecialchars($project['ward_name'] . ', ' . $project['sub_county_name']); ?>
            </div>
            <div class="flex items-center text-sm text-gray-600">
                <i class="fas fa-building mr-2 text-blue-500"></i>
                <?php echo htmlspecialchars($project['department_name']); ?>
            </div>
        </div>

        <!-- Progress Bar -->
        <div class="mb-4">
            <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-medium text-gray-700">Progress</span>
                <span class="text-sm text-gray-600"><?php echo $project['progress_percentage']; ?>%</span>
            </div>
            <div class="w-full bg-gray-200 rounded-full h-2">
                <div class="bg-blue-600 h-2 rounded-full" style="width: <?php echo $project['progress_percentage']; ?>%"></div>
            </div>
        </div>

        <!-- Action Buttons -->
        <div class="flex gap-2">
            <a href="<?php echo generate_project_url($project['id'], $project['project_name']); ?>" 
               class="flex-1 bg-blue-600 text-white text-center py-2 px-4 rounded-lg hover:bg-blue-700 transition-colors text-sm font-medium">
                <i class="fas fa-eye mr-1"></i>View Details
            </a>
            <button onclick="if(window.showFeedbackForm) window.showFeedbackForm(<?php echo $project['id']; ?>);" 
                    class="bg-green-600 text-white py-2 px-3 rounded-lg hover:bg-green-700 transition-colors">
                <i class="fas fa-comment"></i>
            </button>
        </div>
    </div>
</div>
<!-- Project List Item -  -->
<div class="bg-white rounded-lg p-4 border border-gray-200 hover:shadow-md transition-shadow cursor-pointer" onclick="window.location.href='<?php echo generate_project_url($project['id'], $project['project_name']); ?>'">
    <!-- Main Content -->
    <div class="space-y-3">
        <!-- Title and Location -->
        <div>
            <h3 class="text-lg font-semibold text-gray-900 mb-1 line-clamp-2 hover:text-blue-600 transition-colors">
                <?php echo htmlspecialchars($project['project_name']); ?>
            </h3>
            <p class="text-sm text-gray-600 flex items-center">
                <i class="fas fa-map-marker-alt mr-1 text-red-400"></i>
                <?php echo htmlspecialchars($project['ward_name'] . ', ' . $project['sub_county_name']); ?>
            </p>
        </div>

        <!-- Description -->
        <div>
            <p class="text-sm text-gray-600 line-clamp-2">
                <?php echo htmlspecialchars($project['description']); ?>
            </p>
        </div>

        <!-- Status and Additional Info (Hidden on mobile) -->
        <div class="hidden md:flex items-center justify-between pt-2 border-t border-gray-100">
            <div class="flex items-center gap-4 text-xs text-gray-500">
                <span class="flex items-center">
                    <i class="fas fa-building mr-1"></i>
                    <?php echo htmlspecialchars($project['department_name']); ?>
                </span>
                <span class="flex items-center">
                    <i class="fas fa-calendar mr-1"></i>
                    <?php echo $project['project_year']; ?>
                </span>
            </div>
            <div class="flex items-center gap-2">
                <span class="status-badge-modern <?php echo 'status-' . $project['status']; ?>">
                    <?php echo ucfirst($project['status']); ?>
                </span>
                <span class="text-xs text-gray-500 bg-gray-100 px-2 py-1 rounded">
                    <?php echo $project['progress_percentage']; ?>% complete
                </span>
            </div>
        </div>

        <!-- Mobile Status Only -->
        <div class="md:hidden flex justify-between items-center pt-2 border-t border-gray-100">
            <span class="status-badge-modern <?php echo 'status-' . $project['status']; ?>">
                <?php echo ucfirst($project['status']); ?>
            </span>
            <span class="text-xs text-gray-500">
                <?php echo $project['progress_percentage']; ?>% complete
            </span>
        </div>
    </div>
</div>