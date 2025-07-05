<!-- Project Card -->
<div class="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden hover:shadow-lg transition-shadow">
    <!-- Map Preview -->
    <?php if (!empty($project['location_coordinates'])): ?>
        <div class="h-32 bg-gray-200 relative cursor-pointer" onclick="window.location.href='projectDetails.php?id=<?php echo $project['id']; ?>'">
            <div id="map-preview-<?php echo $project['id']; ?>" class="w-full h-full"></div>
            <div class="absolute top-2 right-2 bg-black bg-opacity-50 text-white px-2 py-1 rounded text-xs">
                <i class="fas fa-map-marker-alt mr-1"></i>
                Location
            </div>
        </div>
    <?php else: ?>
        <div class="h-32 bg-gray-200 flex items-center justify-center cursor-pointer" onclick="window.location.href='projectDetails.php?id=<?php echo $project['id']; ?>'">
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
                <a href="projectDetails.php?id=<?php echo $project['id']; ?>" class="block hover:text-blue-600 transition-colors">
                    <h3 class="text-lg font-semibold text-gray-900 mb-2">
                        <?php echo htmlspecialchars($project['project_name']); ?>
                    </h3>
                </a>
                <div class="flex items-center space-x-4 text-sm text-gray-600">
                    <span class="flex items-center">
                        <i class="fas fa-building mr-1"></i>
                        <?php echo htmlspecialchars($project['department_name']); ?>
                    </span>
                    <span class="flex items-center">
                        <i class="fas fa-map-marker-alt mr-1"></i>
                        <?php echo htmlspecialchars($project['sub_county_name']); ?>
                    </span>
                    <span class="flex items-center">
                        <i class="fas fa-calendar mr-1"></i>
                        <?php echo $project['project_year']; ?>
                    </span>
                </div>
            </div>
            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?php echo get_status_badge_class($project['status']); ?>">
                <?php echo ucfirst($project['status']); ?>
            </span>
        </div>



        <!-- Project Rating -->
        <div class="mb-4">
            <div class="flex justify-between items-center">
                <span class="text-sm font-medium text-gray-700">Rating</span>
                <?php echo generate_star_rating($project['average_rating'], $project['total_ratings']); ?>
            </div>
        </div>

        <!-- Project Details -->
        <div class="grid grid-cols-1 gap-4 text-sm mb-4">
            <div>
                <span class="text-gray-600">Location:</span>
                <p class="font-semibold text-gray-900"><?php echo htmlspecialchars($project['ward_name']); ?></p>
            </div>
        </div>

        <!-- Action Buttons -->
        <div class="pt-4 border-t border-gray-200">
            <div class="flex space-x-2">
                <a href="projectDetails.php?id=<?php echo $project['id']; ?>" 
                   class="flex-1 inline-flex items-center justify-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 transition-colors">
                    <i class="fas fa-eye mr-2"></i>
                    View Details
                </a>
                <button onclick="openFeedbackModal(<?php echo $project['id']; ?>)" 
                        class="px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 transition-colors">
                    <i class="fas fa-comment"></i>
                </button>
            </div>
        </div>
    </div>
</div>
<!-- Project List Item -  -->
<div class="bg-white rounded-lg p-4 border border-gray-200 hover:shadow-md transition-shadow cursor-pointer" onclick="window.location.href='projectDetails.php?id=<?php echo $project['id']; ?>'">
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