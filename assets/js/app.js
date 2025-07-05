// Combined JavaScript for County Project Tracking System
// Unified file to prevent duplicate declarations and conflicts

// Ensure BASE_URL is available
if (typeof window.BASE_URL === 'undefined') {
    // Fallback - will be overridden by PHP
    window.BASE_URL = '/';
}

// Theme Management (Public site only)
if (typeof window.PublicThemeManager === 'undefined') {
    window.PublicThemeManager = class PublicThemeManager {
        constructor() {
            this.init();
        }

        init() {
            // Check for saved theme preference or default to light mode
            const savedTheme = localStorage.getItem('theme');
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

            if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
                this.enableDarkMode();
            } else {
                this.enableLightMode();
            }

            // Theme toggle button
            const themeToggle = document.getElementById('theme-toggle');
            if (themeToggle) {
                themeToggle.addEventListener('click', () => this.toggleTheme());
            }
        }

        enableDarkMode() {
            document.documentElement.classList.add('dark');
            localStorage.setItem('theme', 'dark');
        }

        enableLightMode() {
            document.documentElement.classList.remove('dark');
            localStorage.setItem('theme', 'light');
        }

        toggleTheme() {
            if (document.documentElement.classList.contains('dark')) {
                this.enableLightMode();
            } else {
                this.enableDarkMode();
            }
        }
    };
}

// Utility Functions
if (typeof window.Utils === 'undefined') {
    window.Utils = class Utils {
        static showNotification(message, type = 'info', duration = 5000) {
            const notification = document.createElement('div');
            notification.className = `fixed top-4 right-4 z-50 p-4 rounded-lg shadow-lg max-w-sm transform transition-all duration-300 translate-x-full`;

            const typeClasses = {
                success: 'bg-green-100 border-green-500 text-green-800 border-l-4',
                error: 'bg-red-100 border-red-500 text-red-800 border-l-4',
                warning: 'bg-yellow-100 border-yellow-500 text-yellow-800 border-l-4',
                info: 'bg-blue-100 border-blue-500 text-blue-800 border-l-4'
            };

            notification.className += ` ${typeClasses[type] || typeClasses.info}`;

            notification.innerHTML = `
                <div class="flex items-center">
                    <div class="flex-1">
                        <p class="font-medium">${message}</p>
                    </div>
                    <button onclick="this.parentElement.parentElement.remove()" class="ml-3 text-gray-400 hover:text-gray-600">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `;

            document.body.appendChild(notification);

            // Animate in
            setTimeout(() => {
                notification.classList.remove('translate-x-full');
            }, 100);

            // Auto remove
            setTimeout(() => {
                notification.classList.add('translate-x-full');
                setTimeout(() => notification.remove(), 300);
            }, duration);
        }

        static formatCurrency(amount) {
            return new Intl.NumberFormat('en-KE', {
                style: 'currency',
                currency: 'KES',
                minimumFractionDigits: 0,
                maximumFractionDigits: 0
            }).format(amount);
        }

        static formatDate(dateString) {
            return new Date(dateString).toLocaleDateString('en-KE', {
                year: 'numeric',
                month: 'long',
                day: 'numeric'
            });
        }

        static debounce(func, wait) {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        }
    };
}

// Project Management
if (typeof window.ProjectManager === 'undefined') {
    window.ProjectManager = class ProjectManager {
        constructor() {
            this.currentProject = null;
        }

        async fetchProjectDetails(projectId) {
            try {
                const response = await fetch(`${window.BASE_URL}api/projects.php?id=${projectId}`);
                const data = await response.json();

                if (data.success) {
                    return data.project;
                } else {
                    throw new Error(data.message || 'Failed to fetch project details');
                }
            } catch (error) {
                console.error('Error fetching project details:', error);
                window.Utils.showNotification('Failed to load project details', 'error');
                return null;
            }
        }

        async showProjectDetails(projectId) {
            const project = await this.fetchProjectDetails(projectId);
            if (!project) return;

            this.currentProject = project;

            const detailsContainer = document.getElementById('projectDetails');
            if (detailsContainer) {
                detailsContainer.innerHTML = this.renderProjectDetails(project);
            }

            const modal = document.getElementById('projectModal');
            if (modal) {
                modal.classList.remove('hidden');
                document.body.style.overflow = 'hidden';
            }
        }

        renderProjectDetails(project) {
            const progressColor = this.getProgressColor(project.progress_percentage);
            const statusBadge = this.getStatusBadgeClass(project.status);

            return `
                <div class="space-y-6">
                    <div class="flex items-start justify-between">
                        <div>
                            <h3 class="text-xl font-bold text-gray-900 dark:text-white mb-2">
                                ${project.project_name}
                            </h3>
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${statusBadge}">
                                ${project.status.charAt(0).toUpperCase() + project.status.slice(1)}
                            </span>
                        </div>
                        <button onclick="window.projectManager.exportProjectPDF(${project.id})" 
                                class="inline-flex items-center px-3 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors">
                            <i class="fas fa-file-pdf mr-2"></i>
                            Export PDF
                        </button>
                    </div>

                    <div class="prose dark:prose-invert">
                        <p class="text-gray-600 dark:text-gray-300">${project.description || 'No description available'}</p>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div class="space-y-4">
                            <h4 class="font-semibold text-gray-900 dark:text-white">Project Information</h4>
                            <dl class="space-y-3">
                                <div>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Department</dt>
                                    <dd class="text-sm text-gray-900 dark:text-white">${project.department_name}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Location</dt>
                                    <dd class="text-sm text-gray-900 dark:text-white">${project.ward_name}, ${project.sub_county_name}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Year</dt>
                                    <dd class="text-sm text-gray-900 dark:text-white">${project.project_year}</dd>
                                </div>
                            </dl>
                        </div>

                        <div class="space-y-4">
                            <h4 class="font-semibold text-gray-900 dark:text-white">Timeline & Progress</h4>
                            <dl class="space-y-3">
                                ${project.start_date ? `
                                    <div>
                                        <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Start Date</dt>
                                        <dd class="text-sm text-gray-900 dark:text-white">${window.Utils.formatDate(project.start_date)}</dd>
                                    </div>
                                ` : ''}
                                ${project.expected_completion_date ? `
                                    <div>
                                        <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Expected Completion</dt>
                                        <dd class="text-sm text-gray-900 dark:text-white">${window.Utils.formatDate(project.expected_completion_date)}</dd>
                                    </div>
                                ` : ''}
                                ${project.actual_completion_date ? `
                                    <div>
                                        <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Actual Completion</dt>
                                        <dd class="text-sm text-gray-900 dark:text-white">${window.Utils.formatDate(project.actual_completion_date)}</dd>
                                    </div>
                                ` : ''}
                                <div>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Progress</dt>
                                    <dd class="mt-1">
                                        <div class="flex items-center">
                                            <div class="flex-1">
                                                <div class="w-full bg-gray-200 dark:bg-gray-600 rounded-full h-2">
                                                    <div class="h-2 rounded-full ${progressColor}" style="width: ${project.progress_percentage}%"></div>
                                                </div>
                                            </div>
                                            <span class="ml-3 text-sm text-gray-900 dark:text-white">${project.progress_percentage}%</span>
                                        </div>
                                    </dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Rating</dt>
                                    <dd class="mt-1">
                                        <div class="flex items-center space-x-1">
                                            ${this.generateStarRating(project.average_rating)}
                                            <span class="text-sm text-gray-600 dark:text-gray-400">${parseFloat(project.average_rating).toFixed(1)} (${project.total_ratings})</span>
                                        </div>
                                    </dd>
                                </div>
                            </dl>
                        </div>
                    </div>

                    ${project.contractor_name ? `
                        <div class="space-y-4">
                            <h4 class="font-semibold text-gray-900 dark:text-white">Contractor Information</h4>
                            <dl class="space-y-3">
                                <div>
                                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Contractor</dt>
                                    <dd class="text-sm text-gray-900 dark:text-white">${project.contractor_name}</dd>
                                </div>
                                ${project.contractor_contact ? `
                                    <div>
                                        <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Contact</dt>
                                        <dd class="text-sm text-gray-900 dark:text-white">${project.contractor_contact}</dd>
                                    </div>
                                ` : ''}
                            </dl>
                        </div>
                    ` : ''}

                    ${project.location_coordinates ? `
                        <div class="space-y-4">
                            <h4 class="font-semibold text-gray-900 dark:text-white">Location</h4>
                            <div id="projectDetailMap" class="h-48 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
                        </div>
                    ` : ''}
                </div>
            `;
        }

        getProgressColor(percentage) {
            if (percentage >= 80) return 'bg-green-500';
            if (percentage >= 60) return 'bg-blue-500';
            if (percentage >= 40) return 'bg-yellow-500';
            if (percentage >= 20) return 'bg-orange-500';
            return 'bg-red-500';
        }

        generateStarRating(rating) {
            const fullStars = Math.floor(rating);
            const halfStar = (rating - fullStars) >= 0.5;
            const emptyStars = 5 - fullStars - (halfStar ? 1 : 0);

            let stars = '';

            // Full stars
            for (let i = 0; i < fullStars; i++) {
                stars += '<i class="fas fa-star text-yellow-400"></i>';
            }

            // Half star
            if (halfStar) {
                stars += '<i class="fas fa-star-half-alt text-yellow-400"></i>';
            }

            // Empty stars
            for (let i = 0; i < emptyStars; i++) {
                stars += '<i class="far fa-star text-gray-300"></i>';
            }

            return `<div class="flex space-x-1">${stars}</div>`;
        }

        getStatusBadgeClass(status) {
            const classes = {
                planning: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300',
                ongoing: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300',
                completed: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300',
                suspended: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300',
                cancelled: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'
            };
            return classes[status] || 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300';
        }

        closeProjectDetails() {
            const modal = document.getElementById('projectModal');
            if (modal) {
                modal.classList.add('hidden');
                document.body.style.overflow = 'auto';
            }
        }

        async exportProjectPDF(projectId) {
            try {
                const response = await fetch(`${window.BASE_URL}api/export_pdf?project_id=${projectId}`);

                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.style.display = 'none';
                    a.href = url;
                    a.download = `project_${projectId}_details.pdf`;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    window.Utils.showNotification('PDF exported successfully', 'success');
                } else {
                    throw new Error('Export failed');
                }
            } catch (error) {
                console.error('Export error:', error);
                window.Utils.showNotification('Failed to export PDF', 'error');
            }
        }
    };
}

// Feedback Management
if (typeof window.FeedbackManager === 'undefined') {
    window.FeedbackManager = class FeedbackManager {
        constructor() {
            this.currentProjectId = null;
        }

        showFeedbackForm(projectId) {
            this.currentProjectId = projectId;
            const projectIdInput = document.getElementById('feedbackProjectId');
            const modal = document.getElementById('feedbackModal');

            if (projectIdInput) {
                projectIdInput.value = projectId;
            }
            if (modal) {
                modal.classList.remove('hidden');
                document.body.style.overflow = 'hidden';
            }
        }

        closeFeedbackForm() {
            const modal = document.getElementById('feedbackModal');
            const form = document.getElementById('feedbackForm');

            if (modal) {
                modal.classList.add('hidden');
            }
            if (form) {
                form.reset();
            }
            document.body.style.overflow = 'auto';
        }

        async submitFeedback(event) {
            event.preventDefault();

            const formData = new FormData(event.target);

            try {
                const response = await fetch(`${window.BASE_URL}api/feedback.php`, {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (data.success) {
                    window.Utils.showNotification('Feedback submitted successfully', 'success');
                    this.closeFeedbackForm();
                } else {
                    window.Utils.showNotification(data.message || 'Failed to submit feedback', 'error');
                }
            } catch (error) {
                console.error('Feedback submission error:', error);
                window.Utils.showNotification('Failed to submit feedback', 'error');
            }
        }
    };
}

// Map Management
if (typeof window.MapManager === 'undefined') {
    window.MapManager = class MapManager {
        constructor() {
            this.map = null;
            this.markers = [];
            this.isMapVisible = false;
        }

        async showMap() {
            try {
                const mapModal = document.getElementById('mapModal');
                if (mapModal) {
                    mapModal.classList.remove('hidden');
                    document.body.style.overflow = 'hidden';
                    this.isMapVisible = true;

                    if (!this.map) {
                        await this.initializeMap();
                    }

                    await this.loadProjectMarkers();

                    setTimeout(() => {
                        if (this.map) {
                            this.map.invalidateSize();
                        }
                    }, 100);
                }
            } catch (error) {
                console.error('Error showing map:', error);
                if (window.Utils) {
                    window.Utils.showNotification('Failed to load map', 'error');
                }
            }
        }

        async initializeMap() {
            try {
                const defaultLat = -1.2921;
                const defaultLng = 36.8219;

                const mapContainer = document.getElementById('map');
                if (!mapContainer) {
                    throw new Error('Map container not found');
                }

                this.map = L.map(mapContainer).setView([defaultLat, defaultLng], 7);

                L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    attribution: '© OpenStreetMap contributors',
                    maxZoom: 18
                }).addTo(this.map);

                L.control.scale().addTo(this.map);

            } catch (error) {
                console.error('Error initializing map:', error);
                throw error;
            }
        }

        async loadProjectMarkers() {
            try {
                this.clearMarkers();

                const urlParams = new URLSearchParams(window.location.search);
                const params = urlParams.toString();

                const response = await fetch(`${window.BASE_URL}api/projects.php?map=1&${params}`);
                const data = await response.json();

                if (!data.success) {
                    throw new Error(data.message || 'Failed to load projects');
                }

                const projects = data.projects || [];
                const validProjects = projects.filter(project =>
                    project.location_coordinates &&
                    project.location_coordinates.includes(',')
                );

                if (validProjects.length === 0) {
                    if (window.Utils) {
                        window.Utils.showNotification('No projects with location data found', 'warning');
                    }
                    return;
                }

                validProjects.forEach(project => {
                    this.addProjectMarker(project);
                });

                if (this.markers.length > 0) {
                    const group = new L.featureGroup(this.markers);
                    this.map.fitBounds(group.getBounds().pad(0.1));
                }

            } catch (error) {
                console.error('Error loading project markers:', error);
                if (window.Utils) {
                    window.Utils.showNotification('Failed to load project locations', 'error');
                }
            }
        }

        addProjectMarker(project) {
            try {
                if (!project.location_coordinates) {
                    console.warn(`No location coordinates for project ${project.id}`);
                    return;
                }

                // Handle coordinate format - should be comma-separated string
                let lat, lng;
                if (typeof project.location_coordinates === 'string' && project.location_coordinates.includes(',')) {
                    // Comma-separated string format (expected format)
                    const coordParts = project.location_coordinates.split(',');
                    if (coordParts.length === 2) {
                        lat = parseFloat(coordParts[0].trim());
                        lng = parseFloat(coordParts[1].trim());
                    } else {
                        console.warn(`Invalid coordinate format for project ${project.id}: ${project.location_coordinates}`);
                        return;
                    }
                } else {
                    console.warn(`Invalid coordinate format for project ${project.id}: ${project.location_coordinates}`);
                    return;
                }

                if (isNaN(lat) || isNaN(lng)) {
                    console.warn(`Invalid coordinates for project ${project.id}: ${project.location_coordinates} (lat: ${lat}, lng: ${lng})`);
                    return;
                }

                // Validate coordinate ranges (basic sanity check)
                if (lat < -90 || lat > 90 || lng < -180 || lng > 180) {
                    console.warn(`Coordinates out of range for project ${project.id}: lat=${lat}, lng=${lng}`);
                    return;
                }

                const markerColor = this.getMarkerColor(project.status);

                const statusColors = {
                    'ongoing': '#3b82f6',      // Blue
                    'completed': '#10b981',    // Green
                    'planning': '#f59e0b',     // Amber
                    'suspended': '#f97316',    // Orange
                    'cancelled': '#ef4444'     // Red
                };

                const color = statusColors[project.status] || '#6b7280';

                const markerIcon = new L.Icon({
                    iconUrl: `data:image/svg+xml;charset=UTF-8,${encodeURIComponent(`
                        <svg width="25" height="41" viewBox="0 0 25 41" xmlns="http://www.w3.org/2000/svg">
                            <path fill="${color}" stroke="#FFFFFF" stroke-width="1" d="M12.5,0C5.6,0,0,5.6,0,12.5c0,6.9,12.5,28.5,12.5,28.5s12.5-21.6,12.5-28.5C25,5.6,19.4,0,12.5,0z"/>
                            <circle fill="#FFFFFF" cx="12.5" cy="12.5" r="4"/>
                        </svg>
                    `)}`,
                    iconSize: [25, 41],
                    iconAnchor: [12.5, 41],
                    popupAnchor: [0, -41]
                });

                const marker = L.marker([lat, lng], { icon: markerIcon });

                const popupContent = `
                    <div class="relative p-3 max-w-xs">
                        <button onclick="document.querySelector('.leaflet-popup-close-button').click()"
                                class="absolute top-1 right-1 w-6 h-6 flex items-center justify-center text-gray-400 hover:text-gray-600 bg-white rounded-full shadow-sm border border-gray-200 z-50">
                            <i class="fas fa-times text-xs"></i>
                        </button>

                        <h4 class="font-medium text-gray-900 text-sm mb-2 leading-tight pr-8">${this.escapeHtml(project.project_name)}</h4>

                        <div class="space-y-1 text-xs text-gray-600 mb-3">
                            <div class="flex items-center">
                                <i class="fas fa-building mr-1 text-blue-500 w-3"></i>
                                <span>${this.escapeHtml(project.department_name || 'N/A')}</span>
                            </div>
                            <div class="flex items-center">
                                <i class="fas fa-map-marker-alt mr-1 text-red-500 w-3"></i>
                                <span>${this.escapeHtml(project.ward_name || 'N/A')}, ${this.escapeHtml(project.sub_county_name || 'N/A')}</span>
                            </div>
                            <div class="flex items-center">
                                <i class="fas fa-calendar mr-1 text-green-500 w-3"></i>
                                <span>${project.project_year || 'N/A'}</span>
                            </div>
                            <div class="flex items-center">
                                <i class="fas fa-tasks mr-1 text-purple-500 w-3"></i>
                                <span class="px-1 py-0.5 rounded text-xs font-medium" style="background-color: ${markerColor}20; color: ${markerColor};">
                                    ${project.status.charAt(0).toUpperCase() + project.status.slice(1)}
                                </span>
                            </div>
                            ${project.progress_percentage > 0 ? `
                                <div class="flex items-center">
                                    <i class="fas fa-chart-line mr-1 text-indigo-500 w-3"></i>
                                    <span>${project.progress_percentage}% complete</span>
                                </div>
                            ` : ''}
                        </div>

                        <div class="flex gap-2">
                            <a href="${window.BASE_URL}projectDetails/${project.id}"
                               class="text-blue-600 hover:text-blue-800 text-xs font-medium underline">
                                View Details
                            </a>
                            <a href="#" onclick="openFeedbackModal(${project.id}); return false;"
                               class="text-green-600 hover:text-green-800 text-xs font-medium underline">
                                Give Feedback
                            </a>
                        </div>
                    </div>
                `;
                marker.bindPopup(popupContent, {
                    maxWidth: 250,
                    className: 'custom-popup map-pin-popup',
                    closeButton: false,
                    autoPan: true,
                    zoomAnimation: false
                });

                marker.addTo(this.map);
                this.markers.push(marker);

            } catch (error) {
                console.error(`Error adding marker for project ${project.id}:`, error);
            }
        }

        getMarkerColor(status) {
            const colors = {
                planning: 'text-yellow-500',
                ongoing: 'text-blue-500',
                completed: 'text-green-500',
                suspended: 'text-orange-500',
                cancelled: 'text-red-500'
            };
            return colors[status] || 'text-gray-500';
        }

        escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        clearMarkers() {
            this.markers.forEach(marker => {
                if (this.map) {
                    this.map.removeLayer(marker);
                }
            });
            this.markers = [];
        }

        closeMap() {
            const mapModal = document.getElementById('mapModal');
            if (mapModal) {
                mapModal.classList.add('hidden');
                document.body.style.overflow = 'auto';
            }
            this.isMapVisible = false;
        }
    };
}

// Export Functions
if (typeof window.ExportManager === 'undefined') {
    window.ExportManager = class ExportManager {
        static async exportPDF() {
            try {
                const urlParams = new URLSearchParams(window.location.search);
                const queryString = urlParams.toString();

                const response = await fetch(`${window.BASE_URL}api/exportPdf.php?${queryString}`);

                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.style.display = 'none';
                    a.href = url;
                    a.download = `county_projects_${new Date().getTime()}.pdf`;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    window.Utils.showNotification('PDF exported successfully', 'success');
                } else {
                    throw new Error('Export failed');
                }
            } catch (error) {
                console.error('Export error:', error);
                window.Utils.showNotification('Failed to export PDF', 'error');
            }
        }

        static async exportCSV() {
            try {
                const urlParams = new URLSearchParams(window.location.search);
                const queryString = urlParams.toString();

                const response = await fetch(`${window.BASE_URL}api/exportCsv.php?${queryString}`);

                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.style.display = 'none';
                    a.href = url;
                    a.download = `county_projects_${new Date().getTime()}.csv`;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    window.Utils.showNotification('CSV exported successfully', 'success');
                } else {
                    throw new Error('Export failed');
                }
            } catch (error) {
                console.error('Export error:', error);
                window.Utils.showNotification('Failed to export CSV', 'error');
            }
        }
    };
}

// View Management - Global variables
window.currentView = 'grid';
window.allProjects = [];
if (typeof window.mapViewMarkers === 'undefined') {
    window.mapViewMarkers = [];
}
if (typeof window.mainMapViewInstance === 'undefined') {
    window.mainMapViewInstance = null;
}

// Global instances
window.publicThemeManager = null;
window.projectManager = null;
window.feedbackManager = null;
window.mapManager = null;

// View switching functionality - Make it globally accessible
window.switchView = function(viewType) {
    window.currentView = viewType;

    // Update active button
    document.querySelectorAll('.view-btn-modern').forEach(btn => {
        btn.classList.remove('active');
    });
    const activeBtn = document.getElementById(viewType + 'View');
    if (activeBtn) {
        activeBtn.classList.add('active');
    }

    // Hide all containers
    const gridContainer = document.getElementById('gridContainer');
    const listContainer = document.getElementById('listContainer');
    const mapContainer = document.getElementById('mapContainer');

    if (gridContainer) gridContainer.classList.add('hidden');
    if (listContainer) listContainer.classList.add('hidden');
    if (mapContainer) mapContainer.classList.add('hidden');

    // Show selected container
    switch(viewType) {
        case 'grid':
            if (gridContainer) {
                gridContainer.classList.remove('hidden');
                setTimeout(() => initGridMaps(), 100);
            }
            break;
        case 'list':
            if (listContainer) {
                listContainer.classList.remove('hidden');
                renderListView();
            }
            break;
        case 'map':
            if (mapContainer) {
                mapContainer.classList.remove('hidden');
                setTimeout(() => renderMapView(), 100);
            }
            break;
    }
};

function renderListView() {
    const container = document.getElementById('listContainer');
    if (!container) return;

    if (!window.projectsData || !window.projectsData.length) {
        container.innerHTML = '<div class="glass-card text-center py-16"><p class="text-gray-500">No projects available</p></div>';
        return;
    }

    // Categorize projects by status
    const ongoingProjects = window.projectsData.filter(p => p.status === 'ongoing');
    const completedProjects = window.projectsData.filter(p => p.status === 'completed');
    const planningProjects = window.projectsData.filter(p => p.status === 'planning');

    function renderProjectCategory(projects, title) {
        if (!projects.length) return '';

        return `
            <div class="mb-8">
                <div class="category-header-modern mb-4 ml-4">
                    <div class="category-title-modern" style="color: #000000 !important;">
                        ${title} Projects
                    </div>
                    <span class="category-count-modern">
                        ${projects.length} projects
                    </span>
                </div>
                <div class="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
                    <div class="divide-y divide-gray-200">
                        ${projects.map((project, index) => `
                            <div class="flex items-center justify-between p-4 hover:bg-gray-50 transition-colors">
                                <div class="flex-1 min-w-0">
                                    <div class="mb-2">
                                        <a href="${window.BASE_URL}projectDetails/${project.id}" class="font-semibold hover:text-blue-600 transition-colors line-clamp-1" style="color: #000000 !important;">
                                            ${project.project_name}
                                        </a>
                                    </div>
                                    <div class="flex flex-wrap items-center gap-4 text-sm text-gray-600">
                                        <div class="flex items-center gap-1">
                                            <i class="fas fa-map-marker-alt text-red-400"></i>
                                            <span>${project.ward_name}, ${project.sub_county_name}</span>
                                        </div>
                                        <div class="flex items-center gap-1">
                                            <i class="fas fa-building text-blue-400"></i>
                                            <span>${project.department_name}</span>
                                        </div>
                                        <div class="flex items-center gap-1">
                                            <i class="fas fa-chart-line text-purple-400"></i>
                                            <span>${project.progress_percentage || 0}% complete</span>
                                        </div>
                                    </div>
                                </div>
                                <div class="flex items-center gap-3 ml-4">
                                    <a href="${window.BASE_URL}projectDetails/${project.id}" class="text-blue-600 hover:text-blue-800 font-medium text-sm whitespace-nowrap">
                                        View Details →
                                    </a>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    }

    container.innerHTML = `
        <div class="list-view-container space-y-8">
            ${renderProjectCategory(ongoingProjects, 'Active')}
            ${renderProjectCategory(completedProjects, 'Completed')}
            ${renderProjectCategory(planningProjects, 'Planning')}
        </div>
    `;
}

function renderMapView() {
    if (!window.allProjects || !window.allProjects.length) {
        const projectsList = document.getElementById('mapProjectsList');
        if (projectsList) {
            projectsList.innerHTML = '<div class="text-center text-gray-500 py-8"><p>No projects available</p></div>';
        }
        return;
    }

    // Filter for ongoing and completed projects with valid coordinates only
    const ongoingProjects = window.allProjects.filter(project =>
        project.status === 'ongoing' &&
        project.location_coordinates &&
        project.location_coordinates.includes(',') &&
        project.location_coordinates.trim() !== '' &&
        project.location_coordinates !== '0,0'
    );

    const completedProjects = window.allProjects.filter(project =>
        project.status === 'completed' &&
        project.location_coordinates &&
        project.location_coordinates.includes(',') &&
        project.location_coordinates.trim() !== '' &&
        project.location_coordinates !== '0,0'
    );

    // Randomly select up to 15 ongoing and 5 completed projects
    const shuffleArray = (array) => {
        const shuffled = [...array];
        for (let i = shuffled.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        }
        return shuffled;
    };

    const selectedOngoing = shuffleArray(ongoingProjects).slice(0, Math.min(15, ongoingProjects.length));
    const selectedCompleted = shuffleArray(completedProjects).slice(0, Math.min(5, completedProjects.length));
    const selectedProjects = [...selectedOngoing, ...selectedCompleted];

    console.log('Available ongoing projects:', ongoingProjects.length);
    console.log('Available completed projects:', completedProjects.length);
    console.log('Selected projects for map:', selectedProjects.length);

    // Hide the project list sidebar for full map view
    const projectsList = document.getElementById('mapProjectsList');
    if (projectsList) {
        projectsList.style.display = 'none';
    }

    // Initialize the main map view with selected projects
    setTimeout(() => initMainMapView(selectedProjects), 200);
}

function initGridMaps() {
    if (typeof L === 'undefined') {
        console.warn('Leaflet not loaded');
        return;
    }

    const mapElements = document.querySelectorAll('[id^="map-preview-"]');

    mapElements.forEach(mapEl => {
        // Skip if already initialized
        if (mapEl._leaflet_id) {
            return;
        }

        const projectId = mapEl.id.replace('map-preview-', '');
        const project = window.allProjects.find(p => p.id == projectId);

        if (project && project.location_coordinates) {
            try {
                // Parse coordinates
                const coords = parseCoordinates(project.location_coordinates);
                if (coords && coords.length === 2) {
                    const [lat, lng] = coords;

                    if (!isNaN(lat) && !isNaN(lng)) {
                        // Clear any existing content
                        mapEl.innerHTML = '';

                        const map = L.map(mapEl, {
                            zoomControl: false,
                            dragging: false,
                            touchZoom: false,
                            doubleClickZoom: false,
                            scrollWheelZoom: false,
                            boxZoom: false,
                            keyboard: false,
                            attributionControl: false
                        }).setView([lat, lng], 13);

                        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                            attribution: ''
                        }).addTo(map);

                        // Use custom marker
                        createCustomMarker(lat, lng, project).addTo(map);
                    }
                }
            } catch (error) {
                console.warn('Error initializing map for project:', projectId, error);
            }
        }
    });
}

function createCustomMarker(lat, lng, project) {
    // Get color based on project status
    const statusColors = {
        'ongoing': '#3b82f6',      // Blue
        'completed': '#10b981',    // Green
        'planning': '#f59e0b',     // Amber
        'suspended': '#f97316',    // Orange
        'cancelled': '#ef4444'     // Red
    };

    const color = statusColors[project.status] || '#6b7280'; // Default gray

    // Create custom icon with default Leaflet pin style
    const customIcon = new L.Icon({
        iconUrl: `data:image/svg+xml;charset=UTF-8,${encodeURIComponent(`
            <svg width="25" height="41" viewBox="0 0 25 41" xmlns="http://www.w3.org/2000/svg">
                <path fill="${color}" stroke="#FFFFFF" stroke-width="1" d="M12.5,0C5.6,0,0,5.6,0,12.5c0,6.9,12.5,28.5,12.5,28.5s12.5-21.6,12.5-28.5C25,5.6,19.4,0,12.5,0z"/>
                <circle fill="#FFFFFF" cx="12.5" cy="12.5" r="4"/>
            </svg>
        `)}`,
        iconSize: [25, 41],
        iconAnchor: [12.5, 41],
        popupAnchor: [0, -41]
    });

    return L.marker([lat, lng], { icon: customIcon });
}

function initMainMapView(projects = []) {
    if (typeof L === 'undefined') {
        console.warn('Leaflet not loaded');
        return;
    }

    const mapContainer = document.getElementById('mainMapView');
    if (!mapContainer) return;

    // Clear existing map
    if (mainMapViewInstance) {
        mainMapViewInstance.remove();
        mainMapViewInstance = null;
        mapViewMarkers = [];
    }

    try {
        // Initialize map centered on Migori County with appropriate zoom
        mainMapViewInstance = L.map(mapContainer, {
            zoomControl: true,
            attributionControl: true
        }).setView([-1.0634, 34.4731], 11);

        // Add tile layer
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors',
            maxZoom: 18
        }).addTo(mainMapViewInstance);

        // Add markers for projects
        let validMarkersCount = 0;
        projects.forEach(project => {
            if (project.location_coordinates && project.location_coordinates.trim() !== '' && project.location_coordinates !== '0,0') {
                try {
                    // Parse coordinates
                    const coords = parseCoordinates(project.location_coordinates);
                    if (coords && coords.length === 2) {
                        const [lat, lng] = coords;

                        if (!isNaN(lat) && !isNaN(lng) && lat !== 0 && lng !== 0) {
                            // Create custom marker with status-based color
                            const markerColors = {
                                'ongoing': '#3B82F6', // Blue
                                'completed': '#10B981', // Green
                                'planning': '#F59E0B', // Yellow
                                'suspended': '#F97316', // Orange
                                'cancelled': '#EF4444' // Red
                            };

                            const markerColor = markerColors[project.status] || '#6B7280';

                            const markerIcon = new L.Icon({
                                iconUrl: `data:image/svg+xml;charset=UTF-8,${encodeURIComponent(`
                                    <svg width="25" height="41" viewBox="0 0 25 41" xmlns="http://www.w3.org/2000/svg">
                                        <path fill="${markerColor}" stroke="#FFFFFF" stroke-width="1" d="M12.5,0C5.6,0,0,5.6,0,12.5c0,6.9,12.5,28.5,12.5,28.5s12.5-21.6,12.5-28.5C25,5.6,19.4,0,12.5,0z"/>
                                        <circle fill="#FFFFFF" cx="12.5" cy="12.5" r="4"/>
                                    </svg>
                                `)}`,
                                iconSize: [25, 41],
                                iconAnchor: [12.5, 41],
                                popupAnchor: [0, -41]
                            });

                            const marker = L.marker([lat, lng], { icon: markerIcon });
                            marker.projectId = project.id;

                            // Create clean popup content
                            const popupContent = `
                                <div class="relative p-3 max-w-xs">
                                    <button onclick="document.querySelector('.leaflet-popup-close-button').click()"
                                            class="absolute top-1 right-1 w-6 h-6 flex items-center justify-center text-gray-400 hover:text-gray-600 bg-white rounded-full shadow-sm border border-gray-200 z-50">
                                        <i class="fas fa-times text-xs"></i>
                                    </button>

                                    <h4 class="font-medium text-gray-900 text-sm mb-2 leading-tight pr-8">${escapeHtml(project.project_name)}</h4>

                                    <div class="space-y-1 text-xs text-gray-600 mb-3">
                                        <div class="flex items-center">
                                            <i class="fas fa-building mr-1 text-blue-500 w-3"></i>
                                            <span>${escapeHtml(project.department_name || 'N/A')}</span>
                                        </div>
                                        <div class="flex items-center">
                                            <i class="fas fa-map-marker-alt mr-1 text-red-500 w-3"></i>
                                            <span>${escapeHtml(project.ward_name || 'N/A')}, ${escapeHtml(project.sub_county_name || 'N/A')}</span>
                                        </div>
                                        <div class="flex items-center">
                                            <i class="fas fa-calendar mr-1 text-green-500 w-3"></i>
                                            <span>${project.project_year || 'N/A'}</span>
                                        </div>
                                        <div class="flex items-center">
                                            <i class="fas fa-tasks mr-1 text-purple-500 w-3"></i>
                                            <span class="px-1 py-0.5 rounded text-xs font-medium" style="background-color: ${markerColor}20; color: ${markerColor};">
                                                ${project.status.charAt(0).toUpperCase() + project.status.slice(1)}
                                            </span>
                                        </div>
                                        ${project.progress_percentage > 0 ? `
                                            <div class="flex items-center">
                                                <i class="fas fa-chart-line mr-1 text-indigo-500 w-3"></i>
                                                <span>${project.progress_percentage}% complete</span>
                                            </div>
                                        ` : ''}
                                    </div>

                                    <div class="flex gap-2">
                                        <a href="${window.BASE_URL}projectDetails/${project.id}"
                                           class="text-blue-600 hover:text-blue-800 text-xs font-medium underline">
                                            View Details
                                        </a>
                                        <a href="#" onclick="openFeedbackModal(${project.id}); return false;"
                                           class="text-green-600 hover:text-green-800 text-xs font-medium underline">
                                            Give Feedback
                                        </a>
                                    </div>
                                </div>
                            `;
                            marker.bindPopup(popupContent, {
                                maxWidth: 250,
                                className: 'custom-popup map-pin-popup',
                                closeButton: false,
                                autoPan: true,
                                zoomAnimation: false
                            });

                            marker.addTo(mainMapViewInstance);
                            mapViewMarkers.push(marker);
                            validMarkersCount++;

                            console.log(`Added marker for project: ${project.project_name} at ${lat}, ${lng}`);
                        } else {
                            console.warn(`Invalid coordinates for project ${project.id}: lat=${lat}, lng=${lng}`);
                        }
                    }
                } catch (e) {
                    console.warn('Error processing coordinates for project:', project.id, e);
                }
            } else {
                console.warn(`No coordinates for project ${project.id}: "${project.location_coordinates}"`);
            }
        });

        console.log(`Total markers added to map: ${validMarkersCount}`);

        // Fit map to markers if available, otherwise stay at Migori County center
        if (mapViewMarkers.length > 0) {
            const group = new L.featureGroup(mapViewMarkers);
            mainMapViewInstance.fitBounds(group.getBounds().pad(0.05));
        }

    } catch (error) {
        console.error('Error initializing main map view:', error);
    }
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Enhanced coordinate parsing - handles both string and array formats
function parseCoordinates(coordinateString) {
    if (!coordinateString) return null;

    try {
        // If it's already an array (JSON format)
        if (coordinateString.startsWith('[')) {
            return JSON.parse(coordinateString);
        }

        // If it's a comma-separated string
        if (typeof coordinateString === 'string' && coordinateString.includes(',')) {
            const parts = coordinateString.split(',');
            if (parts.length === 2) {
                const lat = parseFloat(parts[0].trim());
                const lng = parseFloat(parts[1].trim());
                if (!isNaN(lat) && !isNaN(lng)) {
                    return [lat, lng];
                }
            }
        }

        return null;
    } catch (e) {
        console.warn('Error parsing coordinates:', coordinateString, e);
        return null;
    }
}

// Global functions for HTML onclick handlers
window.showProjectDetails = function(projectId) {
    if (window.projectManager) {
        window.projectManager.showProjectDetails(projectId);
    }
};

window.closeProjectDetails = function() {
    if (window.projectManager) {
        window.projectManager.closeProjectDetails();
    }
};

window.showFeedbackForm = function(projectId) {
    if (window.feedbackManager) {
        window.feedbackManager.showFeedbackForm(projectId);
    }
};

window.closeFeedbackForm = function() {
    if (window.feedbackManager) {
        window.feedbackManager.closeFeedbackForm();
    }
};

window.submitFeedback = function(event) {
    if (window.feedbackManager) {
        return window.feedbackManager.submitFeedback(event);
    }
};

window.exportPDF = function() {
    return window.ExportManager.exportPDF();
};

window.exportCSV = function() {
    return window.ExportManager.exportCSV();
};

window.openFeedbackModal = function(projectId) {
    if (window.feedbackManager) {
        window.feedbackManager.showFeedbackForm(projectId);
    }
};

window.closeFeedbackModal = function() {
    if (window.feedbackManager) {
        window.feedbackManager.closeFeedbackForm();
    }
};

// Rating modal functions
window.openRatingModal = function(projectId) {
    const ratingProjectId = document.getElementById('rating-project-id');
    const ratingModal = document.getElementById('rating-modal');

    if (ratingProjectId) {
        ratingProjectId.value = projectId;
    }
    if (ratingModal) {
        ratingModal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }
};

window.closeRatingModal = function() {
    const ratingModal = document.getElementById('rating-modal');
    const ratingForm = document.getElementById('rating-form');

    if (ratingModal) {
        ratingModal.classList.add('hidden');
    }
    if (ratingForm) {
        ratingForm.reset();
    }
    document.body.style.overflow = 'auto';

    // Reset star rating
    const stars = document.querySelectorAll('.star-btn');
    stars.forEach(star => {
        star.innerHTML = '<i class="far fa-star"></i>';
        star.classList.remove('text-yellow-400');
        star.classList.add('text-gray-300');
    });

    const selectedRating = document.getElementById('selected-rating');
    if (selectedRating) {
        selectedRating.value = '';
    }
};

window.applyFilters = function() {
    const departmentFilter = document.getElementById('departmentFilter');
    const statusFilter = document.getElementById('statusFilter');
    const yearFilter = document.getElementById('yearFilter');

    const departmentId = departmentFilter ? departmentFilter.value : '';
    const status = statusFilter ? statusFilter.value : '';
    const year = yearFilter ? yearFilter.value : '';

    // Build query string
    const params = new URLSearchParams(window.location.search);

    if (departmentId) {
        params.set('department', departmentId);
    } else {
        params.delete('department');
    }

    if (status) {
        params.set('status', status);
    } else {
        params.delete('status');
    }

    if (year) {
        params.set('year', year);
    } else {
        params.delete('year');
    }

    // Redirect with new filters
    window.location.href = window.location.pathname + '?' + params.toString();
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Only initialize if we're not in admin area
    if (!window.location.pathname.includes('/admin/')) {
        if (!window.publicThemeManager) {
            window.publicThemeManager = new window.PublicThemeManager();
        }
    }

    // Create global instances
    if (!window.projectManager) {
        window.projectManager = new window.ProjectManager();
    }

    if (!window.feedbackManager) {
        window.feedbackManager = new window.FeedbackManager();
    }

    // Initialize mapManager only if Leaflet is defined
    if (typeof L !== 'undefined' && !window.mapManager) {
        window.mapManager = new window.MapManager();
    }

    // Initialize view switching if on index page
    if (typeof window.projectsData !== 'undefined') {
        window.allProjects = window.projectsData;

        // Initialize grid maps after a delay to ensure DOM is ready
        setTimeout(() => {
            if (typeof initGridMaps === 'function') {
                initGridMaps();
            }
        }, 300);
    }

    // Scroll to top functionality with null checks
    const scrollToTopBtn = document.getElementById('scrollToTop');
    if (scrollToTopBtn) {
        // Show/hide scroll to top button
        window.addEventListener('scroll', function() {
            if (window.pageYOffset > 300) {
                scrollToTopBtn.classList.add('opacity-100', 'visible');
                scrollToTopBtn.classList.remove('opacity-0', 'invisible', 'translate-y-4');
            } else {
                scrollToTopBtn.classList.add('opacity-0', 'invisible', 'translate-y-4');
                scrollToTopBtn.classList.remove('opacity-100', 'visible');
            }
        });

        // Scroll to top when clicked
        scrollToTopBtn.addEventListener('click', function() {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
    }

    // Initialize scroll progress indicator
    initScrollProgress();
});

// Initialize scroll progress indicator
function initScrollProgress() {
    const progressIndicator = document.querySelector('.scroll-indicator');
    if (progressIndicator) {
        window.addEventListener('scroll', function() {
            const scrolled = (window.pageYOffset / (document.documentElement.scrollHeight - window.innerHeight)) * 100;
            progressIndicator.style.setProperty('--scroll-progress', scrolled / 100);
        });
    }
}