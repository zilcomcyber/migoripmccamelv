// Public-facing JavaScript for County Project Tracking System
// Consolidated from app.js, main.js, and mobile-menu.js

// Ensure BASE_URL is available
if (typeof window.BASE_URL === "undefined") {
    window.BASE_URL = "/";
}

// Theme Management
if (typeof window.PublicThemeManager === "undefined") {
    window.PublicThemeManager = class PublicThemeManager {
        constructor() {
            this.init();
        }

        init() {
            const savedTheme = localStorage.getItem("theme");
            const prefersDark = window.matchMedia(
                "(prefers-color-scheme: dark)",
            ).matches;

            if (savedTheme === "dark" || (!savedTheme && prefersDark)) {
                this.enableDarkMode();
            } else {
                this.enableLightMode();
            }

            const themeToggle = document.getElementById("theme-toggle");
            if (themeToggle) {
                themeToggle.addEventListener("click", () => this.toggleTheme());
            }
        }

        enableDarkMode() {
            document.documentElement.classList.add("dark");
            localStorage.setItem("theme", "dark");
        }

        enableLightMode() {
            document.documentElement.classList.remove("dark");
            localStorage.setItem("theme", "light");
        }

        toggleTheme() {
            if (document.documentElement.classList.contains("dark")) {
                this.enableLightMode();
            } else {
                this.enableDarkMode();
            }
        }
    };
}

// Utility Functions
if (typeof window.Utils === "undefined") {
    window.Utils = class Utils {
        static showNotification(message, type = "info", duration = 5000) {
            const notification = document.createElement("div");
            notification.className = `fixed top-4 right-4 z-50 p-4 rounded-lg shadow-lg max-w-sm transform transition-all duration-300 translate-x-full`;

            const typeClasses = {
                success:
                    "bg-green-100 border-green-500 text-green-800 border-l-4",
                error: "bg-red-100 border-red-500 text-red-800 border-l-4",
                warning:
                    "bg-yellow-100 border-yellow-500 text-yellow-800 border-l-4",
                info: "bg-blue-100 border-blue-500 text-blue-800 border-l-4",
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

            setTimeout(() => {
                notification.classList.remove("translate-x-full");
            }, 100);

            setTimeout(() => {
                notification.classList.add("translate-x-full");
                setTimeout(() => notification.remove(), 300);
            }, duration);
        }

        static formatCurrency(amount) {
            return new Intl.NumberFormat("en-KE", {
                style: "currency",
                currency: "KES",
                minimumFractionDigits: 0,
                maximumFractionDigits: 0,
            }).format(amount);
        }

        static formatDate(dateString) {
            return new Date(dateString).toLocaleDateString("en-KE", {
                year: "numeric",
                month: "long",
                day: "numeric",
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
if (typeof window.ProjectManager === "undefined") {
    window.ProjectManager = class ProjectManager {
        constructor() {
            this.currentProject = null;
        }

        async fetchProjectDetails(projectId) {
            try {
                const response = await fetch(
                    `${window.BASE_URL}api/projects.php?id=${projectId}`,
                );
                const data = await response.json();

                if (data.success) {
                    return data.project;
                } else {
                    throw new Error(
                        data.message || "Failed to fetch project details",
                    );
                }
            } catch (error) {
                console.error("Error fetching project details:", error);
                window.Utils.showNotification(
                    "Failed to load project details",
                    "error",
                );
                return null;
            }
        }

        async showProjectDetails(projectId) {
            const project = await this.fetchProjectDetails(projectId);
            if (!project) return;

            this.currentProject = project;

            const detailsContainer = document.getElementById("projectDetails");
            if (detailsContainer) {
                detailsContainer.innerHTML = this.renderProjectDetails(project);
            }

            const modal = document.getElementById("projectModal");
            if (modal) {
                modal.classList.remove("hidden");
                document.body.style.overflow = "hidden";
            }
        }

        renderProjectDetails(project) {
            const progressColor = this.getProgressColor(
                project.progress_percentage,
            );
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
                        <p class="text-gray-600 dark:text-gray-300">${project.description || "No description available"}</p>
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
                                ${
                                    project.start_date
                                        ? `
                                    <div>
                                        <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Start Date</dt>
                                        <dd class="text-sm text-gray-900 dark:text-white">${window.Utils.formatDate(project.start_date)}</dd>
                                    </div>
                                `
                                        : ""
                                }
                                ${
                                    project.expected_completion_date
                                        ? `
                                    <div>
                                        <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Expected Completion</dt>
                                        <dd class="text-sm text-gray-900 dark:text-white">${window.Utils.formatDate(project.expected_completion_date)}</dd>
                                    </div>
                                `
                                        : ""
                                }
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
                            </dl>
                        </div>
                    </div>
                </div>
            `;
        }

        getProgressColor(percentage) {
            if (percentage >= 80) return "bg-green-500";
            if (percentage >= 60) return "bg-blue-500";
            if (percentage >= 40) return "bg-yellow-500";
            if (percentage >= 20) return "bg-orange-500";
            return "bg-red-500";
        }

        getStatusBadgeClass(status) {
            const classes = {
                planning:
                    "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300",
                ongoing:
                    "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300",
                completed:
                    "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300",
                suspended:
                    "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300",
                cancelled:
                    "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300",
            };
            return (
                classes[status] ||
                "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300"
            );
        }

        closeProjectDetails() {
            const modal = document.getElementById("projectModal");
            if (modal) {
                modal.classList.add("hidden");
                document.body.style.overflow = "auto";
            }
        }

        async exportProjectPDF(projectId) {
            try {
                const response = await fetch(
                    `${window.BASE_URL}api/export_pdf?project_id=${projectId}`,
                );

                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.style.display = "none";
                    a.href = url;
                    a.download = `project_${projectId}_details.pdf`;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    window.Utils.showNotification(
                        "PDF exported successfully",
                        "success",
                    );
                } else {
                    throw new Error("Export failed");
                }
            } catch (error) {
                console.error("Export error:", error);
                window.Utils.showNotification("Failed to export PDF", "error");
            }
        }
    };
}

// Feedback Management
if (typeof window.FeedbackManager === "undefined") {
    window.FeedbackManager = class FeedbackManager {
        constructor() {
            this.currentProjectId = null;
        }

        showFeedbackForm(projectId) {
            this.currentProjectId = projectId;
            const projectIdInput = document.getElementById("feedbackProjectId");
            const modal = document.getElementById("feedbackModal");

            if (projectIdInput) {
                projectIdInput.value = projectId;
            }
            if (modal) {
                modal.classList.remove("hidden");
                document.body.style.overflow = "hidden";
            }
        }

        closeFeedbackForm() {
            const modal = document.getElementById("feedbackModal");
            const form = document.getElementById("feedbackForm");

            if (modal) {
                modal.classList.add("hidden");
            }
            if (form) {
                form.reset();
            }
            document.body.style.overflow = "auto";
        }

        async submitFeedback(event) {
            event.preventDefault();

            const formData = new FormData(event.target);

            try {
                const response = await fetch(
                    `${window.BASE_URL}api/feedback.php`,
                    {
                        method: "POST",
                        body: formData,
                    },
                );

                const data = await response.json();

                if (data.success) {
                    window.Utils.showNotification(
                        "Feedback submitted successfully",
                        "success",
                    );
                    this.closeFeedbackForm();
                } else {
                    window.Utils.showNotification(
                        data.message || "Failed to submit feedback",
                        "error",
                    );
                }
            } catch (error) {
                console.error("Feedback submission error:", error);
                window.Utils.showNotification(
                    "Failed to submit feedback",
                    "error",
                );
            }
        }
    };
}

// Export Functions
if (typeof window.ExportManager === "undefined") {
    window.ExportManager = class ExportManager {
        static async exportPDF() {
            try {
                const urlParams = new URLSearchParams(window.location.search);
                const queryString = urlParams.toString();

                const response = await fetch(
                    `${window.BASE_URL}api/exportPdf.php?${queryString}`,
                );

                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.style.display = "none";
                    a.href = url;
                    a.download = `county_projects_${new Date().getTime()}.pdf`;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    window.Utils.showNotification(
                        "PDF exported successfully",
                        "success",
                    );
                } else {
                    throw new Error("Export failed");
                }
            } catch (error) {
                console.error("Export error:", error);
                window.Utils.showNotification("Failed to export PDF", "error");
            }
        }

        static async exportCSV() {
            try {
                const urlParams = new URLSearchParams(window.location.search);
                const queryString = urlParams.toString();

                const response = await fetch(
                    `${window.BASE_URL}api/exportCsv.php?${queryString}`,
                );

                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.style.display = "none";
                    a.href = url;
                    a.download = `county_projects_${new Date().getTime()}.csv`;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    window.Utils.showNotification(
                        "CSV exported successfully",
                        "success",
                    );
                } else {
                    throw new Error("Export failed");
                }
            } catch (error) {
                console.error("Export error:", error);
                window.Utils.showNotification("Failed to export CSV", "error");
            }
        }
    };
}

// Mobile Menu Management
if (typeof window.MobileMenuManager === "undefined") {
    window.MobileMenuManager = class MobileMenuManager {
        constructor() {
            this.init();
        }

        init() {
            const mobileMenuToggle =
                document.getElementById("mobile-menu-toggle");
            const mobileSidebar = document.getElementById("mobile-sidebar");
            const mobileOverlay = document.getElementById(
                "mobile-sidebar-overlay",
            );

            if (!mobileMenuToggle || !mobileSidebar || !mobileOverlay) {
                return;
            }

            mobileMenuToggle.addEventListener("click", (e) => {
                e.preventDefault();
                e.stopPropagation();
                const isOpen = mobileSidebar.classList.contains("active");
                this.toggleSidebar(!isOpen);
            });

            mobileOverlay.addEventListener("click", () => {
                this.toggleSidebar(false);
            });

            const navLinks = mobileSidebar.querySelectorAll("a");
            navLinks.forEach((link) => {
                link.addEventListener("click", () => {
                    this.toggleSidebar(false);
                });
            });

            document.addEventListener("keydown", (e) => {
                if (e.key === "Escape") {
                    this.toggleSidebar(false);
                }
            });

            document.addEventListener("click", (e) => {
                if (
                    !mobileSidebar.contains(e.target) &&
                    !mobileMenuToggle.contains(e.target)
                ) {
                    this.toggleSidebar(false);
                }
            });

            mobileSidebar.addEventListener("click", (e) => {
                e.stopPropagation();
            });
        }

        toggleSidebar(show) {
            const mobileSidebar = document.getElementById("mobile-sidebar");
            const mobileOverlay = document.getElementById(
                "mobile-sidebar-overlay",
            );

            if (show) {
                mobileSidebar.classList.add("active");
                mobileOverlay.classList.add("active");
                mobileOverlay.classList.remove("hidden");
                document.body.classList.add("sidebar-open");
            } else {
                mobileSidebar.classList.remove("active");
                mobileOverlay.classList.remove("active");
                mobileOverlay.classList.add("hidden");
                document.body.classList.remove("sidebar-open");
            }
        }
    };
}

// Global instances
window.publicThemeManager = null;
window.projectManager = null;
window.feedbackManager = null;
window.mobileMenuManager = null;
window.viewManager = null;

// View Management Class
if (typeof window.ViewManager === "undefined") {
    window.ViewManager = class ViewManager {
        constructor() {
            this.currentView = 'grid';
            this.mapInstance = null;
        }

        switchView(view) {
            // Hide all containers
            const containers = ['gridContainer', 'listContainer', 'mapContainer'];
            containers.forEach(containerId => {
                const container = document.getElementById(containerId);
                if (container) {
                    container.classList.add('hidden');
                }
            });

            // Remove active class from all buttons
            const buttons = ['gridView', 'listView', 'mapView'];
            buttons.forEach(buttonId => {
                const button = document.getElementById(buttonId);
                if (button) {
                    button.classList.remove('active');
                }
            });

            // Show selected container and activate button
            const targetContainer = document.getElementById(view + 'Container');
            const targetButton = document.getElementById(view + 'View');
            
            if (targetContainer) {
                targetContainer.classList.remove('hidden');
            }
            if (targetButton) {
                targetButton.classList.add('active');
            }

            this.currentView = view;

            // Initialize map if switching to map view
            if (view === 'map') {
                this.initializeMapView();
            }

            // Update URL without reloading
            const url = new URL(window.location);
            url.searchParams.set('view', view);
            window.history.replaceState({}, '', url);
        }

        initializeMapView() {
            setTimeout(() => {
                // Always try to create main map view, don't depend on mapManager
                this.createMainMapView();
            }, 100);
        }

        async createMainMapView() {
            const mapContainer = document.getElementById('mainMapView');
            if (!mapContainer || typeof L === 'undefined') {
                console.warn('Map container not found or Leaflet not loaded');
                return;
            }

            // Clear existing map
            if (this.mapInstance) {
                this.mapInstance.remove();
                this.mapInstance = null;
            }

            // Clear container and reset Leaflet state
            mapContainer.innerHTML = '';
            if (mapContainer._leaflet_id) {
                delete mapContainer._leaflet_id;
            }

            try {
                // Initialize map
                this.mapInstance = L.map(mapContainer).setView([-1.0634, 34.4738], 10);

                L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    attribution: '© OpenStreetMap contributors',
                    maxZoom: 18
                }).addTo(this.mapInstance);

                // Load project markers
                await this.loadMapProjects();
            } catch (error) {
                console.error('Error initializing map view:', error);
                // Show fallback content
                mapContainer.innerHTML = `
                    <div class="flex items-center justify-center h-64 bg-gray-100 rounded-lg">
                        <div class="text-center text-gray-500">
                            <i class="fas fa-map text-3xl mb-2"></i>
                            <p>Map could not be loaded</p>
                        </div>
                    </div>
                `;
            }
        }

        async loadMapProjects() {
            try {
                const urlParams = new URLSearchParams(window.location.search);
                const baseUrl = window.BASE_URL || './';
                
                const response = await fetch(`${baseUrl}api/projects.php?map=1&${urlParams.toString()}`);
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
                    return;
                }

                const markers = [];
                validProjects.forEach(project => {
                    const marker = this.addProjectMarker(project);
                    if (marker) {
                        markers.push(marker);
                    }
                });

                if (markers.length > 0) {
                    const group = new L.featureGroup(markers);
                    this.mapInstance.fitBounds(group.getBounds().pad(0.1));
                }

            } catch (error) {
                console.error('Error loading map projects:', error);
            }
        }

        addProjectMarker(project) {
            if (!this.mapInstance || !project.location_coordinates) {
                return null;
            }

            try {
                const coords = this.parseCoordinates(project.location_coordinates);
                if (!coords || coords.length !== 2) {
                    return null;
                }

                const [lat, lng] = coords;
                if (isNaN(lat) || isNaN(lng)) {
                    return null;
                }

                const statusColors = {
                    'ongoing': '#3b82f6',
                    'completed': '#10b981',
                    'planning': '#f59e0b',
                    'suspended': '#f97316',
                    'cancelled': '#ef4444'
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

                const popupContent = this.createPopupContent(project);
                marker.bindPopup(popupContent, {
                    maxWidth: 300,
                    className: 'custom-popup'
                });

                marker.addTo(this.mapInstance);
                return marker;

            } catch (error) {
                console.error(`Error adding marker for project ${project.id}:`, error);
                return null;
            }
        }

        parseCoordinates(coordinateString) {
            if (!coordinateString) return null;

            try {
                if (coordinateString.startsWith('[')) {
                    return JSON.parse(coordinateString);
                }

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
                return null;
            }
        }

        createPopupContent(project) {
            const statusBadge = this.getStatusBadgeClass(project.status);
            
            return `
                <div class="p-3 min-w-0">
                    <div class="flex items-start justify-between mb-2">
                        <h4 class="font-semibold text-gray-900 text-sm leading-tight pr-2">
                            ${this.escapeHtml(project.project_name)}
                        </h4>
                        <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${statusBadge} whitespace-nowrap">
                            ${project.status.charAt(0).toUpperCase() + project.status.slice(1)}
                        </span>
                    </div>
                    
                    <div class="space-y-1 text-xs text-gray-600">
                        <div>
                            <span class="font-medium">Department:</span> ${this.escapeHtml(project.department_name)}
                        </div>
                        <div>
                            <span class="font-medium">Location:</span> ${this.escapeHtml(project.ward_name)}, ${this.escapeHtml(project.sub_county_name)}
                        </div>
                        
                        ${project.progress_percentage > 0 ? `
                            <div class="mt-2">
                                <div class="flex items-center justify-between mb-1">
                                    <span class="font-medium">Progress:</span>
                                    <span>${project.progress_percentage}%</span>
                                </div>
                                <div class="w-full bg-gray-200 rounded-full h-1.5">
                                    <div class="h-1.5 rounded-full ${this.getProgressColor(project.progress_percentage)}" 
                                         style="width: ${project.progress_percentage}%"></div>
                                </div>
                            </div>
                        ` : ''}
                    </div>
                    
                    <div class="flex space-x-2 mt-3">
                        <button onclick="window.location.href='${window.BASE_URL || './'}projectDetails/${project.id}'" 
                                class="flex-1 bg-blue-600 text-white text-xs px-2 py-1 rounded hover:bg-blue-700 transition-colors">
                            <i class="fas fa-eye mr-1"></i>Details
                        </button>
                        <button onclick="if(window.showFeedbackForm) window.showFeedbackForm(${project.id});" 
                                class="flex-1 bg-green-600 text-white text-xs px-2 py-1 rounded hover:bg-green-700 transition-colors">
                            <i class="fas fa-comment mr-1"></i>Feedback
                        </button>
                    </div>
                </div>
            `;
        }

        getStatusBadgeClass(status) {
            const classes = {
                planning: 'bg-yellow-100 text-yellow-800',
                ongoing: 'bg-blue-100 text-blue-800',
                completed: 'bg-green-100 text-green-800',
                suspended: 'bg-orange-100 text-orange-800',
                cancelled: 'bg-red-100 text-red-800'
            };
            return classes[status] || 'bg-gray-100 text-gray-800';
        }

        getProgressColor(percentage) {
            if (percentage >= 80) return 'bg-green-500';
            if (percentage >= 60) return 'bg-blue-500';
            if (percentage >= 40) return 'bg-yellow-500';
            if (percentage >= 20) return 'bg-orange-500';
            return 'bg-red-500';
        }

        escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    };
}

// Global functions for HTML onclick handlers
window.showProjectDetails = function (projectId) {
    if (window.projectManager) {
        window.projectManager.showProjectDetails(projectId);
    }
};

window.closeProjectDetails = function () {
    if (window.projectManager) {
        window.projectManager.closeProjectDetails();
    }
};

window.showFeedbackForm = function (projectId) {
    if (window.feedbackManager) {
        window.feedbackManager.showFeedbackForm(projectId);
    }
};

window.closeFeedbackForm = function () {
    if (window.feedbackManager) {
        window.feedbackManager.closeFeedbackForm();
    }
};

window.submitFeedback = function (event) {
    if (window.feedbackManager) {
        return window.feedbackManager.submitFeedback(event);
    }
};

window.exportPDF = function () {
    return window.ExportManager.exportPDF();
};

window.exportCSV = function () {
    return window.ExportManager.exportCSV();
};

window.openFeedbackModal = function (projectId) {
    if (window.feedbackManager) {
        window.feedbackManager.showFeedbackForm(projectId);
    }
};

window.closeFeedbackModal = function () {
    if (window.feedbackManager) {
        window.feedbackManager.closeFeedbackForm();
    }
};

// View switching function
window.switchView = function(view) {
    if (window.viewManager) {
        window.viewManager.switchView(view);
    }
};

window.applyFilters = function () {
    const departmentFilter = document.getElementById("departmentFilter");
    const statusFilter = document.getElementById("statusFilter");
    const yearFilter = document.getElementById("yearFilter");

    const departmentId = departmentFilter ? departmentFilter.value : "";
    const status = statusFilter ? statusFilter.value : "";
    const year = yearFilter ? yearFilter.value : "";

    const params = new URLSearchParams(window.location.search);

    if (departmentId) {
        params.set("department", departmentId);
    } else {
        params.delete("department");
    }

    if (status) {
        params.set("status", status);
    } else {
        params.delete("status");
    }

    if (year) {
        params.set("year", year);
    } else {
        params.delete("year");
    }

    window.location.href = window.location.pathname + "?" + params.toString();
};

// Security validation
window.validateProjectAccess = async function (projectId, action = "view") {
    try {
        const response = await fetch(
            `../api/validateProjectAccess.php?project_id=${projectId}&action=${action}`,
        );
        const data = await response.json();

        if (!data.access) {
            window.location.href = "projects.php?error=access_denied";
            return false;
        }

        return true;
    } catch (error) {
        console.error("Project access validation failed:", error);
        return false;
    }
};

// Map preview functionality
function initializeMapPreviews() {
    if (typeof L === 'undefined') {
        return;
    }

    // Initialize map previews for project cards
    const mapPreviews = document.querySelectorAll('[id^="map-preview-"]');
    mapPreviews.forEach(mapDiv => {
        const projectId = mapDiv.id.replace('map-preview-', '');
        const projectCard = mapDiv.closest('.project-card, .project-card-modern');
        
        if (projectCard) {
            // Get project data from the card
            const projectName = projectCard.querySelector('.project-title, h3, .font-semibold')?.textContent;
            const location = projectCard.querySelector('.project-location, .text-gray-600')?.textContent;
            
            // Initialize preview with available data
            initializeProjectMapPreview(mapDiv, projectId, projectName, location);
        }
    });
}

function initializeProjectMapPreview(mapDiv, projectId, projectName, location) {
    try {
        // Clear any existing Leaflet instance
        if (mapDiv._leaflet_id) {
            delete mapDiv._leaflet_id;
        }
        mapDiv.innerHTML = '';

        // Initialize a small map for preview
        const map = L.map(mapDiv, {
            zoomControl: false,
            scrollWheelZoom: false,
            doubleClickZoom: false,
            dragging: false,
            attributionControl: false
        }).setView([-1.0634, 34.4738], 12);

        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '',
            maxZoom: 18
        }).addTo(map);

        // Add a generic marker for preview
        const marker = L.marker([-1.0634, 34.4738]).addTo(map);
        
        // Add click handler to go to project details
        mapDiv.addEventListener('click', function(e) {
            e.preventDefault();
            const baseUrl = window.BASE_URL || './';
            window.location.href = `${baseUrl}projectDetails/${projectId}`;
        });

    } catch (error) {
        console.error('Error initializing map preview:', error);
        // Show placeholder content
        mapDiv.innerHTML = `
            <div class="w-full h-full bg-gray-100 flex items-center justify-center cursor-pointer" onclick="window.location.href='${window.BASE_URL || './'}projectDetails/${projectId}'">
                <div class="text-center text-gray-500">
                    <i class="fas fa-map-marker-alt text-2xl mb-2"></i>
                    <p class="text-sm">Map Preview</p>
                </div>
            </div>
        `;
    }
}

// Initialize when DOM is loaded
document.addEventListener("DOMContentLoaded", function () {
    // Initialize theme manager for public pages only
    if (!window.location.pathname.includes("/admin/")) {
        if (!window.publicThemeManager) {
            window.publicThemeManager = new window.PublicThemeManager();
        }
    }

    // Initialize managers only if not already initialized
    if (!window.projectManager) {
        window.projectManager = new window.ProjectManager();
    }

    if (!window.feedbackManager) {
        window.feedbackManager = new window.FeedbackManager();
    }

    if (!window.mobileMenuManager) {
        window.mobileMenuManager = new window.MobileMenuManager();
    }

    if (!window.viewManager) {
        window.viewManager = new window.ViewManager();
    }

    // Wait for Leaflet to be available before initializing map previews
    if (typeof L !== 'undefined') {
        setTimeout(() => {
            initializeMapPreviews();
        }, 500);
    }

    // Validate project links
    const projectLinks = document.querySelectorAll("a[data-project-id]");
    projectLinks.forEach((link) => {
        link.addEventListener("click", async function (e) {
            const projectId = this.dataset.projectId;
            const action = this.dataset.action || "view";

            if (!(await window.validateProjectAccess(projectId, action))) {
                e.preventDefault();
                return false;
            }
        });
    });

    // Scroll to top functionality
    const scrollToTopBtn = document.getElementById("scrollToTop");
    if (scrollToTopBtn) {
        window.addEventListener("scroll", function () {
            if (window.pageYOffset > 300) {
                scrollToTopBtn.classList.add("opacity-100", "visible");
                scrollToTopBtn.classList.remove(
                    "opacity-0",
                    "invisible",
                    "translate-y-4",
                );
            } else {
                scrollToTopBtn.classList.add(
                    "opacity-0",
                    "invisible",
                    "translate-y-4",
                );
                scrollToTopBtn.classList.remove("opacity-100", "visible");
            }
        });

        scrollToTopBtn.addEventListener("click", function () {
            window.scrollTo({
                top: 0,
                behavior: "smooth",
            });
        });
    }
});
