</main>

<footer class="relative mt-20 overflow-hidden">
    <!-- Footer Background with Gradient -->
    <div class="absolute inset-0 bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900"></div>
    <div class="absolute inset-0 bg-gradient-to-r from-blue-900/20 via-purple-900/20 to-green-900/20"></div>

    <!-- Animated Background Elements -->
    <div class="absolute inset-0 overflow-hidden">
        <div class="absolute -top-40 -right-40 w-80 h-80 bg-blue-500/10 rounded-full blur-3xl animate-pulse"></div>
        <div class="absolute -bottom-40 -left-40 w-80 h-80 bg-purple-500/10 rounded-full blur-3xl animate-pulse" style="animation-delay: 2s;"></div>
        <div class="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-60 h-60 bg-green-500/10 rounded-full blur-3xl animate-pulse" style="animation-delay: 4s;"></div>
    </div>

    <div class="relative z-10">
        <div class="max-w-7xl mx-auto px-4 py-16 sm:px-6 lg:px-8">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-12 lg:gap-8">
                <!-- Brand Section -->
                <div class="lg:col-span-2">
                    <div class="flex items-center space-x-4 mb-6">
                        <div class="relative">
                            <img src="<?php echo BASE_URL; ?>migoriLogo.png" alt="County Logo" class="h-12 w-12 rounded-xl shadow-lg">
                            <div class="absolute inset-0 rounded-xl bg-gradient-to-br from-blue-400/20 to-purple-500/20"></div>
                        </div>
                        <div>
                            <h3 class="text-2xl font-bold"><span class="text-white"><?php echo APP_NAME; ?></span></h3>
                            <p class="text-gray-200">Migori County Government</p>
                        </div>
                    </div>
                    <p class="text-gray-200 mb-8 max-w-md leading-relaxed">
                        Promoting transparency and accountability in county development projects. 
                        Stay informed about ongoing and completed projects that are transforming our communities.
                    </p>
                    <div class="flex space-x-4">
                        <a href="https://www.facebook.com/steve.deeq3r" target="_blank" class="group p-3 bg-white/10 hover:bg-white/20 rounded-xl transition-all duration-300 backdrop-blur-sm">
                            <i class="fab fa-facebook-f text-white group-hover:text-blue-400 transition-colors duration-300"></i>
                        </a>
                        <a href="https://x.com/lakesidekenya" target="_blank" class="group p-3 bg-white/10 hover:bg-white/20 rounded-xl transition-all duration-300 backdrop-blur-sm">
                            <i class="fab fa-twitter text-white group-hover:text-blue-400 transition-colors duration-300"></i>
                        </a>
                        <a href="#" class="group p-3 bg-white/10 hover:bg-white/20 rounded-xl transition-all duration-300 backdrop-blur-sm">
                            <i class="fab fa-instagram text-white group-hover:text-pink-400 transition-colors duration-300"></i>
                        </a>
                        <a href="#" class="group p-3 bg-white/10 hover:bg-white/20 rounded-xl transition-all duration-300 backdrop-blur-sm">
                            <i class="fab fa-linkedin text-white group-hover:text-blue-500 transition-colors duration-300"></i>
                        </a>
                    </div>
                </div>

                <!-- Quick Links -->
                <div>
                    <h4 class="text-lg font-semibold text-white mb-6 flex items-center">
                        <i class="fas fa-link mr-2 text-blue-400"></i>
                        <span class="text-white">Quick Links</span>
                    </h4>
                    <ul class="space-y-3">
                        <li>
                            <a href="<?php echo BASE_URL; ?>index.php" 
                               class="text-white hover:text-blue-400 transition-colors duration-300 flex items-center group">
                                <i class="fas fa-chevron-right mr-2 text-xs opacity-0 group-hover:opacity-100 transition-all duration-300 transform group-hover:translate-x-1"></i>
                                <span class="text-white">All Projects</span>
                            </a>
                        </li>
                        <li>
                            <a href="<?php echo BASE_URL; ?>?view=grid&status=ongoing" 
                               class="text-white hover:text-blue-400 transition-colors duration-300 flex items-center group">
                                <i class="fas fa-chevron-right mr-2 text-xs opacity-0 group-hover:opacity-100 transition-all duration-300 transform group-hover:translate-x-1"></i>
                                <span class="text-white">Ongoing Projects</span>
                            </a>
                        </li>
                        <li>
                            <a href="<?php echo BASE_URL; ?>?view=grid&status=completed" 
                               class="text-white hover:text-blue-400 transition-colors duration-300 flex items-center group">
                                <i class="fas fa-chevron-right mr-2 text-xs opacity-0 group-hover:opacity-100 transition-all duration-300 transform group-hover:translate-x-1"></i>
                                <span class="text-white">Completed Projects</span>
                            </a>
                        </li>
                        <li>
                            <a href="<?php echo BASE_URL; ?>?view=grid&status=planning" 
                               class="text-white hover:text-blue-400 transition-colors duration-300 flex items-center group">
                                <i class="fas fa-chevron-right mr-2 text-xs opacity-0 group-hover:opacity-100 transition-all duration-300 transform group-hover:translate-x-1"></i>
                                <span class="text-white">Planning Projects</span>
                            </a>
                        </li>
                        <?php if (isset($_SESSION['admin']) && $_SESSION['admin']): ?>
                        <li>
                            <a href="<?php echo BASE_URL; ?>admin/feedback.php" 
                               class="text-white hover:text-blue-400 transition-colors duration-300 flex items-center group">
                                <i class="fas fa-chevron-right mr-2 text-xs opacity-0 group-hover:opacity-100 transition-all duration-300 transform group-hover:translate-x-1"></i>
                                <span class="text-white">Citizen Feedback</span>
                            </a>
                        </li>
                        <?php endif; ?>
                    </ul>
                </div>

                <!-- Contact Info -->
                <div>
                    <h4 class="text-lg font-semibold text-white mb-6 flex items-center">
                        <i class="fas fa-address-book mr-2 text-green-400"></i>
                        <span class="text-white">Contact Us</span>
                    </h4>
                    <ul class="space-y-4 text-white">
                        <li class="flex items-start space-x-3 group">
                            <div class="flex-shrink-0 p-2 bg-blue-500/20 rounded-lg group-hover:bg-blue-500/30 transition-colors duration-300">
                                <i class="fas fa-map-marker-alt text-blue-400"></i>
                            </div>
                            <div>
                                <div class="font-medium text-white">Migori County Government</div>
                                <div class="text-sm text-gray-200">P.O. Box 151, Migori</div>
                            </div>
                        </li>
                        <li class="flex items-center space-x-3 group">
                            <div class="flex-shrink-0 p-2 bg-green-500/20 rounded-lg group-hover:bg-green-500/30 transition-colors duration-300">
                                <i class="fas fa-phone text-green-400"></i>
                            </div>
                            <span class="text-white">+254 020 123 4567</span>
                        </li>
                        <li class="flex items-center space-x-3 group">
                            <div class="flex-shrink-0 p-2 bg-purple-500/20 rounded-lg group-hover:bg-purple-500/30 transition-colors duration-300">
                                <i class="fas fa-envelope text-purple-400"></i>
                            </div>
                            <span class="text-white">info@migori.go.ke</span>
                        </li>
                        <li class="flex items-center space-x-3 group">
                            <div class="flex-shrink-0 p-2 bg-orange-500/20 rounded-lg group-hover:bg-orange-500/30 transition-colors duration-300">
                                <i class="fas fa-globe text-orange-400"></i>
                            </div>
                            <span class="text-white">www.migori.go.ke</span>
                        </li>
                    </ul>
                </div>
            </div>

            <!-- Newsletter Section -->
            <div class="mt-12 p-8 bg-white/5 backdrop-blur-sm rounded-2xl border border-white/10">
                <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-6">
                    <div>
                        <h4 class="text-xl font-semibold mb-2"><span class="text-white">Stay Updated</span></h4>
                        <p class="text-white">Get the latest updates on county development projects delivered to your inbox.</p>
                    </div>
                    <div class="w-full md:min-w-96 flex flex-col gap-3">
                        <input type="email" placeholder="Enter your email address" 
                               class="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent backdrop-blur-sm">
                        <button class="w-full btn-modern btn-primary-modern">
                            <i class="fas fa-paper-plane"></i>
                            Subscribe
                        </button>
                    </div>
                </div>
            </div>

            <!-- Bottom Section -->
            <div class="border-t border-white/10 mt-12 pt-8 flex flex-col md:flex-row justify-between items-center gap-6">
                <p class="text-white text-center md:text-left">
                    © <?php echo date('Y'); ?> Migori County Government. All rights reserved.
                </p>
                <div class="flex flex-wrap justify-center md:justify-end gap-6">
                    <a href="#" class="text-white hover:text-blue-400 transition-colors duration-300">
                        <span class="text-white hover:text-blue-400">Privacy Policy</span>
                    </a>
                    <a href="#" class="text-white hover:text-blue-400 transition-colors duration-300">
                        <span class="text-white hover:text-blue-400">Terms of Service</span>
                    </a>
                    <a href="#" class="text-white hover:text-blue-400 transition-colors duration-300">
                        <span class="text-white hover:text-blue-400">Accessibility</span>
                    </a>
                    <a href="#" class="text-white hover:text-blue-400 transition-colors duration-300">
                        <span class="text-white hover:text-blue-400">Cookie Policy</span>
                    </a>
                </div>
            </div>
        </div>
    </div>
</footer>

<!-- Scripts -->
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" 
        integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" 
        crossorigin=""></script>

<!-- Consolidated JS files -->
<?php if (isset($is_admin_page) && $is_admin_page): ?>
<!-- Admin JS with Chart.js if needed -->
<?php if (basename($_SERVER['PHP_SELF']) === 'index.php' || basename($_SERVER['PHP_SELF']) === 'dashboard.php'): ?>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<?php endif; ?>
<script src="<?php echo BASE_URL; ?>assets/js/main.js?v=<?php echo file_exists(__DIR__ . '/../assets/js/main.js') ? filemtime(__DIR__ . '/../assets/js/main.js') : time(); ?>"></script>
<?php else: ?>
<!-- Public JS -->
<script src="<?php echo BASE_URL; ?>assets/js/app.js?v=<?php echo file_exists(__DIR__ . '/../assets/js/app.js') ? filemtime(__DIR__ . '/../assets/js/app.js') : time(); ?>"></script>
<?php endif; ?>

<!-- Load map JS only when needed -->
<?php if (isset($load_map) && $load_map || basename($_SERVER['PHP_SELF']) === 'projectDetails.php' || strpos($_SERVER['REQUEST_URI'], 'projectDetails') !== false): ?>
<script src="<?php echo BASE_URL; ?>assets/js/map.js?v=<?php echo file_exists(__DIR__ . '/../assets/js/map.js') ? filemtime(__DIR__ . '/../assets/js/map.js') : time(); ?>"></script>
<?php endif; ?>

<?php if (isset($additional_js)): ?>
    <?php foreach ($additional_js as $js): ?>
        <script src="<?php echo $js; ?>?v=<?php echo time(); ?>"></script>
    <?php endforeach; ?>
<?php endif; ?>

<!-- Initialize global variables and functions -->
<script>
// Make projects data available to JavaScript
window.projectsData = <?php 
    echo isset($all_projects) && !empty($all_projects) 
        ? json_encode($all_projects, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) 
        : '[]'; 
?>;

// Initialize application when DOM is fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize scroll progress indicator
    const scrollIndicator = document.querySelector('.scroll-indicator');
    if (scrollIndicator) {
        window.addEventListener('scroll', () => {
            const scrolled = window.pageYOffset;
            const maxHeight = document.body.scrollHeight - window.innerHeight;
            const progress = scrolled / maxHeight;
            scrollIndicator.style.setProperty('--scroll-progress', progress);
        });
    }

    // Initialize stagger animations
    const cards = document.querySelectorAll('.fade-in-up');
    cards.forEach((card, index) => {
        card.style.animationDelay = `${index * 0.1}s`;
    });

    // Initialize scroll-to-top button
    const scrollToTopBtn = document.getElementById('scrollToTop');
    if (scrollToTopBtn) {
        window.addEventListener('scroll', function() {
            if (window.pageYOffset > 300) {
                scrollToTopBtn.classList.remove('opacity-0', 'invisible', 'translate-y-4');
                scrollToTopBtn.classList.add('opacity-100', 'visible', 'translate-y-0');
            } else {
                scrollToTopBtn.classList.add('opacity-0', 'invisible', 'translate-y-4');
                scrollToTopBtn.classList.remove('opacity-100', 'visible', 'translate-y-0');
            }
        });

        scrollToTopBtn.addEventListener('click', function() {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
    }

    // Initialize feedback form
    const feedbackForm = document.getElementById('feedbackForm');
    if (feedbackForm) {
        feedbackForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const formData = new FormData(this);

            try {
                const response = await fetch('api/feedback.php', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();
                alert(data.message || (data.success ? 'Feedback submitted successfully!' : 'Failed to submit feedback'));

                if (data.success) {
                    closeFeedbackModal();
                }
            } catch (error) {
                console.error('Error submitting feedback:', error);
                alert('Failed to submit feedback');
            }
        });
    }

    // Initialize mobile menu toggle
    const mobileMenuButton = document.getElementById('mobile-menu-button');
    if (mobileMenuButton) {
        mobileMenuButton.addEventListener('click', function() {
            const mobileMenu = document.getElementById('mobile-menu');
            if (mobileMenu) {
                mobileMenu.classList.toggle('hidden');
            }
        });
    }

    // Initialize theme toggle
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            const html = document.documentElement;
            const isDark = html.classList.contains('dark');

            if (isDark) {
                html.classList.remove('dark');
                localStorage.setItem('theme', 'light');
            } else {
                html.classList.add('dark');
                localStorage.setItem('theme', 'dark');
            }
        });

        // Initialize theme from localStorage
        const savedTheme = localStorage.getItem('theme');
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

        if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
            document.documentElement.classList.add('dark');
        }
    }

    // Initialize header scroll effect
    const header = document.querySelector('header');
    if (header) {
        window.addEventListener('scroll', function() {
            const scrolled = window.pageYOffset;
            if (scrolled > 50) {
                header.style.background = 'rgba(255, 255, 255, 0.95)';
                header.style.backdropFilter = 'blur(20px)';
            } else {
                header.style.background = 'rgba(255, 255, 255, 0.25)';
                header.style.backdropFilter = 'blur(20px)';
            }
        });
    }
});

// Global functions
window.openFeedbackModal = function(projectId) {
    const modal = document.getElementById('feedbackModal');
    const projectIdField = document.getElementById('feedbackProjectId');
    if (modal && projectIdField) {
        projectIdField.value = projectId;
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }
};

window.closeFeedbackModal = function() {
    const modal = document.getElementById('feedbackModal');
    const feedbackForm = document.getElementById('feedbackForm');
    if (modal) {
        modal.classList.add('hidden');
        if (feedbackForm) feedbackForm.reset();
        document.body.style.overflow = 'auto';
    }
};

window.parseCoordinates = function(coordinateString) {
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
        // Silently handle coordinate parsing errors in production
        return null;
    }
};

</script>

<!-- Modern Scripts loaded above -->
</body>
</html>