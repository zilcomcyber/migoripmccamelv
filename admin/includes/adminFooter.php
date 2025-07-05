            </main>
        </div>

        <!-- Admin Footer -->
        <footer class="bg-white border-t border-gray-200 py-3 px-6">
            <div class="flex items-center justify-between text-sm text-gray-500">
                <div>
                    <span>&copy; <?php echo date('Y'); ?> Migori County Government. All rights reserved.</span>
                </div>
                <div class="flex items-center space-x-4">
                    <span>PMC Portal v2.0</span>
                    <span>•</span>
                    <span>Last login: <?php echo date('M d, Y H:i'); ?></span>
                </div>
            </div>
        </footer>
    </div>

    <!-- Mobile Menu Toggle Script -->
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const mobileMenuToggle = document.getElementById('mobile-menu-toggle');
            const mobileSidebar = document.getElementById('mobile-sidebar');
            const mobileOverlay = document.getElementById('mobile-sidebar-overlay');
            
            function toggleMobileMenu() {
                mobileSidebar.classList.toggle('active');
                mobileOverlay.classList.toggle('active');
            }
            
            mobileMenuToggle.addEventListener('click', toggleMobileMenu);
            mobileOverlay.addEventListener('click', toggleMobileMenu);
            
            // Auto-refresh stats every 30 seconds
            if (typeof updateStats === 'function') {
                setInterval(updateStats, 30000);
            }
        });
    </script>

    <?php if (isset($additional_js) && is_array($additional_js)): ?>
        <?php foreach ($additional_js as $js_file): ?>
            <script src="<?php echo $js_file; ?>"></script>
        <?php endforeach; ?>
    <?php endif; ?>
</body>
</html>