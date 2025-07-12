</main>
</div>

<!-- Admin Footer -->
<footer class="bg-white border-t border-gray-200 py-3 px-6" aria-label="Admin footer">
    <div class="flex items-center justify-between text-sm text-gray-500">
        <div>
            <span>&copy; <?php echo date('Y'); ?> Migori County Government. All rights reserved.</span>
        </div>
        <div class="flex items-center space-x-4">
            <span>PMC Portal v2.0</span>
            <span aria-hidden="true">•</span>
            <span>Last login: <?php echo !empty($_SESSION['user_last_login']) ? formatDateTime($_SESSION['user_last_login']) : 'Never'; ?></span>
        </div>
    </div>
</footer>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    // Let main.js handle mobile menu initialization
    
    // Auto-refresh stats if on dashboard
    if (typeof updateStats === 'function') {
        setInterval(updateStats, 30000);
        updateStats(); // Initial load
    }
});

async function updateStats() {
    try {
        const response = await fetch('ajax/getDashboardStats.php');
        if (!response.ok) throw new Error('Network response was not ok');
        const data = await response.json();
        
        // Update stats if elements exist
        const stats = {
            'totalProjects': data.totalProjects || 0,
            'activeProjects': data.activeProjects || 0,
            'completedProjects': data.completedProjects || 0,
            'pendingFeedback': data.pendingFeedback || 0
        };
        
        Object.entries(stats).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) element.textContent = value;
        });
    } catch (error) {
        console.error('Error updating stats:', error);
    }
}
</script>

<?php if (!empty($additional_js) && is_array($additional_js)): ?>
    <?php foreach ($additional_js as $js_file): ?>
        <script src="<?php echo htmlspecialchars($js_file, ENT_QUOTES); ?>" defer></script>
    <?php endforeach; ?>
<?php endif; ?>

<script src="<?php echo htmlspecialchars(BASE_URL, ENT_QUOTES); ?>assets/js/main.js" defer></script>
</body>
</html>