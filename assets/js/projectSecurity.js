
/**
 * Frontend project security validation
 * Note: This is supplementary to backend validation - never rely solely on frontend checks
 */

async function validateProjectAccess(projectId, action = 'view') {
    try {
        const response = await fetch(`../api/validateProjectAccess.php?project_id=${projectId}&action=${action}`);
        const data = await response.json();
        
        if (!data.access) {
            // Redirect to projects page if access denied
            window.location.href = 'projects.php?error=access_denied';
            return false;
        }
        
        return true;
    } catch (error) {
        console.error('Project access validation failed:', error);
        return false;
    }
}

// Validate project links before navigation
document.addEventListener('DOMContentLoaded', function() {
    const projectLinks = document.querySelectorAll('a[data-project-id]');
    
    projectLinks.forEach(link => {
        link.addEventListener('click', async function(e) {
            const projectId = this.dataset.projectId;
            const action = this.dataset.action || 'view';
            
            if (!await validateProjectAccess(projectId, action)) {
                e.preventDefault();
                return false;
            }
        });
    });
});
