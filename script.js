// --- Modal Functions ---
function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'block';
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
    }
}

// Show error message
function showAlertMessage(message, type = 'error') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.textContent = message;
    
    document.body.appendChild(alertDiv);
    
    setTimeout(() => {
        alertDiv.remove();
    }, 3000);
}

// Format date
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });
}

// Format time
function formatTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Calculate progress percentage
function calculateProgress(completed, total) {
    if (total === 0) return 0;
    return Math.round((completed / total) * 100);
}

// Generate random ID
function generateId() {
    return Math.random().toString(36).substr(2, 9);
}

// Check if user is logged in
function isLoggedIn() {
    return !!getAuthToken();
}

// Check if admin is logged in
function isAdminLoggedIn() {
    return localStorage.getItem('isAdminLoggedIn') === 'true' && getAuthToken();
}

// Get current user
function getCurrentUser() {
    const userData = JSON.parse(localStorage.getItem('currentUser'));
    return userData;
}

// Logout function
function logout() {
    localStorage.removeItem('isLoggedIn');
    localStorage.removeItem('currentUser');
    localStorage.removeItem('isAdminLoggedIn');
    localStorage.removeItem('token');
    window.location.href = 'index.html';
}

// Listen for storage changes to enable cross-tab logout
window.addEventListener('storage', function(event) {
    // When 'isLoggedIn' is removed or set to 'false' in another tab,
    // log out this tab as well by reloading the page.
    // The page's own auth check will then handle the redirect.
    if (event.key === 'isLoggedIn' && (event.newValue === null || event.newValue === 'false')) {
        window.location.reload();
    }
});

// Redirect if not logged in
function requireLogin() {
    if (!isLoggedIn()) {
        window.location.href = 'login.html';
        return false;
    }
    return true;
}

// Redirect if not admin
function requireAdmin() {
    if (!isAdminLoggedIn()) {
        window.location.href = 'login.html';
        return false;
    }
    return true;
}

// Add activity to user's activity log
function addActivity(type, message, description) {
    // This is now a fire-and-forget call to the backend.
    // The dashboard will sync activities on load.
    apiPost('/api/activity', {
        type: type,
        message: message,
        description: description
    }).catch(err => console.error("Failed to log activity:", err));
}

// Utility function to debounce function calls
function debounce(func, wait) {
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

// Utility function to throttle function calls
function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// Animate progress bar
function animateProgressBar(elementId, targetWidth, duration = 1000) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const startWidth = 0;
    const increment = targetWidth / (duration / 16);
    let currentWidth = startWidth;
    
    const timer = setInterval(() => {
        currentWidth += increment;
        element.style.width = currentWidth + '%';
        
        if (currentWidth >= targetWidth) {
            element.style.width = targetWidth + '%';
            clearInterval(timer);
        }
    }, 16);
}

// Show loading spinner
function showLoading(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = '<div class="spinner"></div>';
    }
}

// Hide loading spinner
function hideLoading(elementId, content = '') {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = content;
    }
}

// Copy text to clipboard
function copyToClipboard(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            showAlertMessage('Copied to clipboard!', 'success');
        }).catch(() => {
            showAlertMessage('Failed to copy to clipboard', 'error');
        });
    } else {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        try {
            document.execCommand('copy');
            showAlertMessage('Copied to clipboard!', 'success');
        } catch (err) {
            showAlertMessage('Failed to copy to clipboard', 'error');
        }
        document.body.removeChild(textArea);
    }
}

// Format currency
function formatCurrency(amount, currency = 'ETB') {
    return new Intl.NumberFormat('en-ET', {
        style: 'currency',
        currency: currency
    }).format(amount);
}

// Format number
function formatNumber(number) {
    return new Intl.NumberFormat('en-ET').format(number);
}

// Get time ago
function getTimeAgo(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diffInSeconds = Math.floor((now - date) / 1000);
    
    if (diffInSeconds < 60) {
        return 'Just now';
    } else if (diffInSeconds < 3600) {
        const minutes = Math.floor(diffInSeconds / 60);
        return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    } else if (diffInSeconds < 86400) {
        const hours = Math.floor(diffInSeconds / 3600);
        return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    } else {
        const days = Math.floor(diffInSeconds / 86400);
        return `${days} day${days > 1 ? 's' : ''} ago`;
    }
}

// Validate email
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

// Validate password strength
function validatePassword(password) {
    const minLength = 6;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    
    return {
        isValid: password.length >= minLength,
        minLength: password.length >= minLength,
        hasUpperCase: hasUpperCase,
        hasLowerCase: hasLowerCase,
        hasNumbers: hasNumbers
    };
}

// Generate random color
function generateRandomColor() {
    const colors = ['#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c', '#e67e22', '#34495e'];
    return colors[Math.floor(Math.random() * colors.length)];
}

// Check if device is mobile
function isMobile() {
    return window.innerWidth <= 768;
}

// Check if device is tablet
function isTablet() {
    return window.innerWidth > 768 && window.innerWidth <= 1024;
}

// Check if device is desktop
function isDesktop() {
    return window.innerWidth > 1024;
}

// Initialize tooltips
function initTooltips() {
    const tooltipElements = document.querySelectorAll('[data-tooltip]');
    
    tooltipElements.forEach(element => {
        element.addEventListener('mouseenter', function() {
            const tooltip = document.createElement('div');
            tooltip.className = 'tooltip';
            tooltip.textContent = this.getAttribute('data-tooltip');
            document.body.appendChild(tooltip);
            
            const rect = this.getBoundingClientRect();
            tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
            tooltip.style.top = rect.top - tooltip.offsetHeight - 5 + 'px';
        });
        
        element.addEventListener('mouseleave', function() {
            const tooltip = document.querySelector('.tooltip');
            if (tooltip) {
                tooltip.remove();
            }
        });
    });
}

function toggleMobileMenu() {
    const hamburger = document.querySelector('.hamburger');
    const navMenu = document.querySelector('.nav-menu');
    hamburger.classList.toggle('active');
    navMenu.classList.toggle('active');
}

// Initialize all common functionality
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips (if any)
    initTooltips();
    
    // Bind hamburger globally
    const hamburger = document.querySelector('.hamburger');
    if (hamburger) {
        hamburger.addEventListener('click', toggleMobileMenu);
    }
    
    // Add smooth scrolling to all anchor links (only if target exists)
    const anchorLinks = document.querySelectorAll('a[href^="#"]');
    anchorLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            const target = document.querySelector(this.getAttribute('href'));
            if (!target) return;
            e.preventDefault();
            target.scrollIntoView({ behavior: 'smooth' });
        });
    });
    
    // Add fade-in animation to elements with fade-in class
    const fadeElements = document.querySelectorAll('.fade-in');
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    });
    
    fadeElements.forEach(element => {
        element.style.opacity = '0';
        element.style.transform = 'translateY(20px)';
        element.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(element);
    });
});

// Export functions for use in other scripts
window.LuminarSchool = {
    showAlertMessage,    
    isLoggedIn,
    isAdminLoggedIn,
    getCurrentUser,
    logout,
    addActivity,
    debounce,
    throttle,
    animateProgressBar,
    showLoading,
    hideLoading,
    copyToClipboard,
    formatCurrency,
    formatNumber,
    getTimeAgo,
    validateEmail,
    validatePassword,
    generateRandomColor,
    isMobile,
    isTablet,
    isDesktop,
    syncAndGetCurrentUser
};

// Free Trial helpers
function startFreeTrial() {
    // Mark trial status and allow limited access without registration
    localStorage.setItem('trialActive', 'true');
    localStorage.setItem('trialStream', '');
    // Redirect to stream selection (trial allowed)
    window.location.href = 'stream-selection.html';
}

// API Auth helpers
function setAuthToken(token) {
    if (token) {
        localStorage.setItem('token', token);
    }
}

function getAuthToken() {
    return localStorage.getItem('token');
}

function getAuthHeaders() {
    const token = getAuthToken();
    return token ? { 'Authorization': 'Bearer ' + token } : {};
}

async function apiPost(path, body, extraHeaders = {}) {
    const res = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders(), ...extraHeaders },
        body: JSON.stringify(body)
    });
    return res;
}

async function apiGet(path) {
    const res = await fetch(path, { headers: getAuthHeaders() });
    return res;
}

function isTrialActive() {
    return localStorage.getItem('trialActive') === 'true';
}

function endTrial() {
    localStorage.removeItem('trialActive');
    localStorage.removeItem('trialStream');
}

async function syncAndGetCurrentUser() {
    // This function is now the single source of truth for user session data.
    // It fetches everything from the backend and populates localStorage as a cache.
    const token = getAuthToken();
    if (!token) {
        // If there's no token, it's a guest or trial user. Don't log them out.
        return null; 
    }
    try {
        const res = await apiGet('/api/me');
        if (!res.ok) {
            // If the /me endpoint fails, the token is invalid or expired.
            // Log the user out by clearing the token and redirect to the login page.
            localStorage.removeItem('token');
            window.location.href = 'login.html?session=expired';
            return null; // Stop further execution on this page.
        }
        const data = await res.json();
        const user = data.user;
        localStorage.setItem('currentUser', JSON.stringify(user));
        return user;
    } catch (err) {
        console.error('Failed to sync user data:', err);
        return null;
    }
}
