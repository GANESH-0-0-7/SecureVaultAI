/**
 * SecureVaultAI - Main JavaScript Module
 * Core functionality: DOM utilities, forms, modals, notifications, Socket.IO integration
 */

const App = {
  // Socket.IO instance
  socket: null,

  // Configuration
  config: {
    toastDuration: 5000,
    modalAnimationDuration: 300,
    debounceDelay: 300
  },

  // Initialize the application
  init() {
    this.initDOM();
    this.initSocketIO();
    this.initTheme();
    this.initEventListeners();
    this.setupFormValidation();
    console.log('✓ SecureVaultAI initialized');
  },

  // ==================== DOM UTILITIES ====================

  initDOM() {
    // Create toast container if it doesn't exist
    if (!document.getElementById('toast-container')) {
      const container = document.createElement('div');
      container.id = 'toast-container';
      container.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 9999; width: 400px; max-width: 90%;';
      document.body.appendChild(container);
    }
  },

  // ==================== SOCKET.IO INTEGRATION ====================

  initSocketIO() {
    try {
      this.socket = io();

      this.socket.on('connect', () => {
        console.log('✓ Connected to server (WebSocket)');
        this.showToast('Connected to real-time updates', 'success', 2000);
      });

      this.socket.on('disconnect', () => {
        console.log('✗ Disconnected from server');
        this.showToast('Disconnected from real-time updates', 'warning', 3000);
      });

      // Handle various notification types
      this.socket.on('notification:new', (data) => {
        this.handleNotification(data);
      });

      this.socket.on('share:received', (data) => {
        this.showToast(`${data.sender} shared "${data.file_name}" with you`, 'info');
        this.updateDashboard();
      });

      this.socket.on('share:accessed', (data) => {
        this.showToast(`${data.accessor} accessed your shared file`, 'info');
        this.updateDashboard();
      });

      this.socket.on('share:expired', (data) => {
        this.showToast(`Share has expired: ${data.file_name}`, 'warning');
      });

      this.socket.on('security:alert', (data) => {
        this.showToast(`Security alert: ${data.message}`, 'danger');
        this.updateSecurityLogs();
      });

      this.socket.on('notification:alert', (data) => {
        this.showToast(data.message, data.type || 'info');
      });
    } catch (e) {
      console.warn('Socket.IO not available, real-time features disabled');
    }
  },

  // ==================== NOTIFICATIONS ====================

  showToast(message, type = 'info', duration = null) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    const toastId = `toast-${Date.now()}`;
    toast.id = toastId;

    // Color mapping
    const colorMap = {
      success: '#10b981',
      danger: '#ef4444',
      warning: '#f59e0b',
      info: '#3b82f6'
    };

    const bgColor = colorMap[type] || colorMap.info;

    toast.style.cssText = `
      background: rgba(15, 23, 42, 0.9);
      border-left: 4px solid ${bgColor};
      color: #f1f5f9;
      padding: 12px 16px;
      margin-bottom: 10px;
      border-radius: 4px;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.2);
      animation: slideInRight 0.3s ease-out;
      font-size: 14px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
    `;

    const closeBtn = document.createElement('button');
    closeBtn.innerHTML = '✕';
    closeBtn.style.cssText = `
      background: none;
      border: none;
      color: #94a3b8;
      cursor: pointer;
      font-size: 18px;
      padding: 0;
      line-height: 1;
    `;
    closeBtn.onclick = () => this.removeToast(toastId);

    const messageSpan = document.createElement('span');
    messageSpan.textContent = message;
    messageSpan.style.flex = '1';

    toast.appendChild(messageSpan);
    toast.appendChild(closeBtn);
    container.appendChild(toast);

    const autoDismissDuration = duration || this.config.toastDuration;
    setTimeout(() => this.removeToast(toastId), autoDismissDuration);
  },

  removeToast(toastId) {
    const toast = document.getElementById(toastId);
    if (toast) {
      toast.style.animation = 'slideOutRight 0.3s ease-out';
      setTimeout(() => toast.remove(), 300);
    }
  },

  handleNotification(data) {
    const { message, type = 'info', action = null } = data;
    this.showToast(message, type);
  },

  // ==================== FORM UTILITIES ====================

  setupFormValidation() {
    document.querySelectorAll('form').forEach(form => {
      form.addEventListener('submit', (e) => {
        if (!this.validateForm(form)) {
          e.preventDefault();
        }
      });
    });
  },

  validateForm(form) {
    let isValid = true;

    // Check required fields
    form.querySelectorAll('[required]').forEach(field => {
      if (!field.value.trim()) {
        this.markFieldInvalid(field, 'This field is required');
        isValid = false;
      } else {
        this.clearFieldError(field);
      }
    });

    // Check email fields
    form.querySelectorAll('[type="email"]').forEach(field => {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (field.value && !emailRegex.test(field.value)) {
        this.markFieldInvalid(field, 'Please enter a valid email');
        isValid = false;
      }
    });

    // Check password confirmation
    const passwordField = form.querySelector('[name="password"]');
    const confirmField = form.querySelector('[name="confirm_password"]');
    if (passwordField && confirmField && passwordField.value !== confirmField.value) {
      this.markFieldInvalid(confirmField, 'Passwords do not match');
      isValid = false;
    }

    return isValid;
  },

  markFieldInvalid(field, message) {
    field.classList.add('is-invalid');
    const errorEl = field.parentElement.querySelector('.invalid-feedback');
    if (errorEl) {
      errorEl.textContent = message;
      errorEl.style.display = 'block';
    }
  },

  clearFieldError(field) {
    field.classList.remove('is-invalid');
    const errorEl = field.parentElement.querySelector('.invalid-feedback');
    if (errorEl) {
      errorEl.style.display = 'none';
    }
  },

  // ==================== MODAL UTILITIES ====================

  openModal(modalId, options = {}) {
    const modal = document.getElementById(modalId);
    if (!modal) return;

    modal.style.display = 'block';
    modal.style.animation = 'fadeIn 0.3s ease-out';

    if (options.onOpen) {
      options.onOpen();
    }
  },

  closeModal(modalId, options = {}) {
    const modal = document.getElementById(modalId);
    if (!modal) return;

    modal.style.animation = 'fadeOut 0.3s ease-out';
    setTimeout(() => {
      modal.style.display = 'none';
      if (options.onClose) {
        options.onClose();
      }
    }, 300);
  },

  resetModal(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;

    const form = modal.querySelector('form');
    if (form) {
      form.reset();
      form.querySelectorAll('.invalid-feedback').forEach(el => {
        el.style.display = 'none';
      });
    }
  },

  // ==================== CLIPBOARD UTILITIES ====================

  copyToClipboard(text, feedbackElement = null) {
    // Try modern Clipboard API first
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text)
        .then(() => {
          this.showToast('Copied to clipboard!', 'success', 2000);
          if (feedbackElement) {
            this.showCopyFeedback(feedbackElement);
          }
        })
        .catch(() => {
          this.copyToClipboardFallback(text);
        });
    } else {
      this.copyToClipboardFallback(text);
    }
  },

  copyToClipboardFallback(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    this.showToast('Copied to clipboard!', 'success', 2000);
  },

  showCopyFeedback(element) {
    const originalText = element.textContent;
    element.textContent = '✓ Copied!';
    element.style.color = '#10b981';
    setTimeout(() => {
      element.textContent = originalText;
      element.style.color = '';
    }, 2000);
  },

  // ==================== THEME UTILITIES ====================

  initTheme() {
    const theme = localStorage.getItem('app-theme') || 'dark';
    this.setTheme(theme);

    // Listen for theme toggle button
    const themeToggle = document.querySelector('[data-theme-toggle]');
    if (themeToggle) {
      themeToggle.addEventListener('click', () => {
        const currentTheme = localStorage.getItem('app-theme') || 'dark';
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        this.setTheme(newTheme);
      });
    }
  },

  setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('app-theme', theme);
  },

  // ==================== LOADING STATES ====================

  setLoading(elementId, isLoading = true) {
    const element = document.getElementById(elementId);
    if (!element) return;

    if (isLoading) {
      element.disabled = true;
      element.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Loading...';
    } else {
      element.disabled = false;
      element.innerHTML = element.getAttribute('data-original-text') || 'Submit';
    }
  },

  showSkeleton(elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;
    element.innerHTML = `
      <div class="skeleton-loader">
        <div class="skeleton-line" style="width: 80%; height: 12px; margin-bottom: 8px;"></div>
        <div class="skeleton-line" style="width: 100%; height: 12px; margin-bottom: 8px;"></div>
        <div class="skeleton-line" style="width: 90%; height: 12px;"></div>
      </div>
    `;
  },

  // ==================== UTILITY FUNCTIONS ====================

  debounce(func, delay = this.config.debounceDelay) {
    let timeoutId;
    return function (...args) {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => func.apply(this, args), delay);
    };
  },

  throttle(func, limit = this.config.debounceDelay) {
    let inThrottle;
    return function (...args) {
      if (!inThrottle) {
        func.apply(this, args);
        inThrottle = true;
        setTimeout(() => inThrottle = false, limit);
      }
    };
  },

  formatTime(date) {
    return new Date(date).toLocaleString();
  },

  formatRelativeTime(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);

    const intervals = {
      year: 31536000,
      month: 2592000,
      week: 604800,
      day: 86400,
      hour: 3600,
      minute: 60
    };

    for (const [name, secondsInInterval] of Object.entries(intervals)) {
      const interval = Math.floor(seconds / secondsInInterval);
      if (interval >= 1) {
        return interval === 1 ? `1 ${name} ago` : `${interval} ${name}s ago`;
      }
    }
    return 'just now';
  },

  // ==================== API UTILITIES ====================

  async fetchAPI(url, options = {}) {
    try {
      const defaultOptions = {
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        }
      };

      const response = await fetch(url, { ...defaultOptions, ...options });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('API Error:', error);
      this.showToast('An error occurred. Please try again.', 'danger');
      throw error;
    }
  },

  // ==================== DASHBOARD UPDATES ====================

  updateDashboard() {
    // Emit event to update dashboard stats
    if (this.socket) {
      this.socket.emit('dashboard:refresh');
    }
  },

  updateSecurityLogs() {
    // Emit event to update security logs
    if (this.socket) {
      this.socket.emit('logs:refresh');
    }
  },

  // ==================== EVENT LISTENERS ====================

  initEventListeners() {
    // Close modals when clicking outside
    document.addEventListener('click', (e) => {
      if (e.target.classList.contains('modal') && e.target.style.display === 'block') {
        const modalId = e.target.id;
        this.closeModal(modalId);
      }
    });

    // Copy to clipboard for elements with data-copy-target
    document.querySelectorAll('[data-copy-target]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const targetId = btn.getAttribute('data-copy-target');
        const target = document.getElementById(targetId);
        if (target) {
          this.copyToClipboard(target.textContent, btn);
        }
      });
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      // Escape to close modal
      if (e.key === 'Escape') {
        document.querySelectorAll('.modal[style*="display: block"]').forEach(modal => {
          this.closeModal(modal.id);
        });
      }
    });
  }
};

// Initialize app when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => App.init());
} else {
  App.init();
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
  @keyframes fadeIn {
    from {
      opacity: 0;
      transform: translateY(-10px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  @keyframes fadeOut {
    from {
      opacity: 1;
      transform: translateY(0);
    }
    to {
      opacity: 0;
      transform: translateY(-10px);
    }
  }

  @keyframes slideInRight {
    from {
      opacity: 0;
      transform: translateX(400px);
    }
    to {
      opacity: 1;
      transform: translateX(0);
    }
  }

  @keyframes slideOutRight {
    from {
      opacity: 1;
      transform: translateX(0);
    }
    to {
      opacity: 0;
      transform: translateX(400px);
    }
  }

  .skeleton-loader {
    animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
  }

  .skeleton-line {
    background: linear-gradient(90deg, #1e293b 0%, #334155 50%, #1e293b 100%);
    background-size: 200% 100%;
    animation: shimmer 2s infinite;
    border-radius: 4px;
  }

  @keyframes shimmer {
    0% {
      background-position: 200% 0;
    }
    100% {
      background-position: -200% 0;
    }
  }

  @keyframes pulse {
    0%, 100% {
      opacity: 1;
    }
    50% {
      opacity: 0.7;
    }
  }

  .is-invalid {
    border-color: #ef4444 !important;
  }

  .invalid-feedback {
    display: none;
    color: #ef4444;
    font-size: 12px;
    margin-top: 4px;
  }
`;
document.head.appendChild(style);
