/**
 * Theme Manager - Light/Dark Mode Toggle
 * Persists theme preference to localStorage
 */

class ThemeManager {
  constructor() {
    this.STORAGE_KEY = 'app-theme';
    this.LIGHT_CLASS = 'light-mode';
    this.DARK_CLASS = 'dark-mode';
    this.init();
  }

  init() {
    // Load saved theme or use system preference
    const saved = localStorage.getItem(this.STORAGE_KEY);
    const preferred = saved || (this.getSystemPreference() ? 'dark' : 'light');
    this.setTheme(preferred);
    
    // Add event listener for toggle button
    const toggleBtn = document.getElementById('themeToggle');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => this.toggle());
      this.updateToggleButton();
    }

    // Listen for system theme changes
    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        if (!localStorage.getItem(this.STORAGE_KEY)) {
          this.setTheme(e.matches ? 'dark' : 'light');
        }
      });
    }
  }

  getSystemPreference() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  setTheme(theme) {
    const html = document.documentElement;
    
    if (theme === 'light') {
      html.classList.remove(this.DARK_CLASS);
      html.classList.add(this.LIGHT_CLASS);
    } else {
      html.classList.remove(this.LIGHT_CLASS);
      html.classList.add(this.DARK_CLASS);
    }
    
    localStorage.setItem(this.STORAGE_KEY, theme);
    this.updateToggleButton();
  }

  toggle() {
    const current = localStorage.getItem(this.STORAGE_KEY) || 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    this.setTheme(next);
  }

  updateToggleButton() {
    const toggleBtn = document.getElementById('themeToggle');
    if (!toggleBtn) return;
    
    const current = localStorage.getItem(this.STORAGE_KEY) || 'dark';
    const icon = toggleBtn.querySelector('span');
    
    if (icon) {
      icon.textContent = current === 'dark' ? '☀️' : '🌙';
      icon.title = current === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode';
    }
  }

  getCurrentTheme() {
    return localStorage.getItem(this.STORAGE_KEY) || 'dark';
  }
}

// Initialize theme manager when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new ThemeManager();
});
