// PWA Helper - Handles service worker registration and PWA features
class PWAHelper {
  constructor() {
    this.deferredPrompt = null;
    this.isInstalled = false;
    this.isOnline = navigator.onLine;
    this.init();
  }

  async init() {
    this.registerServiceWorker();
    this.setupInstallPrompt();
    this.setupOfflineHandling();
    this.setupSyncHandling();
    this.checkInstallStatus();
  }

  // Service Worker Registration
  async registerServiceWorker() {
    if ('serviceWorker' in navigator) {
      try {
        console.log('[PWA] Registering service worker...');
        const registration = await navigator.serviceWorker.register('/static/sw.js', {
          scope: '/'
        });

        console.log('[PWA] Service worker registered:', registration);

        // Handle updates
        registration.addEventListener('updatefound', () => {
          const newWorker = registration.installing;
          console.log('[PWA] New service worker found, installing...');
          
          newWorker.addEventListener('statechange', () => {
            if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
              this.showUpdateNotification();
            }
          });
        });

        // Listen for messages from service worker
        navigator.serviceWorker.addEventListener('message', event => {
          this.handleServiceWorkerMessage(event.data);
        });

      } catch (error) {
        console.error('[PWA] Service worker registration failed:', error);
      }
    } else {
      console.log('[PWA] Service workers not supported');
    }
  }

  // Install Prompt Handling
  setupInstallPrompt() {
    window.addEventListener('beforeinstallprompt', (e) => {
      console.log('[PWA] Install prompt available');
      e.preventDefault();
      this.deferredPrompt = e;
      this.showInstallButton();
    });

    window.addEventListener('appinstalled', () => {
      console.log('[PWA] App installed');
      this.isInstalled = true;
      this.hideInstallButton();
      this.showNotification('App đã được cài đặt thành công!', 'success');
    });
  }

  // Check if app is already installed
  checkInstallStatus() {
    // Check if running in standalone mode (installed PWA)
    if (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) {
      this.isInstalled = true;
      console.log('[PWA] App is running in standalone mode');
    }

    // Check for iOS Safari standalone
    if (window.navigator.standalone === true) {
      this.isInstalled = true;
      console.log('[PWA] App is running in iOS standalone mode');
    }
  }

  // Show install button
  showInstallButton() {
    let installBtn = document.getElementById('pwa-install-btn');
    
    if (!installBtn) {
      installBtn = document.createElement('button');
      installBtn.id = 'pwa-install-btn';
      installBtn.className = 'btn btn-primary btn-sm position-fixed';
      installBtn.style.cssText = `
        bottom: 20px;
        right: 20px;
        z-index: 1050;
        border-radius: 50px;
        padding: 10px 20px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        border: none;
        background: linear-gradient(45deg, #3498db, #2980b9);
        color: white;
        font-weight: 500;
        transition: all 0.3s ease;
      `;
      installBtn.innerHTML = '📱 Cài đặt App';
      installBtn.title = 'Cài đặt EikiTomobe lên thiết bị';
      
      installBtn.addEventListener('click', () => this.installApp());
      installBtn.addEventListener('mouseenter', () => {
        installBtn.style.transform = 'scale(1.05)';
        installBtn.style.boxShadow = '0 6px 16px rgba(0,0,0,0.4)';
      });
      installBtn.addEventListener('mouseleave', () => {
        installBtn.style.transform = 'scale(1)';
        installBtn.style.boxShadow = '0 4px 12px rgba(0,0,0,0.3)';
      });
      
      document.body.appendChild(installBtn);
    }
    
    installBtn.style.display = 'block';
  }

  // Hide install button
  hideInstallButton() {
    const installBtn = document.getElementById('pwa-install-btn');
    if (installBtn) {
      installBtn.style.display = 'none';
    }
  }

  // Install the app
  async installApp() {
    if (!this.deferredPrompt) {
      console.log('[PWA] No install prompt available');
      return;
    }

    try {
      this.deferredPrompt.prompt();
      const { outcome } = await this.deferredPrompt.userChoice;
      
      console.log('[PWA] User choice:', outcome);
      
      if (outcome === 'accepted') {
        this.showNotification('Đang cài đặt app...', 'info');
      } else {
        this.showNotification('Bạn có thể cài đặt app sau trong menu trình duyệt', 'info');
      }
      
      this.deferredPrompt = null;
      this.hideInstallButton();
    } catch (error) {
      console.error('[PWA] Install failed:', error);
      this.showNotification('Không thể cài đặt app', 'error');
    }
  }

  // Offline/Online Handling
  setupOfflineHandling() {
    window.addEventListener('online', () => {
      console.log('[PWA] Back online');
      this.isOnline = true;
      this.hideOfflineIndicator();
      this.syncOfflineData();
      this.showNotification('Đã kết nối lại internet', 'success');
    });

    window.addEventListener('offline', () => {
      console.log('[PWA] Gone offline');
      this.isOnline = false;
      this.showOfflineIndicator();
      this.showNotification('Bạn đang offline - Một số tính năng có thể bị hạn chế', 'warning');
    });

    // Check initial state
    if (!this.isOnline) {
      this.showOfflineIndicator();
    }
  }

  // Show offline indicator
  showOfflineIndicator() {
    let indicator = document.getElementById('offline-indicator');
    
    if (!indicator) {
      indicator = document.createElement('div');
      indicator.id = 'offline-indicator';
      indicator.className = 'alert alert-warning position-fixed';
      indicator.style.cssText = `
        top: 0;
        left: 50%;
        transform: translateX(-50%);
        z-index: 1060;
        margin: 10px;
        border-radius: 25px;
        padding: 8px 20px;
        font-size: 14px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        border: none;
        background: linear-gradient(45deg, #f39c12, #e67e22);
        color: white;
        animation: slideDown 0.3s ease;
      `;
      indicator.innerHTML = '📡 Offline - Chế độ ngoại tuyến';
      
      // Add CSS animation
      if (!document.getElementById('pwa-animations')) {
        const style = document.createElement('style');
        style.id = 'pwa-animations';
        style.textContent = `
          @keyframes slideDown {
            from { transform: translateX(-50%) translateY(-100%); opacity: 0; }
            to { transform: translateX(-50%) translateY(0); opacity: 1; }
          }
          @keyframes slideUp {
            from { transform: translateX(-50%) translateY(0); opacity: 1; }
            to { transform: translateX(-50%) translateY(-100%); opacity: 0; }
          }
        `;
        document.head.appendChild(style);
      }
      
      document.body.appendChild(indicator);
    }
    
    indicator.style.display = 'block';
  }

  // Hide offline indicator
  hideOfflineIndicator() {
    const indicator = document.getElementById('offline-indicator');
    if (indicator) {
      indicator.style.animation = 'slideUp 0.3s ease';
      setTimeout(() => {
        indicator.style.display = 'none';
        indicator.style.animation = '';
      }, 300);
    }
  }

  // Background Sync Handling
  setupSyncHandling() {
    if ('serviceWorker' in navigator && 'sync' in window.ServiceWorkerRegistration.prototype) {
      console.log('[PWA] Background sync supported');
    } else {
      console.log('[PWA] Background sync not supported');
    }
  }

  // Sync offline data when back online
  async syncOfflineData() {
    if ('serviceWorker' in navigator && 'sync' in window.ServiceWorkerRegistration.prototype) {
      try {
        const registration = await navigator.serviceWorker.ready;
        await registration.sync.register('offline-requests');
        console.log('[PWA] Background sync registered');
      } catch (error) {
        console.error('[PWA] Background sync registration failed:', error);
      }
    }
  }

  // Handle messages from service worker
  handleServiceWorkerMessage(data) {
    console.log('[PWA] Message from service worker:', data);
    
    if (data.type === 'CACHE_UPDATED') {
      this.showNotification('App đã được cập nhật', 'success');
    }
    
    if (data.type === 'OFFLINE_REQUEST_STORED') {
      this.showNotification('Thao tác đã được lưu, sẽ đồng bộ khi online', 'info');
    }
  }

  // Show update notification
  showUpdateNotification() {
    const updateNotification = document.createElement('div');
    updateNotification.className = 'alert alert-info position-fixed';
    updateNotification.style.cssText = `
      bottom: 80px;
      right: 20px;
      z-index: 1055;
      max-width: 300px;
      border-radius: 10px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      border: none;
      background: linear-gradient(45deg, #3498db, #2980b9);
      color: white;
    `;
    updateNotification.innerHTML = `
      <div class="d-flex align-items-center">
        <div class="flex-grow-1">
          <strong>Có bản cập nhật mới!</strong><br>
          <small>Khởi động lại để sử dụng phiên bản mới</small>
        </div>
        <button class="btn btn-sm btn-light ms-2" onclick="this.parentElement.parentElement.remove(); window.location.reload();">
          Cập nhật
        </button>
      </div>
    `;
    
    document.body.appendChild(updateNotification);
    
    // Auto remove after 10 seconds
    setTimeout(() => {
      if (updateNotification.parentElement) {
        updateNotification.remove();
      }
    }, 10000);
  }

  // Utility: Show notification
  showNotification(message, type = 'info') {
    // Remove existing notifications
    document.querySelectorAll('.pwa-notification').forEach(el => el.remove());
    
    const notification = document.createElement('div');
    notification.className = `alert alert-${type === 'error' ? 'danger' : type} position-fixed pwa-notification`;
    notification.style.cssText = `
      top: 20px;
      right: 20px;
      z-index: 1060;
      max-width: 350px;
      border-radius: 10px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.2);
      border: none;
      animation: slideInRight 0.3s ease;
    `;
    
    // Add animation CSS if not exists
    if (!document.getElementById('notification-animations')) {
      const style = document.createElement('style');
      style.id = 'notification-animations';
      style.textContent = `
        @keyframes slideInRight {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOutRight {
          from { transform: translateX(0); opacity: 1; }
          to { transform: translateX(100%); opacity: 0; }
        }
      `;
      document.head.appendChild(style);
    }
    
    notification.innerHTML = `
      <div class="d-flex align-items-center">
        <div class="flex-grow-1">${message}</div>
        <button type="button" class="btn-close btn-close-white ms-2" aria-label="Close"></button>
      </div>
    `;
    
    // Add close functionality
    notification.querySelector('.btn-close').addEventListener('click', () => {
      notification.style.animation = 'slideOutRight 0.3s ease';
      setTimeout(() => notification.remove(), 300);
    });
    
    document.body.appendChild(notification);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
      if (notification.parentElement) {
        notification.style.animation = 'slideOutRight 0.3s ease';
        setTimeout(() => notification.remove(), 300);
      }
    }, 5000);
  }

  // Utility: Check if feature works offline
  isFeatureAvailableOffline(feature) {
    const offlineFeatures = [
      'mindmap',
      'card_info',
      'ui_settings',
      'view_notes', // Read-only
      'view_tasks', // Read-only
      'quotes'
    ];
    
    return offlineFeatures.includes(feature);
  }

  // Utility: Store data for offline use
  async storeOfflineData(key, data) {
    try {
      localStorage.setItem(`offline_${key}`, JSON.stringify({
        data: data,
        timestamp: Date.now()
      }));
      console.log('[PWA] Data stored for offline use:', key);
    } catch (error) {
      console.error('[PWA] Failed to store offline data:', error);
    }
  }

  // Utility: Get offline data
  getOfflineData(key, maxAge = 24 * 60 * 60 * 1000) { // 24 hours default
    try {
      const stored = localStorage.getItem(`offline_${key}`);
      if (!stored) return null;
      
      const { data, timestamp } = JSON.parse(stored);
      
      // Check if data is still fresh
      if (Date.now() - timestamp > maxAge) {
        localStorage.removeItem(`offline_${key}`);
        return null;
      }
      
      return data;
    } catch (error) {
      console.error('[PWA] Failed to get offline data:', error);
      return null;
    }
  }

  // Update cache manually
  async updateCache() {
    if ('serviceWorker' in navigator) {
      const registration = await navigator.serviceWorker.ready;
      if (registration.active) {
        registration.active.postMessage({ type: 'CACHE_UPDATE' });
      }
    }
  }
}

// Initialize PWA Helper when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  window.pwaHelper = new PWAHelper();
  console.log('[PWA] PWA Helper initialized');
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = PWAHelper;
}
