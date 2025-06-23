// ✅ SỬA: Đơn giản hóa DiaryAuth class
class DiaryAuth {
    constructor() {
        this.isAuthenticated = false;
        this.hasMasterPassword = false;
    }

    async checkAuthStatus() {
        try {
            // ✅ SỬA: Sử dụng diary auth endpoint nhưng backend sẽ check password manager
            const response = await fetch('/api/diary/auth/status');
            const data = await response.json();
            
            if (data.status === 'success') {
                this.hasMasterPassword = data.has_master_password;
                this.isAuthenticated = data.is_authenticated;
                
                // ✅ SỬA: Nếu cần authentication, chuyển đến password manager
                if (data.redirect_to_password_manager) {
                    this.showRedirectModal();
                    return false;
                } else if (!this.hasMasterPassword) {
                    this.showSetupModal();
                    return false;
                }
                return true;
            }
            return false;
        } catch (error) {
            console.error('Error checking diary auth status:', error);
            return false;
        }
    }

    showSetupModal() {
        const modalHtml = `
            <div class="modal fade" id="diarySetupModal" tabindex="-1" data-bs-backdrop="static" data-bs-keyboard="false">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="bi bi-shield-plus me-2"></i>Setup Master Password
                            </h5>
                        </div>
                        <div class="modal-body">
                            <div class="text-center mb-4">
                                <i class="bi bi-shield-lock" style="font-size: 3rem; color: var(--primary-color);"></i>
                            </div>
                            
                            <p class="text-center mb-4">
                                You need to set up a master password to protect your sensitive data including diary entries and passwords.
                            </p>
                            
                            <div class="alert alert-info">
                                <i class="bi bi-info-circle me-2"></i>
                                The master password will protect both your diary entries and saved passwords.
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-outline-secondary" onclick="window.location.href='/home'">
                                <i class="bi bi-house me-1"></i>Back to Home
                            </button>
                            <button type="button" class="btn btn-primary" onclick="window.location.href='/password_manager'">
                                <i class="bi bi-shield-plus me-1"></i>Setup Master Password
                            </button>
                        </div>
                    </div>
                </div>
            </div>`;
        
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        const modal = new bootstrap.Modal(document.getElementById('diarySetupModal'));
        modal.show();
    }

    showRedirectModal() {
        const modalHtml = `
            <div class="modal fade" id="diaryRedirectModal" tabindex="-1" data-bs-backdrop="static" data-bs-keyboard="false">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="bi bi-shield-lock me-2"></i>Authentication Required
                            </h5>
                        </div>
                        <div class="modal-body">
                            <div class="text-center mb-4">
                                <i class="bi bi-lock" style="font-size: 3rem; color: var(--primary-color);"></i>
                            </div>
                            
                            <p class="text-center mb-4">
                                You need to enter your master password to access your diary entries.
                            </p>
                            
                            <div class="alert alert-warning">
                                <i class="bi bi-exclamation-triangle me-2"></i>
                                Your diary is protected by the same master password used for your password manager.
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-outline-secondary" onclick="window.location.href='/home'">
                                <i class="bi bi-house me-1"></i>Back to Home
                            </button>
                            <button type="button" class="btn btn-primary" onclick="window.location.href='/password_manager'">
                                <i class="bi bi-unlock me-1"></i>Enter Master Password
                            </button>
                        </div>
                    </div>
                </div>
            </div>`;
        
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        const modal = new bootstrap.Modal(document.getElementById('diaryRedirectModal'));
        modal.show();
    }

    async lockDiary() {
        try {
            // ✅ SỬA: Sử dụng diary lock endpoint (backend sẽ clear session chung)
            const response = await fetch('/api/diary/auth/lock', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });
            
            if (response.ok) {
                this.isAuthenticated = false;
                this.showToast('Locked successfully - Both diary and password manager are now locked', 'success');
                setTimeout(() => window.location.href = '/home', 1500);
            }
        } catch (error) {
            console.error('Error locking:', error);
            this.showToast('Error locking', 'error');
        }
    }

    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show position-fixed`;
        toast.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px; max-width: 400px;';
        toast.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            if (toast.parentNode) {
                toast.remove();
            }
        }, 4000);
    }
}

// Global instance
const diaryAuth = new DiaryAuth();