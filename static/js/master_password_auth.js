class MasterPasswordAuth {
    constructor() {
        this.isAuthenticated = false;
        this.onAuthSuccess = null;
        this.onAuthFailed = null;
    }

    async checkMasterPasswordStatus() {
        try {
            console.log('🔐 Checking master password status...');
            
            // Test với một API call đơn giản
            const response = await fetch('/api/auth/master_password_status');
            
            if (response.status === 401) {
                console.log('❌ Master password not verified');
                this.isAuthenticated = false;
                this.showMasterPasswordModal();
            } else {
                console.log('✅ Master password already verified');
                this.isAuthenticated = true;
                if (this.onAuthSuccess) {
                    this.onAuthSuccess();
                }
            }
        } catch (error) {
            console.error('💥 Error checking master password status:', error);
            this.isAuthenticated = false;
            this.showMasterPasswordModal();
        }
    }

    showMasterPasswordModal() {
        // Load hint first
        this.loadMasterPasswordHint();
        
        const modal = new bootstrap.Modal(document.getElementById('masterPasswordModal'));
        modal.show();
        
        // Setup event listeners
        document.getElementById('verify-master-password').onclick = () => this.verifyMasterPassword();
        document.getElementById('show-hint-btn').onclick = () => this.toggleHint();
        
        document.getElementById('master-password-input').onkeypress = (e) => {
            if (e.key === 'Enter') {
                this.verifyMasterPassword();
            }
        };
        
        // Clear and focus input
        document.getElementById('master-password-input').value = '';
        document.getElementById('master-password-input').focus();
    }

    async verifyMasterPassword() {
        const masterPassword = document.getElementById('master-password-input').value;
        
        if (!masterPassword) {
            this.showToast('Please enter master password', 'warning');
            return;
        }
        
        const btn = document.getElementById('verify-master-password');
        const originalText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="bi bi-hourglass-split me-1"></i>Verifying...';
        
        try {
            const response = await fetch('/api/auth/master_password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    master_password: masterPassword
                })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.isAuthenticated = true;
                bootstrap.Modal.getInstance(document.getElementById('masterPasswordModal')).hide();
                
                // Clear input
                document.getElementById('master-password-input').value = '';
                
                this.showToast('Access granted', 'success');
                
                // Call success callback
                if (this.onAuthSuccess) {
                    this.onAuthSuccess();
                }
            } else {
                this.showToast('Invalid master password', 'error');
                document.getElementById('master-password-input').select();
            }
        } catch (error) {
            console.error('Error verifying master password:', error);
            this.showToast('Error verifying master password', 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    }

    async lockMasterPassword() {
        const confirmed = confirm(
            'Are you sure you want to lock?\n\n' +
            'You will need to enter your master password again to access protected features.'
        );
        
        if (!confirmed) return;
        
        try {
            const response = await fetch('/api/auth/lock_master_password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.showToast('Locked successfully', 'success');
                
                // Reset state
                this.isAuthenticated = false;
                
                // Fade out and redirect
                document.body.style.transition = 'opacity 0.5s ease';
                document.body.style.opacity = '0';
                
                setTimeout(() => {
                    window.location.href = '/home';
                }, 500);
                
            } else {
                this.showToast('Error: ' + data.message, 'error');
            }
        } catch (error) {
            console.error('Error locking:', error);
            this.showToast('Error locking', 'error');
        }
    }

    async loadMasterPasswordHint() {
        try {
            const response = await fetch('/api/auth/master_password_hint');
            const data = await response.json();
            
            if (data.status === 'success' && data.hint) {
                document.getElementById('password-hint-text').textContent = data.hint;
                document.getElementById('show-hint-btn').style.display = 'block';
            } else {
                document.getElementById('show-hint-btn').style.display = 'none';
            }
        } catch (error) {
            console.error('Error loading hint:', error);
            document.getElementById('show-hint-btn').style.display = 'none';
        }
    }

    toggleHint() {
        const hintSection = document.getElementById('password-hint-section');
        const btn = document.getElementById('show-hint-btn');
        
        if (hintSection.style.display === 'none') {
            hintSection.style.display = 'block';
            btn.innerHTML = '<i class="bi bi-eye-slash me-1"></i>Hide Hint';
        } else {
            hintSection.style.display = 'none';
            btn.innerHTML = '<i class="bi bi-question-circle me-1"></i>Show Hint';
        }
    }

    openHintSetupModal() {
        this.loadCurrentHint();
        
        const modal = new bootstrap.Modal(document.getElementById('hintSetupModal'));
        modal.show();
        
        document.getElementById('save-hint-btn').onclick = () => this.saveHint();
        document.getElementById('clear-hint-btn').onclick = () => this.clearHint();
    }

    async loadCurrentHint() {
        try {
            const response = await fetch('/api/auth/master_password_hint');
            const data = await response.json();
            
            if (data.status === 'success' && data.hint) {
                document.getElementById('hint-input').value = data.hint;
                document.getElementById('clear-hint-btn').style.display = 'inline-block';
            } else {
                document.getElementById('hint-input').value = '';
                document.getElementById('clear-hint-btn').style.display = 'none';
            }
        } catch (error) {
            console.error('Error loading current hint:', error);
            document.getElementById('hint-input').value = '';
            document.getElementById('clear-hint-btn').style.display = 'none';
        }
    }

    async saveHint() {
        const hint = document.getElementById('hint-input').value.trim();
        
        if (hint.length > 200) {
            this.showToast('Hint must be 200 characters or less', 'warning');
            return;
        }
        
        try {
            const response = await fetch('/api/auth/master_password_hint', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    hint: hint
                })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.showToast(hint ? 'Hint saved successfully' : 'Hint cleared successfully', 'success');
                bootstrap.Modal.getInstance(document.getElementById('hintSetupModal')).hide();
                
                // Refresh hint in master password modal
                this.loadMasterPasswordHint();
            } else {
                this.showToast('Error: ' + data.message, 'error');
            }
        } catch (error) {
            console.error('Error saving hint:', error);
            this.showToast('Error saving hint', 'error');
        }
    }

    async clearHint() {
        if (!confirm('Are you sure you want to clear your password hint?')) {
            return;
        }
        
        try {
            const response = await fetch('/api/auth/master_password_hint', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    hint: ''
                })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.showToast('Hint cleared successfully', 'success');
                bootstrap.Modal.getInstance(document.getElementById('hintSetupModal')).hide();
                
                // Refresh hint in master password modal
                this.loadMasterPasswordHint();
            } else {
                this.showToast('Error: ' + data.message, 'error');
            }
        } catch (error) {
            console.error('Error clearing hint:', error);
            this.showToast('Error clearing hint', 'error');
        }
    }

    showToast(message, type = 'info') {
        console.log(`📢 Toast: ${message} (${type})`);
        
        const toast = document.createElement('div');
        toast.className = `alert alert-${type === 'error' ? 'danger' : type} position-fixed`;
        toast.style.cssText = 'top: 20px; right: 20px; z-index: 10000; min-width: 300px;';
        toast.innerHTML = `
            ${message}
            <button type="button" class="btn-close ms-2" onclick="this.parentElement.remove()"></button>
        `;
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            if (toast.parentNode) {
                toast.remove();
            }
        }, 3000);
    }

    // Setup keyboard shortcuts
    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl+L hoặc Cmd+L để lock
            if ((e.ctrlKey || e.metaKey) && e.key === 'l' && this.isAuthenticated) {
                e.preventDefault();
                this.lockMasterPassword();
            }
        });
    }
}

// Export global instance
const masterPasswordAuth = new MasterPasswordAuth();

// Setup keyboard shortcuts
masterPasswordAuth.setupKeyboardShortcuts();

// Make available globally
if (typeof window !== 'undefined') {
    window.masterPasswordAuth = masterPasswordAuth;
}