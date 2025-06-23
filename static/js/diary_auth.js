class DiaryAuth {
    constructor() {
        this.isAuthenticated = false;
        this.hasMasterPassword = false;
    }

    async checkAuthStatus() {
        try {
            console.log('🔒 Checking diary auth status...');
            
            const response = await fetch('/api/diary/auth/status');
            const data = await response.json();
            
            if (data.status === 'success') {
                this.hasMasterPassword = data.has_master_password;
                this.isAuthenticated = data.is_authenticated;
                
                console.log('🔒 Diary Auth Status:', {
                    hasMaster: this.hasMasterPassword,
                    isAuth: this.isAuthenticated,
                    needsRedirect: data.redirect_to_password_manager
                });
                
                // ✅ SỬA: Block page nếu cần authentication
                if (data.redirect_to_password_manager === true) {
                    console.log('❌ Need to redirect to password manager');
                    this.blockPageAndRedirect();
                    return false;
                } else {
                    console.log('✅ Authentication OK - allow access to diary');
                    return true;
                }
            } else {
                throw new Error(data.message || 'Unknown error');
            }
        } catch (error) {
            console.error('❌ Error checking diary auth:', error);
            this.showToast('Error checking authentication', 'error');
            return false;
        }
    }

    blockPageAndRedirect() {
        console.log('🚫 Blocking page access and redirecting...');
        
        // ✅ SỬA: Block toàn bộ page content
        const body = document.body;
        
        // Create overlay to block content
        const overlay = document.createElement('div');
        overlay.id = 'auth-overlay';
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 9999;
            display: flex;
            justify-content: center;
            align-items: center;
            color: white;
            font-family: Arial, sans-serif;
        `;
        
        overlay.innerHTML = `
            <div style="text-align: center; background: rgba(255,255,255,0.1); padding: 2rem; border-radius: 15px; backdrop-filter: blur(10px);">
                <i class="bi bi-shield-lock" style="font-size: 3rem; margin-bottom: 1rem; display: block;"></i>
                <h3 style="margin-bottom: 1rem;">Authentication Required</h3>
                <p style="margin-bottom: 2rem; opacity: 0.9;">You need to authenticate with your master password to access the diary.</p>
                <div style="display: flex; gap: 1rem; justify-content: center;">
                    <button id="go-auth-btn" class="btn btn-primary" style="padding: 0.75rem 1.5rem;">
                        <i class="bi bi-key me-1"></i>Authenticate
                    </button>
                    <button id="go-home-btn" class="btn btn-secondary" style="padding: 0.75rem 1.5rem;">
                        <i class="bi bi-house me-1"></i>Go Home
                    </button>
                </div>
            </div>
        `;
        
        body.appendChild(overlay);
        
        // Add event listeners
        document.getElementById('go-auth-btn').onclick = () => {
            window.location.href = '/password_manager';
        };
        
        document.getElementById('go-home-btn').onclick = () => {
            window.location.href = '/home';
        };
        
        // ✅ SỬA: Hide main content
        const mainContent = document.querySelector('.modern-grid-container') || 
                           document.querySelector('.diary-list-container') || 
                           document.querySelector('main') ||
                           document.querySelector('.container');
        
        if (mainContent) {
            mainContent.style.display = 'none';
        }
    }

    async lockDiary() {
        try {
            console.log('🔒 Locking diary...');
            
            const response = await fetch('/api/diary/auth/lock', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.showToast('Diary and Password Manager locked successfully', 'success');
                
                // ✅ SỬA: Redirect với delay
                setTimeout(() => {
                    window.location.href = '/home';
                }, 1000);
            } else {
                this.showToast('Error: ' + data.message, 'error');
            }
        } catch (error) {
            console.error('❌ Error locking diary:', error);
            this.showToast('Error locking diary', 'error');
        }
    }

    showToast(message, type = 'info') {
        console.log(`📢 Toast: ${message} (${type})`);
        
        // Create toast element
        const toast = document.createElement('div');
        toast.className = `alert alert-${type === 'error' ? 'danger' : type} position-fixed`;
        toast.style.cssText = 'top: 20px; right: 20px; z-index: 10000; min-width: 300px;';
        toast.innerHTML = `
            ${message}
            <button type="button" class="btn-close ms-2" onclick="this.parentElement.remove()"></button>
        `;
        
        document.body.appendChild(toast);
        
        // Auto-remove after 3 seconds
        setTimeout(() => {
            if (toast.parentNode) {
                toast.remove();
            }
        }, 3000);
    }
}

// ✅ SỬA: Export và initialize
const diaryAuth = new DiaryAuth();

// ✅ SỬA: Check auth IMMEDIATELY khi page load
document.addEventListener('DOMContentLoaded', function() {
    // Chỉ check auth cho diary pages
    const isDiaryPage = window.location.pathname.includes('/Diary/') || 
                       window.location.pathname.includes('/diary');
    
    if (isDiaryPage) {
        console.log('📄 Diary page detected - checking auth immediately...');
        
        // ✅ SỬA: Check auth ngay lập tức và block nếu cần
        diaryAuth.checkAuthStatus().then(isAllowed => {
            if (isAllowed) {
                console.log('✅ Auth check passed - diary content accessible');
                // Initialize page functionality here
                initializeDiaryPage();
            } else {
                console.log('❌ Auth check failed - page blocked');
                // Page is already blocked by blockPageAndRedirect()
            }
        }).catch(error => {
            console.error('💥 Auth check error:', error);
            diaryAuth.blockPageAndRedirect();
        });
    }
});

// ✅ SỬA: Function để initialize diary page sau khi auth thành công
function initializeDiaryPage() {
    console.log('🎉 Initializing diary page functionality...');
    
    // Setup lock button nếu có
    const lockBtn = document.getElementById('lock-diary-btn');
    if (lockBtn) {
        lockBtn.onclick = () => {
            const confirmed = confirm('Are you sure you want to lock?\n\nThis will lock both your diary and password manager. You will need to enter your master password again to access them.');
            if (confirmed) {
                diaryAuth.lockDiary();
            }
        };
    }

    // Add keyboard shortcut Ctrl+L to lock
    document.addEventListener('keydown', function(e) {
        if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
            e.preventDefault();
            const confirmed = confirm('Lock diary and password manager?\n\nPress OK to confirm.');
            if (confirmed) {
                diaryAuth.lockDiary();
            }
        }
    });
    
    // Initialize other diary-specific functionality here
    // e.g., grid adjustment, animations, etc.
}

// Export để có thể sử dụng từ templates
if (typeof window !== 'undefined') {
    window.diaryAuth = diaryAuth;
}