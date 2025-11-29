// Content Script for Phishing Detector
class PhishingDetectorContent {
    constructor() {
        this.isEnabled = true;
        this.currentUrl = window.location.href;
        this.warningShown = false;
        this.init();
    }
    
    init() {
        this.setupMessageListener();
        this.setupPageMonitoring();
        this.checkCurrentPage();
        console.log('Phishing Detector Content Script loaded for:', this.currentUrl);
    }
    
    setupMessageListener() {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            this.handleMessage(request, sender, sendResponse);
            return true;
        });
    }
    
    setupPageMonitoring() {
        // Monitor for URL changes (for SPAs)
        let lastUrl = this.currentUrl;
        new MutationObserver(() => {
            const currentUrl = window.location.href;
            if (currentUrl !== lastUrl) {
                lastUrl = currentUrl;
                this.currentUrl = currentUrl;
                this.checkCurrentPage();
            }
        }).observe(document, { subtree: true, childList: true });
        
        // Monitor for form submissions
        document.addEventListener('submit', (e) => {
            this.checkFormSubmission(e);
        });
        
        // Monitor for clicks on suspicious links
        document.addEventListener('click', (e) => {
            this.checkLinkClick(e);
        });
    }
    
    async checkCurrentPage() {
        if (!this.isEnabled) return;
        
        try {
            // Request analysis from background script
            const response = await chrome.runtime.sendMessage({
                action: 'analyzeUrl',
                url: this.currentUrl
            });
            
            if (response && response.success) {
                this.handleAnalysisResult(response.results);
            }
        } catch (error) {
            console.error('Error checking current page:', error);
        }
    }
    
    handleAnalysisResult(result) {
        if (result.is_phishing === true) {
            this.showPhishingWarning(result);
        } else if (result.is_phishing === null) {
            this.showSuspiciousWarning(result);
        }
    }
    
    async handleMessage(request, sender, sendResponse) {
        try {
            switch (request.action) {
                case 'showWarning':
                    this.showPhishingWarning(request.analysis);
                    sendResponse({ success: true });
                    break;
                    
                case 'showSuspiciousWarning':
                    this.showSuspiciousWarning(request.analysis);
                    sendResponse({ success: true });
                    break;
                    
                case 'toggleProtection':
                    this.isEnabled = request.enabled;
                    if (!this.isEnabled) {
                        this.removeWarnings();
                    }
                    sendResponse({ success: true });
                    break;
                    
                default:
                    sendResponse({ success: false, error: 'Unknown action' });
            }
        } catch (error) {
            console.error('Error handling message:', error);
            sendResponse({ success: false, error: error.message });
        }
    }
    
    showPhishingWarning(analysis) {
        if (this.warningShown) return;
        
        this.warningShown = true;
        
        // Create warning overlay
        const overlay = document.createElement('div');
        overlay.id = 'phishing-warning-overlay';
        overlay.className = 'phishing-warning-overlay';
        
        overlay.innerHTML = `
            <div class="phishing-warning-modal">
                <div class="warning-header">
                    <div class="warning-icon">🛡️</div>
                    <h2>Phishing Site Detected</h2>
                </div>
                <div class="warning-content">
                    <div class="warning-message">
                        <p><strong>Warning:</strong> This website has been identified as a phishing site.</p>
                        <p>Your personal information may be at risk if you continue.</p>
                    </div>
                    <div class="risk-details">
                        <div class="risk-score">
                            <span>Risk Score: </span>
                            <span class="score-value ${analysis.risk_score >= 60 ? 'high' : analysis.risk_score >= 40 ? 'medium' : 'low'}">${analysis.risk_score}/100</span>
                        </div>
                        <div class="detection-methods">
                            <span>Detection Methods: </span>
                            <span class="methods">${analysis.detection_methods?.join(', ') || 'Multiple'}</span>
                        </div>
                        ${analysis.reasons?.length > 0 ? `
                        <div class="reasons">
                            <span>Reasons: </span>
                            <ul>
                                ${analysis.reasons.map(reason => `<li>${reason}</li>`).join('')}
                            </ul>
                        </div>
                        ` : ''}
                    </div>
                </div>
                <div class="warning-actions">
                    <button class="btn-leave" onclick="this.leaveSite()">Leave Site</button>
                    <button class="btn-continue" onclick="this.continueAnyway()">Continue Anyway</button>
                    <button class="btn-report" onclick="this.reportError()">Report Error</button>
                </div>
            </div>
        `;
        
        // Add styles
        this.addWarningStyles();
        
        // Add to page
        document.body.appendChild(overlay);
        
        // Prevent page interaction
        document.body.style.overflow = 'hidden';
        
        // Add event listeners
        this.setupWarningEvents(overlay, analysis);
    }
    
    showSuspiciousWarning(analysis) {
        if (this.warningShown) return;
        
        this.warningShown = true;
        
        // Create less intrusive warning banner
        const banner = document.createElement('div');
        banner.id = 'phishing-suspicious-banner';
        banner.className = 'phishing-suspicious-banner';
        
        banner.innerHTML = `
            <div class="suspicious-content">
                <div class="suspicious-icon">⚠️</div>
                <div class="suspicious-message">
                    <strong>Suspicious Site:</strong> This website shows some suspicious characteristics.
                    <span class="risk-score">Risk: ${analysis.risk_score}/100</span>
                </div>
                <div class="suspicious-actions">
                    <button class="btn-dismiss" onclick="this.dismissWarning()">Dismiss</button>
                    <button class="btn-more-info" onclick="this.showMoreInfo()">More Info</button>
                </div>
            </div>
        `;
        
        // Add styles
        this.addSuspiciousStyles();
        
        // Add to page
        document.body.appendChild(banner);
        
        // Setup events
        this.setupSuspiciousEvents(banner);
    }
    
    addWarningStyles() {
        if (document.getElementById('phishing-warning-styles')) return;
        
        const style = document.createElement('style');
        style.id = 'phishing-warning-styles';
        style.textContent = `
            .phishing-warning-overlay {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.8);
                z-index: 999999;
                display: flex;
                align-items: center;
                justify-content: center;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            }
            
            .phishing-warning-modal {
                background: white;
                border-radius: 12px;
                max-width: 500px;
                width: 90%;
                box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
                animation: warningSlideIn 0.3s ease-out;
            }
            
            @keyframes warningSlideIn {
                from { transform: scale(0.9); opacity: 0; }
                to { transform: scale(1); opacity: 1; }
            }
            
            .warning-header {
                background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
                color: white;
                padding: 20px;
                border-radius: 12px 12px 0 0;
                text-align: center;
            }
            
            .warning-icon {
                font-size: 48px;
                margin-bottom: 10px;
            }
            
            .warning-header h2 {
                font-size: 24px;
                font-weight: 600;
                margin: 0;
            }
            
            .warning-content {
                padding: 20px;
            }
            
            .warning-message p {
                margin: 0 0 10px 0;
                line-height: 1.5;
            }
            
            .risk-details {
                margin-top: 15px;
                padding: 15px;
                background: #f8fafc;
                border-radius: 8px;
                border-left: 4px solid #ef4444;
            }
            
            .risk-score, .detection-methods {
                margin-bottom: 8px;
            }
            
            .score-value {
                font-weight: 600;
            }
            
            .score-value.high { color: #ef4444; }
            .score-value.medium { color: #f59e0b; }
            .score-value.low { color: #10b981; }
            
            .methods {
                font-weight: 500;
                color: #374151;
            }
            
            .reasons ul {
                margin: 5px 0 0 0;
                padding-left: 20px;
            }
            
            .reasons li {
                margin-bottom: 3px;
                font-size: 14px;
                color: #6b7280;
            }
            
            .warning-actions {
                padding: 20px;
                display: flex;
                gap: 10px;
                justify-content: flex-end;
                border-top: 1px solid #e5e7eb;
            }
            
            .btn-leave, .btn-continue, .btn-report {
                padding: 10px 16px;
                border-radius: 6px;
                font-size: 14px;
                font-weight: 500;
                cursor: pointer;
                border: 1px solid;
                transition: all 0.2s ease;
            }
            
            .btn-leave {
                background: #ef4444;
                color: white;
                border-color: #ef4444;
            }
            
            .btn-leave:hover {
                background: #dc2626;
                border-color: #dc2626;
            }
            
            .btn-continue {
                background: white;
                color: #374151;
                border-color: #d1d5db;
            }
            
            .btn-continue:hover {
                background: #f9fafb;
            }
            
            .btn-report {
                background: #f3f4f6;
                color: #6b7280;
                border-color: #d1d5db;
            }
            
            .btn-report:hover {
                background: #e5e7eb;
            }
        `;
        
        document.head.appendChild(style);
    }
    
    addSuspiciousStyles() {
        if (document.getElementById('phishing-suspicious-styles')) return;
        
        const style = document.createElement('style');
        style.id = 'phishing-suspicious-styles';
        style.textContent = `
            .phishing-suspicious-banner {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                background: #fef3c7;
                border-bottom: 1px solid #f59e0b;
                z-index: 999999;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                animation: bannerSlideDown 0.3s ease-out;
            }
            
            @keyframes bannerSlideDown {
                from { transform: translateY(-100%); }
                to { transform: translateY(0); }
            }
            
            .suspicious-content {
                display: flex;
                align-items: center;
                padding: 12px 16px;
                gap: 12px;
            }
            
            .suspicious-icon {
                font-size: 20px;
                flex-shrink: 0;
            }
            
            .suspicious-message {
                flex: 1;
                font-size: 14px;
                color: #92400e;
                line-height: 1.4;
            }
            
            .risk-score {
                display: block;
                font-size: 12px;
                font-weight: 600;
                margin-top: 2px;
            }
            
            .suspicious-actions {
                display: flex;
                gap: 8px;
                flex-shrink: 0;
            }
            
            .btn-dismiss, .btn-more-info {
                padding: 6px 12px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: 500;
                cursor: pointer;
                border: 1px solid;
                transition: all 0.2s ease;
            }
            
            .btn-dismiss {
                background: #fbbf24;
                color: #92400e;
                border-color: #f59e0b;
            }
            
            .btn-dismiss:hover {
                background: #f59e0b;
                color: white;
            }
            
            .btn-more-info {
                background: white;
                color: #374151;
                border-color: #d1d5db;
            }
            
            .btn-more-info:hover {
                background: #f9fafb;
            }
        `;
        
        document.head.appendChild(style);
    }
    
    setupWarningEvents(overlay, analysis) {
        const leaveBtn = overlay.querySelector('.btn-leave');
        const continueBtn = overlay.querySelector('.btn-continue');
        const reportBtn = overlay.querySelector('.btn-report');
        
        leaveBtn.addEventListener('click', () => {
            this.leaveSite();
        });
        
        continueBtn.addEventListener('click', () => {
            this.continueAnyway(overlay);
        });
        
        reportBtn.addEventListener('click', () => {
            this.reportError(analysis);
        });
    }
    
    setupSuspiciousEvents(banner) {
        const dismissBtn = banner.querySelector('.btn-dismiss');
        const moreInfoBtn = banner.querySelector('.btn-more-info');
        
        dismissBtn.addEventListener('click', () => {
            this.dismissWarning(banner);
        });
        
        moreInfoBtn.addEventListener('click', () => {
            this.showMoreInfo();
        });
    }
    
    leaveSite() {
        // Navigate to safe page
        window.location.href = 'about:blank';
    }
    
    continueAnyway(overlay) {
        // Remove warning and allow page access
        document.body.removeChild(overlay);
        document.body.style.overflow = '';
        this.warningShown = false;
        
        // Log that user continued anyway
        chrome.runtime.sendMessage({
            action: 'userContinued',
            url: this.currentUrl
        });
    }
    
    reportError(analysis) {
        // Open report dialog
        chrome.runtime.sendMessage({
            action: 'reportPhishing',
            report: {
                url: this.currentUrl,
                reason: 'false_positive',
                description: 'User reported false positive detection'
            }
        });
        
        // Show confirmation
        this.showNotification('Report submitted. Thank you for your feedback.', 'info');
    }
    
    dismissWarning(banner) {
        document.body.removeChild(banner);
        this.warningShown = false;
    }
    
    showMoreInfo() {
        // Show detailed analysis in popup
        chrome.runtime.sendMessage({
            action: 'openPopup'
        });
    }
    
    checkFormSubmission(e) {
        const form = e.target;
        const formData = new FormData(form);
        
        // Check for sensitive fields
        const sensitiveFields = ['password', 'credit_card', 'ssn', 'social_security'];
        const hasSensitiveData = Array.from(formData.keys()).some(key =>
            sensitiveFields.some(field => key.toLowerCase().includes(field))
        );
        
        if (hasSensitiveData) {
            // Check if the page is suspicious
            chrome.runtime.sendMessage({
                action: 'checkFormSecurity',
                url: this.currentUrl,
                hasHttps: window.location.protocol === 'https:'
            });
        }
    }
    
    checkLinkClick(e) {
        const link = e.target.closest('a');
        if (!link) return;
        
        const href = link.href;
        if (!href) return;
        
        // Check if the link is external and suspicious
        try {
            const linkUrl = new URL(href);
            const currentUrl = new URL(this.currentUrl);
            
            if (linkUrl.origin !== currentUrl.origin) {
                chrome.runtime.sendMessage({
                    action: 'checkExternalLink',
                    url: href,
                    source: this.currentUrl
                });
            }
        } catch (error) {
            // Invalid URL, ignore
        }
    }
    
    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `phishing-notification ${type}`;
        notification.textContent = message;
        
        Object.assign(notification.style, {
            position: 'fixed',
            top: '20px',
            right: '20px',
            padding: '12px 16px',
            borderRadius: '8px',
            color: 'white',
            fontSize: '14px',
            fontWeight: '500',
            zIndex: '999999',
            boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
            animation: 'notificationSlideIn 0.3s ease'
        });
        
        const colors = {
            success: '#10b981',
            error: '#ef4444',
            warning: '#f59e0b',
            info: '#3b82f6'
        };
        
        notification.style.background = colors[type] || colors.info;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'notificationSlideOut 0.3s ease';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }
    
    removeWarnings() {
        // Remove all warning elements
        const overlay = document.getElementById('phishing-warning-overlay');
        const banner = document.getElementById('phishing-suspicious-banner');
        
        if (overlay) {
            document.body.removeChild(overlay);
            document.body.style.overflow = '';
        }
        
        if (banner) {
            document.body.removeChild(banner);
        }
        
        this.warningShown = false;
    }
}

// Initialize content script when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new PhishingDetectorContent();
    });
} else {
    new PhishingDetectorContent();
}