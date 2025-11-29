// Background Script for Phishing Detector Extension
class PhishingDetectorBackground {
    constructor() {
        this.apiEndpoint = 'http://localhost:5000';
        this.settings = {};
        this.cache = new Map();
        this.init();
    }
    
    async init() {
        await this.loadSettings();
        this.setupEventListeners();
        this.setupWebNavigation();
        this.setupWebRequest();
        console.log('Phishing Detector Background Script Initialized');
    }
    
    async loadSettings() {
        try {
            const stored = await chrome.storage.sync.get([
                'realTimeProtection',
                'blockPages',
                'showWarnings'
            ]);
            
            this.settings = {
                realTimeProtection: stored.realTimeProtection !== false,
                blockPages: stored.blockPages !== false,
                showWarnings: stored.showWarnings !== false
            };
        } catch (error) {
            console.error('Error loading settings:', error);
            this.settings = {
                realTimeProtection: true,
                blockPages: true,
                showWarnings: true
            };
        }
    }
    
    setupEventListeners() {
        // Handle messages from popup and content scripts
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            this.handleMessage(request, sender, sendResponse);
            return true; // Keep message channel open for async response
        });
        
        // Handle storage changes
        chrome.storage.onChanged.addListener((changes, namespace) => {
            if (namespace === 'sync') {
                this.handleSettingsChange(changes);
            }
        });
        
        // Handle extension installation/update
        chrome.runtime.onInstalled.addListener((details) => {
            this.handleInstallation(details);
        });
    }
    
    setupWebNavigation() {
        // Monitor page navigation for real-time protection
        chrome.webNavigation.onCommitted.addListener((details) => {
            if (this.settings.realTimeProtection && details.url) {
                this.checkUrlSafety(details.url, details.tabId);
            }
        });
        
        chrome.webNavigation.onBeforeNavigate.addListener((details) => {
            if (this.settings.realTimeProtection && details.url) {
                this.preCheckUrl(details.url, details.tabId);
            }
        });
    }
    
    setupWebRequest() {
        // Monitor web requests for additional security
        chrome.webRequest.onBeforeRequest.addListener(
            (details) => {
                if (this.settings.realTimeProtection && details.url) {
                    return this.handleWebRequest(details);
                }
            },
            { urls: ['<all_urls>'] },
            ['blocking']
        );
    }
    
    async handleMessage(request, sender, sendResponse) {
        try {
            switch (request.action) {
                case 'analyzeUrl':
                    const result = await this.analyzeUrl(request.url);
                    sendResponse({ success: true, results: result });
                    break;
                    
                case 'getStatistics':
                    const stats = await this.getStatistics();
                    sendResponse({ success: true, statistics: stats });
                    break;
                    
                case 'reportPhishing':
                    await this.reportPhishing(request.report);
                    sendResponse({ success: true });
                    break;
                    
                case 'updateSettings':
                    this.settings = { ...this.settings, ...request.settings };
                    sendResponse({ success: true });
                    break;
                    
                case 'getSettings':
                    sendResponse({ success: true, settings: this.settings });
                    break;
                    
                default:
                    sendResponse({ success: false, error: 'Unknown action' });
            }
        } catch (error) {
            console.error('Error handling message:', error);
            sendResponse({ success: false, error: error.message });
        }
    }
    
    async analyzeUrl(url) {
        // Check cache first
        const cacheKey = url;
        if (this.cache.has(cacheKey)) {
            const cached = this.cache.get(cacheKey);
            if (Date.now() - cached.timestamp < 300000) { // 5 minutes cache
                return cached.result;
            }
        }
        
        try {
            const response = await fetch(`${this.apiEndpoint}/analyze`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const result = await response.json();
            
            // Cache the result
            this.cache.set(cacheKey, {
                result: result,
                timestamp: Date.now()
            });
            
            return result;
            
        } catch (error) {
            console.error('Error analyzing URL:', error);
            // Fallback to local analysis
            return this.fallbackAnalysis(url);
        }
    }
    
    async fallbackAnalysis(url) {
        // Simple heuristic-based fallback analysis
        const result = {
            url: url,
            risk_score: 0,
            is_phishing: false,
            confidence: 0,
            detection_methods: ['fallback'],
            reasons: []
        };
        
        try {
            const urlObj = new URL(url);
            
            // Check for suspicious patterns
            if (url.length > 100) {
                result.risk_score += 10;
                result.reasons.push('Very long URL');
            }
            
            // Check for IP addresses
            if (/^\d+\.\d+\.\d+\.\d+$/.test(urlObj.hostname)) {
                result.risk_score += 50;
                result.reasons.push('Uses IP address');
                result.is_phishing = true;
            }
            
            // Check for suspicious TLDs
            const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq'];
            if (suspiciousTlds.some(tld => urlObj.hostname.endsWith(tld))) {
                result.risk_score += 30;
                result.reasons.push('Suspicious TLD');
            }
            
            // Check for HTTPS
            if (urlObj.protocol !== 'https:') {
                result.risk_score += 20;
                result.reasons.push('Not using HTTPS');
            }
            
            // Check for excessive subdomains
            const subdomainCount = urlObj.hostname.split('.').length - 2;
            if (subdomainCount > 2) {
                result.risk_score += 15;
                result.reasons.push('Excessive subdomains');
            }
            
            // Final classification
            if (result.risk_score >= 60) {
                result.is_phishing = true;
            } else if (result.risk_score >= 40) {
                result.is_phishing = null; // Suspicious
            }
            
            result.confidence = Math.min(result.risk_score * 1.5, 100);
            
        } catch (error) {
            console.error('Error in fallback analysis:', error);
            result.risk_score = 0;
            result.is_phishing = false;
            result.confidence = 0;
        }
        
        return result;
    }
    
    async checkUrlSafety(url, tabId) {
        try {
            const result = await this.analyzeUrl(url);
            
            if (result.is_phishing === true) {
                if (this.settings.blockPages) {
                    this.blockMaliciousPage(tabId, url, result);
                } else if (this.settings.showWarnings) {
                    this.showWarning(tabId, url, result);
                }
            } else if (result.is_phishing === null) {
                if (this.settings.showWarnings) {
                    this.showSuspiciousWarning(tabId, url, result);
                }
            }
            
            // Store analysis result
            await this.storeAnalysis(result);
            
        } catch (error) {
            console.error('Error checking URL safety:', error);
        }
    }
    
    async preCheckUrl(url, tabId) {
        // Quick pre-check before navigation
        try {
            const result = await this.analyzeUrl(url);
            
            if (result.is_phishing === true && this.settings.blockPages) {
                // Cancel navigation if it's a known phishing site
                chrome.tabs.remove(tabId);
                this.showBlockedNotification(url, result);
            }
            
        } catch (error) {
            console.error('Error in pre-check:', error);
        }
    }
    
    handleWebRequest(details) {
        // Handle web request blocking
        if (this.settings.blockPages && details.type === 'main_frame') {
            // This is a simplified check - in production, you'd want to
            // use a more sophisticated approach
            return { cancel: false };
        }
        
        return { cancel: false };
    }
    
    async blockMaliciousPage(tabId, url, analysis) {
        try {
            const blockUrl = chrome.runtime.getURL('warning.html') + 
                `?url=${encodeURIComponent(url)}&action=block`;
            
            chrome.tabs.update(tabId, { url: blockUrl });
            
            // Log the block action
            console.log(`Blocked phishing site: ${url}`);
            
        } catch (error) {
            console.error('Error blocking page:', error);
        }
    }
    
    async showWarning(tabId, url, analysis) {
        try {
            // Inject warning into the page
            await chrome.tabs.sendMessage(tabId, {
                action: 'showWarning',
                url: url,
                analysis: analysis
            });
            
        } catch (error) {
            console.error('Error showing warning:', error);
        }
    }
    
    async showSuspiciousWarning(tabId, url, analysis) {
        try {
            await chrome.tabs.sendMessage(tabId, {
                action: 'showSuspiciousWarning',
                url: url,
                analysis: analysis
            });
            
        } catch (error) {
            console.error('Error showing suspicious warning:', error);
        }
    }
    
    showBlockedNotification(url, analysis) {
        // Show a notification that the page was blocked
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: 'Phishing Site Blocked',
            message: `Blocked access to: ${new URL(url).hostname}`,
            buttons: [
                { title: 'Report Error' },
                { title: 'More Info' }
            ]
        });
    }
    
    async getStatistics() {
        try {
            const response = await fetch(`${this.apiEndpoint}/statistics`);
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            return await response.json();
            
        } catch (error) {
            console.error('Error getting statistics:', error);
            return {
                total_analyzed: 0,
                phishing_detected: 0,
                avg_risk_score: 0
            };
        }
    }
    
    async reportPhishing(report) {
        try {
            const response = await fetch(`${this.apiEndpoint}/blacklist`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    domain: new URL(report.url).hostname,
                    reason: report.reason
                })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            console.log('Phishing report submitted:', report);
            
        } catch (error) {
            console.error('Error reporting phishing:', error);
            throw error;
        }
    }
    
    async storeAnalysis(result) {
        try {
            // Store in local storage for statistics
            const key = `analysis_${Date.now()}`;
            await chrome.storage.local.set({
                [key]: result
            });
            
            // Clean up old entries (keep last 1000)
            const stored = await chrome.storage.local.get();
            const analysisKeys = Object.keys(stored).filter(key => 
                key.startsWith('analysis_')
            ).sort().slice(0, -1000);
            
            if (analysisKeys.length > 0) {
                await chrome.storage.local.remove(analysisKeys);
            }
            
        } catch (error) {
            console.error('Error storing analysis:', error);
        }
    }
    
    handleSettingsChange(changes) {
        for (const key in changes) {
            this.settings[key] = changes[key].newValue;
        }
        console.log('Settings updated:', this.settings);
    }
    
    handleInstallation(details) {
        if (details.reason === 'install') {
            console.log('Phishing Detector installed');
            // Set default settings
            chrome.storage.sync.set({
                realTimeProtection: true,
                blockPages: true,
                showWarnings: true
            });
        } else if (details.reason === 'update') {
            console.log('Phishing Detector updated');
        }
    }
}

// Initialize the background script
const phishingDetector = new PhishingDetectorBackground();