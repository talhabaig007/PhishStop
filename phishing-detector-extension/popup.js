// Phishing Detector Popup JavaScript
document.addEventListener('DOMContentLoaded', function() {
    initializePopup();
});

async function initializePopup() {
    try {
        // Load current tab information
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        if (tab && tab.url) {
            document.getElementById('currentUrl').textContent = tab.url;
            
            // Analyze current URL
            await analyzeUrl(tab.url);
        }
        
        // Load statistics
        await loadStatistics();
        
        // Setup event listeners
        setupEventListeners();
        
        // Load settings
        await loadSettings();
        
    } catch (error) {
        console.error('Error initializing popup:', error);
        showError('Failed to initialize popup');
    }
}

async function analyzeUrl(url) {
    try {
        showLoading();
        
        // Send URL to background script for analysis
        const response = await chrome.runtime.sendMessage({
            action: 'analyzeUrl',
            url: url
        });
        
        if (response && response.success) {
            displayAnalysisResults(response.results);
        } else {
            showError(response?.error || 'Analysis failed');
        }
        
    } catch (error) {
        console.error('Error analyzing URL:', error);
        showError('Failed to analyze URL');
    } finally {
        hideLoading();
    }
}

function displayAnalysisResults(results) {
    const riskScore = results.risk_score || 0;
    const confidence = results.confidence || 0;
    const isPhishing = results.is_phishing;
    const detectionMethods = results.detection_methods || [];
    const reasons = results.reasons || [];
    
    // Update risk score
    document.getElementById('riskScore').textContent = `${riskScore}/100`;
    
    // Update score bar
    const scoreFill = document.getElementById('scoreFill');
    scoreFill.style.width = `${riskScore}%`;
    
    // Set color based on risk level
    if (riskScore >= 60) {
        scoreFill.style.background = '#ef4444'; // Red
    } else if (riskScore >= 40) {
        scoreFill.style.background = '#f59e0b'; // Yellow
    } else {
        scoreFill.style.background = '#10b981'; // Green
    }
    
    // Update confidence
    document.getElementById('confidenceLevel').textContent = `${confidence}%`;
    
    // Update detection methods
    const methodsList = document.getElementById('methodsList');
    methodsList.innerHTML = '';
    
    detectionMethods.forEach(method => {
        const tag = document.createElement('span');
        tag.className = 'method-tag';
        tag.textContent = method.replace('_', ' ').toUpperCase();
        methodsList.appendChild(tag);
    });
    
    // Update status indicator
    const statusIndicator = document.getElementById('statusIndicator');
    const statusDot = statusIndicator.querySelector('.status-dot');
    const statusText = statusIndicator.querySelector('.status-text');
    
    if (isPhishing === true) {
        statusDot.style.background = '#ef4444';
        statusText.textContent = 'Phishing Detected';
        statusText.className = 'status-text error';
    } else if (isPhishing === null) {
        statusDot.style.background = '#f59e0b';
        statusText.textContent = 'Suspicious';
        statusText.className = 'status-text warning';
    } else {
        statusDot.style.background = '#10b981';
        statusText.textContent = 'Safe';
        statusText.className = 'status-text success';
    }
    
    // Animate the results
    const resultElement = document.getElementById('analysisResult');
    resultElement.classList.add('fade-in');
}

async function loadStatistics() {
    try {
        const response = await chrome.runtime.sendMessage({
            action: 'getStatistics'
        });
        
        if (response && response.success) {
            const stats = response.statistics;
            
            document.getElementById('totalAnalyzed').textContent = stats.total_analyzed || 0;
            document.getElementById('phishingDetected').textContent = stats.phishing_detected || 0;
            document.getElementById('avgRiskScore').textContent = stats.avg_risk_score || 0;
        }
    } catch (error) {
        console.error('Error loading statistics:', error);
    }
}

function setupEventListeners() {
    // Analyze button
    document.getElementById('analyzeBtn').addEventListener('click', async () => {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url) {
            await analyzeUrl(tab.url);
        }
    });
    
    // Report button
    document.getElementById('reportBtn').addEventListener('click', showReportModal);
    
    // Settings checkboxes
    document.getElementById('realTimeProtection').addEventListener('change', saveSettings);
    document.getElementById('blockPages').addEventListener('change', saveSettings);
    document.getElementById('showWarnings').addEventListener('change', saveSettings);
    
    // Modal controls
    document.getElementById('closeModal').addEventListener('click', hideReportModal);
    document.getElementById('cancelReport').addEventListener('click', hideReportModal);
    
    // Report form
    document.getElementById('reportForm').addEventListener('submit', handleReportSubmit);
    
    // Help link
    document.getElementById('helpLink').addEventListener('click', openHelpPage);
    
    // Close modal when clicking outside
    document.getElementById('reportModal').addEventListener('click', (e) => {
        if (e.target.id === 'reportModal') {
            hideReportModal();
        }
    });
}

async function loadSettings() {
    try {
        const settings = await chrome.storage.sync.get([
            'realTimeProtection',
            'blockPages',
            'showWarnings'
        ]);
        
        document.getElementById('realTimeProtection').checked = 
            settings.realTimeProtection !== false;
        document.getElementById('blockPages').checked = 
            settings.blockPages !== false;
        document.getElementById('showWarnings').checked = 
            settings.showWarnings !== false;
            
    } catch (error) {
        console.error('Error loading settings:', error);
    }
}

async function saveSettings() {
    try {
        const settings = {
            realTimeProtection: document.getElementById('realTimeProtection').checked,
            blockPages: document.getElementById('blockPages').checked,
            showWarnings: document.getElementById('showWarnings').checked
        };
        
        await chrome.storage.sync.set(settings);
        
        // Notify background script about settings change
        chrome.runtime.sendMessage({
            action: 'updateSettings',
            settings: settings
        });
        
    } catch (error) {
        console.error('Error saving settings:', error);
    }
}

function showReportModal() {
    const modal = document.getElementById('reportModal');
    const [tab] = chrome.tabs.query({ active: true, currentWindow: true });
    
    if (tab && tab.url) {
        document.getElementById('reportUrl').value = tab.url;
    }
    
    modal.style.display = 'block';
    document.body.style.overflow = 'hidden';
}

function hideReportModal() {
    const modal = document.getElementById('reportModal');
    modal.style.display = 'none';
    document.body.style.overflow = 'auto';
    
    // Reset form
    document.getElementById('reportForm').reset();
}

async function handleReportSubmit(e) {
    e.preventDefault();
    
    const formData = {
        url: document.getElementById('reportUrl').value,
        reason: document.getElementById('reportReason').value,
        description: document.getElementById('reportDescription').value
    };
    
    try {
        // Send report to background script
        const response = await chrome.runtime.sendMessage({
            action: 'reportPhishing',
            report: formData
        });
        
        if (response && response.success) {
            showNotification('Report submitted successfully!', 'success');
            hideReportModal();
        } else {
            showNotification('Failed to submit report', 'error');
        }
        
    } catch (error) {
        console.error('Error submitting report:', error);
        showNotification('Failed to submit report', 'error');
    }
}

function openHelpPage(e) {
    e.preventDefault();
    chrome.tabs.create({ url: 'https://github.com/phishing-detector/help' });
}

function showLoading() {
    const analyzeBtn = document.getElementById('analyzeBtn');
    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = '<span class="btn-icon">⏳</span>Analyzing...';
}

function hideLoading() {
    const analyzeBtn = document.getElementById('analyzeBtn');
    analyzeBtn.disabled = false;
    analyzeBtn.innerHTML = '<span class="btn-icon">🔍</span>Analyze Current Page';
}

function showError(message) {
    const riskScore = document.getElementById('riskScore');
    riskScore.textContent = 'Error';
    riskScore.className = 'score-value error';
    
    const confidenceLevel = document.getElementById('confidenceLevel');
    confidenceLevel.textContent = message;
    confidenceLevel.className = 'confidence-value error';
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    // Style the notification
    Object.assign(notification.style, {
        position: 'fixed',
        top: '20px',
        right: '20px',
        padding: '12px 16px',
        borderRadius: '8px',
        color: 'white',
        fontSize: '14px',
        fontWeight: '500',
        zIndex: '10000',
        boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
        animation: 'slideIn 0.3s ease'
    });
    
    // Set background color based on type
    const colors = {
        success: '#10b981',
        error: '#ef4444',
        warning: '#f59e0b',
        info: '#3b82f6'
    };
    
    notification.style.background = colors[type] || colors.info;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, 3000);
}

// Add CSS animations for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);