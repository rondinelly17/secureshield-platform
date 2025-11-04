// Global variables
let currentScanId = null;

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
});

function initializeApp() {
    updateStats();
    checkAPIStatus();
}

function setupEventListeners() {
    // File upload handling
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');
    
    uploadArea.addEventListener('click', () => fileInput.click());
    uploadArea.addEventListener('dragover', handleDragOver);
    uploadArea.addEventListener('drop', handleFileDrop);
    fileInput.addEventListener('change', handleFileSelect);
}

// Navigation
function showSection(sectionId) {
    // Hide all sections
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    });
    
    // Remove active class from all nav links
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    
    // Show target section
    document.getElementById(sectionId).classList.add('active');
    
    // Activate corresponding nav link
    document.querySelector(`[href="#${sectionId}"]`).classList.add('active');
    
    // Update stats when showing dashboard
    if (sectionId === 'dashboard') {
        updateStats();
    }
}

// Drag and drop handlers
function handleDragOver(e) {
    e.preventDefault();
    e.currentTarget.style.borderColor = '#2563eb';
    e.currentTarget.style.background = 'rgba(37, 99, 235, 0.1)';
}

function handleFileDrop(e) {
    e.preventDefault();
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        scanFile(files[0]);
    }
    resetUploadArea();
}

function handleFileSelect(e) {
    if (e.target.files.length > 0) {
        scanFile(e.target.files[0]);
    }
}

function resetUploadArea() {
    const uploadArea = document.getElementById('uploadArea');
    uploadArea.style.borderColor = '#e2e8f0';
    uploadArea.style.background = '';
}

// File scanning
async function scanFile(file) {
    if (!file) return;
    
    // Validate file size (32MB max)
    if (file.size > 32 * 1024 * 1024) {
        showNotification('File size exceeds 32MB limit', 'error');
        return;
    }
    
    showLoading('Scanning file with VirusTotal...');
    
    try {
        const formData = new FormData();
        formData.append('file', file);
        
        const response = await fetch('/api/virustotal/scan-file', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (result.data && result.data.id) {
            currentScanId = result.data.id;
            incrementStat('fileScans');
            pollScanResults(result.data.id);
        } else {
            throw new Error('Failed to start scan');
        }
        
    } catch (error) {
        hideLoading();
        showNotification('Error scanning file: ' + error.message, 'error');
        console.error('Scan error:', error);
    }
}

async function pollScanResults(scanId) {
    try {
        const response = await fetch(`/api/virustotal/analysis/${scanId}`);
        const result = await response.json();
        
        if (result.data && result.data.attributes) {
            const attributes = result.data.attributes;
            
            if (attributes.status === 'completed') {
                hideLoading();
                displayFileResults(attributes);
                // Check if threat was detected
                if (attributes.stats.malicious > 0) {
                    incrementStat('threats');
                }
                return;
            }
        }
        
        // If not completed, poll again after 5 seconds
        setTimeout(() => pollScanResults(scanId), 5000);
        
    } catch (error) {
        hideLoading();
        showNotification('Error checking scan results', 'error');
        console.error('Poll error:', error);
    }
}

function displayFileResults(attributes) {
    const resultsDiv = document.getElementById('fileResults');
    const contentDiv = document.getElementById('fileResultContent');
    
    const stats = attributes.stats;
    const totalEngines = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;
    const detectionRate = totalEngines > 0 ? (stats.malicious / totalEngines * 100).toFixed(1) : 0;
    
    let resultsHTML = `
        <div class="result-summary ${stats.malicious > 0 ? 'danger' : 'success'}">
            <h4>${stats.malicious > 0 ? '🚨 THREAT DETECTED' : '✅ FILE CLEAN'}</h4>
            <p>Detection Rate: <strong>${detectionRate}%</strong> (${stats.malicious}/${totalEngines} engines)</p>
        </div>
        
        <div class="result-details">
            <h5>Scan Statistics:</h5>
            <div class="stats-grid-small">
                <div class="stat-item malicious">
                    <span class="stat-label">Malicious</span>
                    <span class="stat-value">${stats.malicious}</span>
                </div>
                <div class="stat-item suspicious">
                    <span class="stat-label">Suspicious</span>
                    <span class="stat-value">${stats.suspicious}</span>
                </div>
                <div class="stat-item undetected">
                    <span class="stat-label">Undetected</span>
                    <span class="stat-value">${stats.undetected}</span>
                </div>
                <div class="stat-item harmless">
                    <span class="stat-label">Harmless</span>
                    <span class="stat-value">${stats.harmless}</span>
                </div>
            </div>
    `;
    
    // Add engine results if available
    if (attributes.results) {
        const maliciousEngines = Object.entries(attributes.results).filter(([_, result]) => 
            result.category === 'malicious' || result.category === 'suspicious'
        );
        
        if (maliciousEngines.length > 0) {
            resultsHTML += `<h5>Threat Detections:</h5><div class="engine-results">`;
            
            maliciousEngines.forEach(([engine, result]) => {
                resultsHTML += `
                    <div class="engine-result ${result.category}">
                        <span class="engine-name">${engine}</span>
                        <span class="engine-result">${result.result || result.category}</span>
                    </div>
                `;
            });
            
            resultsHTML += `</div>`;
        }
    }
    
    resultsHTML += `</div>`;
    
    contentDiv.innerHTML = resultsHTML;
    resultsDiv.style.display = 'block';
    
    // Scroll to results
    resultsDiv.scrollIntoView({ behavior: 'smooth' });
}

// IP Reputation Check
async function checkIP() {
    const ipInput = document.getElementById('ipInput');
    const ip = ipInput.value.trim();
    
    if (!ip) {
        showNotification('Please enter an IP address', 'warning');
        return;
    }
    
    // Basic IP validation
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) {
        showNotification('Please enter a valid IP address', 'warning');
        return;
    }
    
    showLoading('Checking IP reputation...');
    
    try {
        const response = await fetch(`/api/abuseipdb/check-ip/${ip}`);
        const result = await response.json();
        
        hideLoading();
        incrementStat('ipChecks');
        
        if (result.data && result.data.abuseConfidenceScore > 50) {
            incrementStat('threats');
        }
        
        displayIPResults(result.data);
        
    } catch (error) {
        hideLoading();
        showNotification('Error checking IP reputation', 'error');
        console.error('IP check error:', error);
    }
}

function displayIPResults(data) {
    const resultsDiv = document.getElementById('ipResults');
    const contentDiv = document.getElementById('ipResultContent');
    
    const isMalicious = data.abuseConfidenceScore >= 50;
    const lastReported = data.lastReportedAt ? new Date(data.lastReportedAt).toLocaleDateString() : 'Never';
    
    let resultsHTML = `
        <div class="result-summary ${isMalicious ? 'danger' : 'success'}">
            <h4>${isMalicious ? '🚨 SUSPICIOUS IP' : '✅ CLEAN IP'}</h4>
            <p>Abuse Confidence Score: <strong>${data.abuseConfidenceScore}%</strong></p>
        </div>
        
        <div class="result-details">
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-label">IP Address:</span>
                    <span class="info-value">${data.ipAddress}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">ISP:</span>
                    <span class="info-value">${data.isp || 'Unknown'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Country:</span>
                    <span class="info-value">${data.countryCode || 'Unknown'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Domain:</span>
                    <span class="info-value">${data.domain || 'Unknown'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Total Reports:</span>
                    <span class="info-value">${data.totalReports || 0}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Last Reported:</span>
                    <span class="info-value">${lastReported}</span>
                </div>
            </div>
    `;
    
    if (isMalicious) {
        resultsHTML += `
            <div class="warning-message">
                <i class="fas fa-exclamation-triangle"></i>
                This IP has been reported multiple times for malicious activity.
            </div>
        `;
    }
    
    resultsHTML += `</div>`;
    
    contentDiv.innerHTML = resultsHTML;
    resultsDiv.style.display = 'block';
    resultsDiv.scrollIntoView({ behavior: 'smooth' });
}

// URL Analysis
async function analyzeURL() {
    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();
    
    if (!url) {
        showNotification('Please enter a URL', 'warning');
        return;
    }
    
    // Basic URL validation
    try {
        new URL(url);
    } catch {
        showNotification('Please enter a valid URL', 'warning');
        return;
    }
    
    showLoading('Analyzing URL with Hybrid Analysis...');
    
    try {
        const response = await fetch('/api/hybridanalysis/scan-url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });
        
        const result = await response.json();
        
        hideLoading();
        incrementStat('urlAnalyses');
        
        // Check if threat was detected (simplified logic)
        if (result.threat_level && result.threat_level > 1) {
            incrementStat('threats');
        }
        
        displayURLResults(result);
        
    } catch (error) {
        hideLoading();
        showNotification('Error analyzing URL', 'error');
        console.error('URL analysis error:', error);
    }
}

function displayURLResults(data) {
    const resultsDiv = document.getElementById('urlResults');
    const contentDiv = document.getElementById('urlResultContent');
    
    // Simplified threat detection logic
    const isMalicious = data.threat_level > 1 || data.threat_score > 5;
    
    let resultsHTML = `
        <div class="result-summary ${isMalicious ? 'danger' : 'success'}">
            <h4>${isMalicious ? '🚨 SUSPICIOUS URL' : '✅ CLEAN URL'}</h4>
            <p>Analysis completed with Hybrid Analysis</p>
        </div>
        
        <div class="result-details">
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-label">Threat Level:</span>
                    <span class="info-value">${data.threat_level || 'Unknown'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Threat Score:</span>
                    <span class="info-value">${data.threat_score || 'N/A'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Verdict:</span>
                    <span class="info-value">${data.verdict || 'Unknown'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Analysis Time:</span>
                    <span class="info-value">${new Date().toLocaleString()}</span>
                </div>
            </div>
    `;
    
    if (data.tags && data.tags.length > 0) {
        resultsHTML += `<h5>Detected Tags:</h5><div class="tags-list">`;
        
        data.tags.forEach(tag => {
            resultsHTML += `<span class="tag">${tag}</span>`;
        });
        
        resultsHTML += `</div>`;
    }
    
    resultsHTML += `</div>`;
    
    contentDiv.innerHTML = resultsHTML;
    resultsDiv.style.display = 'block';
    resultsDiv.scrollIntoView({ behavior: 'smooth' });
}

// Stats management (without database)
function updateStats() {
    // Get from localStorage or initialize
    let fileScans = parseInt(localStorage.getItem('fileScans') || '0');
    let ipChecks = parseInt(localStorage.getItem('ipChecks') || '0');
    let urlAnalyses = parseInt(localStorage.getItem('urlAnalyses') || '0');
    let threats = parseInt(localStorage.getItem('threats') || '0');
    
    // Update display
    document.getElementById('file-scans-count').textContent = fileScans;
    document.getElementById('ip-checks-count').textContent = ipChecks;
    document.getElementById('url-analyses-count').textContent = urlAnalyses;
    document.getElementById('threats-count').textContent = threats;
}

function incrementStat(statName) {
    const current = parseInt(localStorage.getItem(statName) || '0');
    localStorage.setItem(statName, (current + 1).toString());
    updateStats();
}

// Utility Functions
function showLoading(message = 'Processing...') {
    const modal = document.getElementById('loadingModal');
    const modalText = modal.querySelector('p');
    modalText.textContent = message;
    modal.style.display = 'flex';
}

function hideLoading() {
    const modal = document.getElementById('loadingModal');
    modal.style.display = 'none';
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <span class="notification-message">${message}</span>
        <button class="notification-close" onclick="this.parentElement.remove()">×</button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}

async function checkAPIStatus() {
    try {
        // Test backend connectivity
        const response = await fetch('/api/health');
        if (!response.ok) throw new Error('Backend not responding');
        
        console.log('✅ Backend API is connected');
    } catch (error) {
        console.error('❌ Backend API connection failed:', error);
        showNotification('Backend service is unavailable', 'error');
    }
}

// Add warning message style
const warningStyle = document.createElement('style');
warningStyle.textContent = `
    .warning-message {
        background: #fef3c7;
        border: 1px solid #f59e0b;
        border-radius: 6px;
        padding: 1rem;
        margin: 1rem 0;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        color: #92400e;
    }
    
    .warning-message i {
        color: #f59e0b;
    }
    
    .engine-name {
        font-weight: 600;
    }
    
    .engine-result {
        font-style: italic;
        color: #dc2626;
    }
`;
document.head.appendChild(warningStyle);
