/**
 * Professional Popup Script for Phish-Shield
 * Handles UI updates with smooth animations and modern interactions
 */

// UI Elements
const elements = {
  loading: document.getElementById('loading'),
  content: document.getElementById('content'),
  error: document.getElementById('error'),
  
  // Status Card
  statusCard: document.getElementById('status-card'),
  statusIcon: document.getElementById('status-icon'),
  statusIconBg: document.getElementById('status-icon-bg'),
  statusText: document.getElementById('status-text'),
  statusSubtitle: document.getElementById('status-subtitle'),
  
  // URL
  currentUrl: document.getElementById('current-url'),
  copyUrlBtn: document.getElementById('copy-url-btn'),
  
  // Risk Meter
  riskScoreLarge: document.getElementById('risk-score-large'),
  progressRing: document.getElementById('progress-ring'),
  riskLevelBadge: document.getElementById('risk-level-badge'),
  riskLevelText: document.getElementById('risk-level-text'),
  riskMessage: document.getElementById('risk-message'),
  
  // Detection Items
  heuristicItem: document.getElementById('heuristic-item'),
  heuristicDot: document.getElementById('heuristic-dot'),
  heuristicValue: document.getElementById('heuristic-value'),
  
  threatItem: document.getElementById('threat-item'),
  threatDot: document.getElementById('threat-dot'),
  threatValue: document.getElementById('threat-value'),
  
  mlItem: document.getElementById('ml-item'),
  mlDot: document.getElementById('ml-dot'),
  mlValue: document.getElementById('ml-value'),
  
  detectionMethod: document.getElementById('detection-method'),
  
  // Technical Details
  technicalDetails: document.getElementById('technical-details'),
  toggleDetailsBtn: document.getElementById('toggle-details'),
  expandIcon: document.getElementById('expand-icon'),
  heuristicDetails: document.getElementById('heuristic-details'),
  threatIntelDetails: document.getElementById('threat-intel-details'),
  mlDetails: document.getElementById('ml-details'),
  scanTime: document.getElementById('scan-time'),
  
  // Actions
  rescanBtn: document.getElementById('rescan-btn'),
  retryBtn: document.getElementById('retry-btn'),
  errorMessage: document.getElementById('error-message')
};

let currentTabId = null;
let currentUrl = null;

/**
 * Initialize popup
 */
async function init() {
  try {
    // Get current tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab) {
      showError('No active tab found');
      return;
    }
    
    currentTabId = tab.id;
    currentUrl = tab.url;
    
    // Skip internal pages
    if (currentUrl.startsWith('chrome://') || 
        currentUrl.startsWith('chrome-extension://') ||
        currentUrl.startsWith('about:')) {
      showError('Cannot scan internal Chrome pages');
      return;
    }
    
    // Display current URL
    elements.currentUrl.textContent = currentUrl;
    elements.currentUrl.title = currentUrl;
    
    // Get scan result from background script
    chrome.runtime.sendMessage(
      { action: 'getScanResult', tabId: currentTabId },
      (result) => {
        if (result) {
          displayResult(result);
        } else {
          setTimeout(() => {
            chrome.runtime.sendMessage(
              { action: 'getScanResult', tabId: currentTabId },
              (retryResult) => {
                if (retryResult) {
                  displayResult(retryResult);
                } else {
                  showError('Scan in progress... Please wait and try again.');
                }
              }
            );
          }, 1000);
        }
      }
    );
    
  } catch (error) {
    console.error('Error initializing popup:', error);
    showError('Failed to initialize: ' + error.message);
  }
}

/**
 * Display scan result with animations
 */
function displayResult(result) {
  // Hide loading, show content
  elements.loading.style.display = 'none';
  elements.error.style.display = 'none';
  elements.content.style.display = 'block';
  
  // Update status card with animation
  updateStatusCard(result);
  
  // Update risk score with circular progress
  updateRiskScore(result);
  
  // Update detection layers
  updateDetectionLayers(result);
  
  // Update technical details
  if (result.details) {
    updateTechnicalDetails(result.details);
  }
  
  // Format timestamp
  if (result.timestamp) {
    const date = new Date(result.timestamp);
    elements.scanTime.textContent = date.toLocaleString();
  }
}

/**
 * Update status card with smooth transitions
 */
function updateStatusCard(result) {
  const status = result.status;
  const riskScore = result.risk_score || 0;
  
  // Determine status level
  let statusLevel, statusIcon, statusTitle, statusSubtitle, bgGradient;
  
  if (status === 'error') {
    statusLevel = 'error';
    statusIcon = '⚠️';
    statusTitle = 'Error';
    statusSubtitle = 'Unable to complete scan';
    bgGradient = 'linear-gradient(135deg, #E5E7EB 0%, #D1D5DB 100%)';
  } else if (riskScore >= 75) {
    statusLevel = 'danger';
    statusIcon = '🛑';
    statusTitle = 'Dangerous';
    statusSubtitle = 'High risk detected';
    bgGradient = 'linear-gradient(135deg, #FEE2E2 0%, #FCA5A5 100%)';
  } else if (riskScore >= 50) {
    statusLevel = 'warning';
    statusIcon = '⚠️';
    statusTitle = 'Suspicious';
    statusSubtitle = 'Multiple warning signs';
    bgGradient = 'linear-gradient(135deg, #FED7AA 0%, #FDBA74 100%)';
  } else if (riskScore >= 25) {
    statusLevel = 'caution';
    statusIcon = '⚡';
    statusTitle = 'Caution';
    statusSubtitle = 'Minor concerns detected';
    bgGradient = 'linear-gradient(135deg, #FEF3C7 0%, #FDE68A 100%)';
  } else {
    statusLevel = 'safe';
    statusIcon = '✅';
    statusTitle = 'Safe';
    statusSubtitle = 'No threats detected';
    bgGradient = 'linear-gradient(135deg, #D1FAE5 0%, #A7F3D0 100%)';
  }
  
  // Update card classes
  elements.statusCard.className = 'status-card status-' + statusLevel;
  
  // Animate icon change
  elements.statusIcon.style.transform = 'scale(0)';
  setTimeout(() => {
    elements.statusIcon.textContent = statusIcon;
    elements.statusIcon.style.transform = 'scale(1)';
  }, 150);
  
  // Update background
  elements.statusIconBg.style.background = bgGradient;
  
  // Update text
  elements.statusText.textContent = statusTitle;
  elements.statusSubtitle.textContent = statusSubtitle;
}

/**
 * Update risk score with circular progress animation
 */
function updateRiskScore(result) {
  const riskScore = result.risk_score || 0;
  
  // Animate number
  animateNumber(elements.riskScoreLarge, 0, riskScore, 1000);
  
  // Update circular progress
  const circumference = 2 * Math.PI * 52; // radius = 52
  const offset = circumference - (riskScore / 100) * circumference;
  
  // Add gradient definition if not exists
  if (!document.querySelector('#progress-gradient')) {
    const svg = elements.progressRing.closest('svg');
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    const gradient = document.createElementNS('http://www.w3.org/2000/svg', 'linearGradient');
    gradient.id = 'progress-gradient';
    gradient.setAttribute('x1', '0%');
    gradient.setAttribute('y1', '0%');
    gradient.setAttribute('x2', '100%');
    gradient.setAttribute('y2', '100%');
    
    let color1, color2;
    if (riskScore >= 75) {
      color1 = '#DC2626';
      color2 = '#EF4444';
    } else if (riskScore >= 50) {
      color1 = '#F97316';
      color2 = '#FB923C';
    } else if (riskScore >= 25) {
      color1 = '#F59E0B';
      color2 = '#FBBF24';
    } else {
      color1 = '#10B981';
      color2 = '#34D399';
    }
    
    const stop1 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
    stop1.setAttribute('offset', '0%');
    stop1.setAttribute('stop-color', color1);
    
    const stop2 = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
    stop2.setAttribute('offset', '100%');
    stop2.setAttribute('stop-color', color2);
    
    gradient.appendChild(stop1);
    gradient.appendChild(stop2);
    defs.appendChild(gradient);
    svg.insertBefore(defs, svg.firstChild);
  }
  
  elements.progressRing.style.strokeDashoffset = offset;
  
  // Update risk level badge
  let badgeClass, badgeText, message;
  
  if (riskScore >= 75) {
    badgeClass = 'danger';
    badgeText = 'High Risk';
    message = 'This website shows strong indicators of being malicious. Do not enter any personal information.';
  } else if (riskScore >= 50) {
    badgeClass = 'warning';
    badgeText = 'Suspicious';
    message = 'Multiple suspicious patterns detected. Exercise caution when interacting with this site.';
  } else if (riskScore >= 25) {
    badgeClass = 'caution';
    badgeText = 'Low Risk';
    message = 'Some minor concerns detected. Verify the website legitimacy before providing sensitive data.';
  } else {
    badgeClass = 'safe';
    badgeText = 'Secure';
    message = 'This website appears legitimate with no significant security concerns detected.';
  }
  
  elements.riskLevelBadge.className = 'risk-level-badge ' + badgeClass;
  elements.riskLevelText.textContent = badgeText;
  elements.riskMessage.textContent = message;
}

/**
 * Update detection layers display
 */
function updateDetectionLayers(result) {
  const details = result.details || {};
  
  // Heuristic Analysis
  if (details.heuristic) {
    const h = details.heuristic;
    const suspicious = h.suspicious;
    const score = h.score || 0;
    
    elements.heuristicItem.className = 'detection-item ' + (suspicious ? 'fail' : 'pass');
    elements.heuristicDot.className = 'status-dot ' + (suspicious ? 'fail' : 'pass');
    elements.heuristicValue.textContent = suspicious ? 'Suspicious' : 'Clean';
  }
  
  // Threat Intelligence
  if (details.threat_intelligence) {
    const ti = details.threat_intelligence;
    const hit = ti.hit;
    
    elements.threatItem.className = 'detection-item ' + (hit ? 'fail' : 'pass');
    elements.threatDot.className = 'status-dot ' + (hit ? 'fail' : 'pass');
    elements.threatValue.textContent = hit ? 'Flagged' : 'Clean';
  }
  
  // Machine Learning
  if (details.machine_learning) {
    const ml = details.machine_learning;
    
    if (ml.error) {
      elements.mlItem.className = 'detection-item warning';
      elements.mlDot.className = 'status-dot warning';
      elements.mlValue.textContent = 'Unavailable';
    } else if (ml.status) {
      elements.mlItem.className = 'detection-item warning';
      elements.mlDot.className = 'status-dot warning';
      elements.mlValue.textContent = 'Disabled';
    } else {
      const prediction = ml.prediction;
      const probability = ml.probability || 0;
      
      elements.mlItem.className = 'detection-item ' + (prediction === 1 ? 'fail' : 'pass');
      elements.mlDot.className = 'status-dot ' + (prediction === 1 ? 'fail' : 'pass');
      elements.mlValue.textContent = prediction === 1 ? 
        `${(probability * 100).toFixed(0)}% Phishing` : 
        `${((1 - probability) * 100).toFixed(0)}% Safe`;
    }
  }
  
  // Primary detection method
  elements.detectionMethod.textContent = result.detection_method || 'Combined Analysis';
}

/**
 * Update technical details section
 */
function updateTechnicalDetails(details) {
  // Heuristic details
  if (details.heuristic) {
    const h = details.heuristic;
    elements.heuristicDetails.innerHTML = `
      <div class="detail-item">
        <span class="detail-label">Status:</span>
        <span class="detail-value">${h.suspicious ? 'Suspicious' : 'Clean'}</span>
      </div>
      <div class="detail-item">
        <span class="detail-label">Confidence:</span>
        <span class="detail-value">${h.score}/100</span>
      </div>
      <div class="detail-item">
        <span class="detail-label">Findings:</span>
        <span class="detail-value">${h.reason || 'None'}</span>
      </div>
    `;
  }
  
  // Threat intelligence details
  if (details.threat_intelligence) {
    const ti = details.threat_intelligence;
    elements.threatIntelDetails.innerHTML = `
      <div class="detail-item">
        <span class="detail-label">Database Check:</span>
        <span class="detail-value">${ti.hit ? 'Match Found' : 'No Match'}</span>
      </div>
      <div class="detail-item">
        <span class="detail-label">Status:</span>
        <span class="detail-value">${ti.reason || 'Unknown'}</span>
      </div>
    `;
  }
  
  // ML details
  if (details.machine_learning) {
    const ml = details.machine_learning;
    
    if (ml.error) {
      elements.mlDetails.innerHTML = `
        <div class="detail-item">
          <span class="detail-label">Status:</span>
          <span class="detail-value" style="color: #DC2626;">Error: ${ml.error}</span>
        </div>
      `;
    } else if (ml.status) {
      elements.mlDetails.innerHTML = `
        <div class="detail-item">
          <span class="detail-label">Status:</span>
          <span class="detail-value">${ml.status}</span>
        </div>
      `;
    } else {
      elements.mlDetails.innerHTML = `
        <div class="detail-item">
          <span class="detail-label">Classification:</span>
          <span class="detail-value">${ml.prediction === 1 ? 'Phishing' : 'Legitimate'}</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">Confidence:</span>
          <span class="detail-value">${(ml.confidence * 100).toFixed(1)}%</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">Phishing Probability:</span>
          <span class="detail-value">${(ml.probability * 100).toFixed(1)}%</span>
        </div>
      `;
    }
  }
}

/**
 * Animate number counting
 */
function animateNumber(element, start, end, duration) {
  const range = end - start;
  const increment = range / (duration / 16);
  let current = start;
  
  const timer = setInterval(() => {
    current += increment;
    if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
      current = end;
      clearInterval(timer);
    }
    element.textContent = Math.round(current);
  }, 16);
}

/**
 * Show error state
 */
function showError(message) {
  elements.loading.style.display = 'none';
  elements.content.style.display = 'none';
  elements.error.style.display = 'block';
  elements.errorMessage.textContent = message;
}

/**
 * Copy URL to clipboard
 */
elements.copyUrlBtn.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(currentUrl);
    
    // Show feedback
    const originalHTML = elements.copyUrlBtn.innerHTML;
    elements.copyUrlBtn.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
        <path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z"/>
      </svg>
    `;
    elements.copyUrlBtn.style.color = '#10B981';
    
    setTimeout(() => {
      elements.copyUrlBtn.innerHTML = originalHTML;
      elements.copyUrlBtn.style.color = '';
    }, 2000);
  } catch (error) {
    console.error('Failed to copy:', error);
  }
});

/**
 * Handle rescan button
 */
elements.rescanBtn.addEventListener('click', async () => {
  // Show loading
  elements.loading.style.display = 'block';
  elements.content.style.display = 'none';
  
  // Request rescan
  chrome.runtime.sendMessage(
    { action: 'rescanURL', url: currentUrl, tabId: currentTabId },
    (result) => {
      if (result) {
        displayResult(result);
      } else {
        showError('Rescan failed. Please try again.');
      }
    }
  );
});

/**
 * Handle retry button
 */
elements.retryBtn.addEventListener('click', () => {
  elements.error.style.display = 'none';
  elements.loading.style.display = 'block';
  init();
});

/**
 * Handle toggle details button
 */
elements.toggleDetailsBtn.addEventListener('click', () => {
  const isExpanded = elements.technicalDetails.style.display !== 'none';
  
  if (isExpanded) {
    elements.technicalDetails.style.display = 'none';
    elements.expandIcon.classList.remove('rotated');
    elements.toggleDetailsBtn.querySelector('span').textContent = 'Technical Details';
  } else {
    elements.technicalDetails.style.display = 'block';
    elements.expandIcon.classList.add('rotated');
    elements.toggleDetailsBtn.querySelector('span').textContent = 'Hide Details';
  }
});

// Initialize on load
document.addEventListener('DOMContentLoaded', init);