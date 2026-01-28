/**
 * Content Script for Phish-Shield
 * Injects warning banners on phishing websites
 */

let warningBanner = null;

/**
 * Create and inject warning banner
 */
function createWarningBanner(result) {
  // Remove existing banner if present
  removeWarningBanner();
  
  // Create banner container
  const banner = document.createElement('div');
  banner.id = 'phish-shield-warning';
  banner.className = 'phish-shield-banner';
  
  // Determine severity class based on risk score
  let severityClass = 'warning-high';
  if (result.risk_score >= 75) {
    severityClass = 'warning-critical';
  } else if (result.risk_score >= 50) {
    severityClass = 'warning-high';
  } else if (result.risk_score >= 25) {
    severityClass = 'warning-medium';
  }
  
  banner.classList.add(severityClass);
  
  // Build banner content
  banner.innerHTML = `
    <div class="phish-shield-content">
      <div class="phish-shield-icon">⚠️</div>
      <div class="phish-shield-message">
        <div class="phish-shield-title">
          <strong>⚠️ Phishing Warning - This site may be dangerous!</strong>
        </div>
        <div class="phish-shield-details">
          <p><strong>Risk Score:</strong> ${result.risk_score}/100</p>
          <p><strong>Reason:</strong> ${result.reason}</p>
          <p><strong>Detection Method:</strong> ${result.detection_method}</p>
          <p class="phish-shield-advice">
            <strong>⚠️ Do not enter passwords, credit card information, or personal data on this site.</strong>
          </p>
        </div>
        <div class="phish-shield-actions">
          <button id="phish-shield-details-btn" class="phish-shield-btn phish-shield-btn-secondary">
            Show Details
          </button>
          <button id="phish-shield-close-btn" class="phish-shield-btn phish-shield-btn-primary">
            I Understand
          </button>
        </div>
      </div>
    </div>
    <div id="phish-shield-details" class="phish-shield-details-panel" style="display: none;">
      <h3>Technical Details</h3>
      <pre>${JSON.stringify(result.details || {}, null, 2)}</pre>
    </div>
  `;
  
  // Insert banner at the top of the page
  if (document.body) {
    document.body.insertBefore(banner, document.body.firstChild);
  } else {
    // If body doesn't exist yet, wait for DOM to load
    document.addEventListener('DOMContentLoaded', () => {
      document.body.insertBefore(banner, document.body.firstChild);
    });
  }
  
  // Add event listeners
  setTimeout(() => {
    const closeBtn = document.getElementById('phish-shield-close-btn');
    const detailsBtn = document.getElementById('phish-shield-details-btn');
    const detailsPanel = document.getElementById('phish-shield-details');
    
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        banner.style.display = 'none';
      });
    }
    
    if (detailsBtn && detailsPanel) {
      detailsBtn.addEventListener('click', () => {
        if (detailsPanel.style.display === 'none') {
          detailsPanel.style.display = 'block';
          detailsBtn.textContent = 'Hide Details';
        } else {
          detailsPanel.style.display = 'none';
          detailsBtn.textContent = 'Show Details';
        }
      });
    }
  }, 100);
  
  warningBanner = banner;
  
  console.log('[Phish-Shield] Warning banner injected');
}

/**
 * Remove warning banner
 */
function removeWarningBanner() {
  if (warningBanner) {
    warningBanner.remove();
    warningBanner = null;
  }
  
  // Also remove by ID in case reference is lost
  const existingBanner = document.getElementById('phish-shield-warning');
  if (existingBanner) {
    existingBanner.remove();
  }
}

/**
 * Listen for messages from background script
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'showWarning') {
    console.log('[Phish-Shield] Received warning request:', request.result);
    createWarningBanner(request.result);
    sendResponse({ success: true });
  } else if (request.action === 'removeWarning') {
    removeWarningBanner();
    sendResponse({ success: true });
  }
  
  return true;
});

console.log('[Phish-Shield] Content script initialized');