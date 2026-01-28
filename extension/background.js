/**
 * Background Service Worker for Phish-Shield
 * Monitors tab updates and scans URLs for phishing
 */

const API_URL = 'http://localhost:8000';
const SCAN_CACHE = new Map(); // Cache scan results to avoid redundant API calls
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// Store scan results for each tab
const tabResults = new Map();

/**
 * Scan a URL for phishing using the backend API
 */
async function scanURL(url) {
  console.log('[Phish-Shield] Scanning URL:', url);
  
  // Check cache first
  const cached = SCAN_CACHE.get(url);
  if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
    console.log('[Phish-Shield] Using cached result');
    return cached.result;
  }
  
  try {
    const response = await fetch(`${API_URL}/scan-url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: url })
    });
    
    if (!response.ok) {
      throw new Error(`API returned status ${response.status}`);
    }
    
    const result = await response.json();
    
    // Cache the result
    SCAN_CACHE.set(url, {
      result: result,
      timestamp: Date.now()
    });
    
    console.log('[Phish-Shield] Scan result:', result);
    return result;
    
  } catch (error) {
    console.error('[Phish-Shield] Error scanning URL:', error);
    
    // Return a safe default if API is unavailable
    return {
      url: url,
      status: 'error',
      risk_score: 0,
      reason: `Unable to connect to Phish-Shield API: ${error.message}`,
      detection_method: 'Error',
      timestamp: new Date().toISOString()
    };
  }
}

/**
 * Handle tab updates and scan new URLs
 */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Only scan when the page has finished loading
  if (changeInfo.status === 'complete' && tab.url) {
    // Skip internal Chrome pages
    if (tab.url.startsWith('chrome://') || 
        tab.url.startsWith('chrome-extension://') ||
        tab.url.startsWith('about:')) {
      return;
    }
    
    console.log('[Phish-Shield] Tab updated:', tabId, tab.url);
    
    // Scan the URL
    const result = await scanURL(tab.url);
    
    // Store result for this tab
    tabResults.set(tabId, result);
    
    // Update badge to show risk level
    updateBadge(tabId, result);
    
    // If unsafe, inject warning
    if (result.status === 'unsafe') {
      console.log('[Phish-Shield] Unsafe site detected! Injecting warning...');
      
      // Send message to content script to show warning
      try {
        await chrome.tabs.sendMessage(tabId, {
          action: 'showWarning',
          result: result
        });
      } catch (error) {
        console.error('[Phish-Shield] Error sending message to content script:', error);
      }
    }
  }
});

/**
 * Update extension badge based on risk score
 */
function updateBadge(tabId, result) {
  const riskScore = result.risk_score || 0;
  
  let color, text;
  
  if (result.status === 'error') {
    color = '#808080'; // Gray
    text = '?';
  } else if (riskScore >= 75) {
    color = '#DC2626'; // Red
    text = '!!!';
  } else if (riskScore >= 50) {
    color = '#F59E0B'; // Orange
    text = '!!';
  } else if (riskScore >= 25) {
    color = '#FCD34D'; // Yellow
    text = '!';
  } else {
    color = '#10B981'; // Green
    text = '✓';
  }
  
  chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
  chrome.action.setBadgeText({ text: text, tabId: tabId });
}

/**
 * Handle messages from popup or content script
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getScanResult') {
    // Return cached scan result for current tab
    const result = tabResults.get(request.tabId);
    sendResponse(result || null);
  } else if (request.action === 'rescanURL') {
    // Force rescan of URL
    SCAN_CACHE.delete(request.url);
    scanURL(request.url).then(result => {
      if (request.tabId) {
        tabResults.set(request.tabId, result);
        updateBadge(request.tabId, result);
      }
      sendResponse(result);
    });
    return true; // Indicates async response
  }
});

/**
 * Clean up cache periodically
 */
setInterval(() => {
  const now = Date.now();
  for (const [url, data] of SCAN_CACHE.entries()) {
    if (now - data.timestamp > CACHE_DURATION) {
      SCAN_CACHE.delete(url);
    }
  }
}, 60000); // Clean every minute

/**
 * Clean up tab results when tab is closed
 */
chrome.tabs.onRemoved.addListener((tabId) => {
  tabResults.delete(tabId);
});

console.log('[Phish-Shield] Background service worker initialized');