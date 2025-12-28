// Content script for detecting client-side threats
// Rules are loaded from rules.js

// Helper function to safely send messages to background script
function safeSendMessage(messageData) {
  try {
    if (!chrome.runtime || !chrome.runtime.id) {
      // Extension context invalidated - silently ignore
      return;
    }

    chrome.runtime.sendMessage(messageData, (response) => {
      if (chrome.runtime.lastError) {
        // Silently ignore connection errors
      }
    });
  } catch (e) {
    // Silently ignore all errors - extension may have been reloaded
  }
}

// Track basic user gestures to help detect background downloads
document.addEventListener(
  "click",
  () => {
    safeSendMessage({ type: "USER_GESTURE" });
  },
  true
);

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("[CONTENT] Received message:", message.type);

  if (message.type === "SHOW_ALERT") {
    // Show styled in-page notification
    showInPageAlert(message.title, message.message, message.severity);

    // Send response to acknowledge
    sendResponse({ received: true });
  }
  return true; // Keep channel open for async response
});

// Function to show styled in-page alert
function showInPageAlert(title, message, severity = "warning") {
  console.log(`[ALERT] Showing: "${title}"`);

  // Create alert container
  const alertDiv = document.createElement("div");
  alertDiv.style.cssText = `
    position: fixed !important;
    top: 20px !important;
    right: 20px !important;
    background: ${severity === "critical" ? "#dc3545" : "#ff6b35"} !important;
    color: white !important;
    padding: 15px 20px !important;
    border-radius: 8px !important;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3) !important;
    z-index: 2147483647 !important;
    font-family: Arial, sans-serif !important;
    font-size: 14px !important;
    font-weight: bold !important;
    max-width: 400px !important;
    border-left: 5px solid #fff !important;
    animation: slideIn 0.3s ease-out !important;
    display: block !important;
    visibility: visible !important;
    opacity: 1 !important;
  `;

  alertDiv.innerHTML = `
    <div style="font-size: 16px; margin-bottom: 8px;">${title}</div>
    <div style="font-weight: normal; font-size: 12px; opacity: 0.9;">${message.replace(
      /\n/g,
      "<br>"
    )}</div>
    <button onclick="this.parentElement.remove()" style="
      position: absolute;
      top: 5px;
      right: 8px;
      background: none;
      border: none;
      color: white;
      font-size: 18px;
      cursor: pointer;
      padding: 0;
      width: 20px;
      height: 20px;
    ">×</button>
  `;

  // Add CSS animation
  if (!document.getElementById("alertStyles")) {
    const style = document.createElement("style");
    style.id = "alertStyles";
    style.textContent = `
      @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
    `;
    if (document.head) {
      document.head.appendChild(style);
    }
  }

  // Ensure body exists before appending
  if (document.body) {
    document.body.appendChild(alertDiv);
    console.log("[ALERT] Alert div appended to body");

    // Auto-remove after 1 second
    setTimeout(() => {
      if (alertDiv.parentElement) {
        alertDiv.remove();
        console.log("[ALERT] Alert removed");
      }
    }, 1000);
  } else {
    console.error("[ALERT] document.body not available, cannot show alert");
    // Wait for body to be available
    document.addEventListener("DOMContentLoaded", () => {
      if (document.body) {
        document.body.appendChild(alertDiv);
        console.log(
          "[ALERT] Alert div appended to body (after DOMContentLoaded)"
        );

        setTimeout(() => {
          if (alertDiv.parentElement) {
            alertDiv.remove();
          }
        }, 1000);
      }
    });
  }
}

// Wait for rules to be available
function waitForRules() {
  return new Promise((resolve) => {
    if (window.rules) {
      resolve();
    } else {
      setTimeout(() => waitForRules().then(resolve), 10);
    }
  });
}

// --- Inline Script Detection ---
function detectInlineScripts() {
  if (!window.rules) {
    console.warn("Rules not loaded yet, skipping detection");
    return;
  }

  const scripts = document.querySelectorAll("script");

  for (const s of scripts) {
    if (s.innerHTML && window.rules.inlineJS.test(s.innerHTML)) {
      console.warn("[DETECTED] Inline script injection:", s.innerHTML);
      // Send alert to background script
      safeSendMessage({
        type: "THREAT_DETECTED",
        threatType: "INLINE_SCRIPT",
        details: s.innerHTML.substring(0, 100),
      });
    }
  }
}

// --- Suspicious Inline Event Attributes (like onclick=eval()) ---
function detectSuspiciousAttributes() {
  if (!window.rules) {
    console.warn("Rules not loaded yet, skipping attribute detection");
    return;
  }

  const elements = document.querySelectorAll("*");

  const badAttrs = [
    "onload",
    "onerror",
    "onclick",
    "onmouseover",
    "onfocus",
    "onblur",
  ];

  elements.forEach((el) => {
    for (const attr of badAttrs) {
      if (el.hasAttribute(attr)) {
        const val = el.getAttribute(attr);
        if (/javascript:|eval|new Function/i.test(val)) {
          console.warn("[DETECTED] Suspicious inline event handler:", val);
          safeSendMessage({
            type: "THREAT_DETECTED",
            threatType: "SUSPICIOUS_ATTRIBUTE",
            details: `${attr}="${val}"`,
          });
        }
      }
    }
  });
}

// --- Clipboard Stealing Detection ---
function detectClipboardStealing() {
  console.log("[CLIPBOARD] Installing clipboard interceptors...");

  // Intercept clipboard read attempts
  if (navigator.clipboard && navigator.clipboard.readText) {
    const originalReadText = navigator.clipboard.readText;
    navigator.clipboard.readText = function () {
      console.warn("[DETECTED] Clipboard read attempt detected!");
      alert(
        "🚨 CLIPBOARD THEFT DETECTED!\n\nThis page is trying to read your clipboard data!"
      );

      safeSendMessage({
        type: "THREAT_DETECTED",
        threatType: "CLIPBOARD_THEFT",
        details: "Page attempted to read clipboard data",
      });

      return originalReadText.apply(this, arguments);
    };
    console.log("[CLIPBOARD] readText interceptor installed");
  } else {
    console.warn("[CLIPBOARD] navigator.clipboard.readText not available");
  }

  // Intercept clipboard write attempts (data replacement)
  if (navigator.clipboard && navigator.clipboard.writeText) {
    const originalWriteText = navigator.clipboard.writeText;
    navigator.clipboard.writeText = function (text) {
      console.warn("[DETECTED] Clipboard write attempt detected!");
      alert(
        "🚨 CLIPBOARD MANIPULATION DETECTED!\n\nThis page is trying to modify your clipboard data!"
      );

      safeSendMessage({
        type: "THREAT_DETECTED",
        threatType: "CLIPBOARD_MANIPULATION",
        details: `Page attempted to modify clipboard: ${text.substring(
          0,
          50
        )}...`,
      });

      return originalWriteText.apply(this, arguments);
    };
    console.log("[CLIPBOARD] writeText interceptor installed");
  } else {
    console.warn("[CLIPBOARD] navigator.clipboard.writeText not available");
  }
}

// --- Keylogger Detection ---
function detectKeylogger() {
  let keyListenerCount = 0;

  // Intercept addEventListener for keyboard events
  const originalAddEventListener = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, listener, options) {
    if (type === "keydown" || type === "keypress" || type === "keyup") {
      keyListenerCount++;
      console.warn(
        `[DETECTED] Keylogger listener added: ${type} (Total: ${keyListenerCount})`
      );

      // Alert if multiple keyboard listeners detected
      if (keyListenerCount >= 2) {
        safeSendMessage({
          type: "THREAT_DETECTED",
          threatType: "KEYLOGGER",
          details: `Multiple keyboard event listeners detected (${keyListenerCount} total)`,
        });
      }
    }

    return originalAddEventListener.call(this, type, listener, options);
  };
}

// --- Camera Access Detection ---
function detectCameraAccess() {
  console.log("[EXTENSION CAMERA] Installing camera/microphone interceptor...");

  // Use Object.defineProperty to create a more robust intercept
  if (navigator.mediaDevices) {
    const originalGetUserMedia = navigator.mediaDevices.getUserMedia;

    if (originalGetUserMedia) {
      Object.defineProperty(navigator.mediaDevices, "getUserMedia", {
        value: function (constraints) {
          console.warn(
            "[EXTENSION DETECTED] Camera/microphone access requested!",
            constraints
          );

          // Check if video (camera) is requested
          if (constraints && constraints.video) {
            alert(
              "🚨 CAMERA ACCESS DETECTED!\n\nThis page is trying to access your camera!"
            );

            safeSendMessage({
              type: "THREAT_DETECTED",
              threatType: "CAMERA_ACCESS",
              details: "Page is requesting camera access",
            });
          }

          // Check if audio (microphone) is requested
          if (constraints && constraints.audio) {
            alert(
              "🚨 MICROPHONE ACCESS DETECTED!\n\nThis page is trying to access your microphone!"
            );

            safeSendMessage({
              type: "THREAT_DETECTED",
              threatType: "MICROPHONE_ACCESS",
              details: "Page is requesting microphone access",
            });
          }

          return originalGetUserMedia.call(navigator.mediaDevices, constraints);
        },
        configurable: true,
        writable: true,
      });
      console.log(
        "[EXTENSION CAMERA] getUserMedia interceptor installed successfully"
      );
    }
  } else {
    console.warn("[EXTENSION CAMERA] navigator.mediaDevices not available");
  }
}

// --- Auto Redirect Detection ---
function detectAndBlockAutoRedirect() {
  console.log("[REDIRECT MONITOR] Auto-redirect detection initialized");

  // Track if user clicked recently
  let lastUserClick = 0;
  document.addEventListener(
    "click",
    () => {
      lastUserClick = Date.now();
    },
    true
  );

  // Detect location changes that happen without user interaction
  let currentUrl = window.location.href;

  setInterval(() => {
    if (window.location.href !== currentUrl) {
      const timeSinceClick = Date.now() - lastUserClick;

      // If redirect happened more than 500ms after last click, it's likely automatic
      if (timeSinceClick > 500) {
        console.warn("[DETECTED] Automatic redirect detected!");

        safeSendMessage({
          type: "THREAT_DETECTED",
          threatType: "AUTO_REDIRECT_BLOCKED",
          details: `Automatic redirect detected: ${window.location.href}`,
        });
      }

      currentUrl = window.location.href;
    }
  }, 100);
}

// --- Credential Hijacking Detection ---
function detectCredentialHijacking() {
  // Monitor all form submissions
  document.addEventListener(
    "submit",
    (e) => {
      const form = e.target;

      // Check if form has password fields
      const passwordFields = form.querySelectorAll('input[type="password"]');
      if (passwordFields.length === 0) return;

      // Get form action URL
      const formAction = form.action || form.getAttribute("action");
      if (!formAction) return;

      try {
        const formURL = new URL(formAction, window.location.href);
        const currentDomain = window.location.hostname;
        const targetDomain = formURL.hostname;

        // Check if submitting to a different domain
        if (
          targetDomain &&
          targetDomain !== currentDomain &&
          targetDomain !== "localhost"
        ) {
          console.error(
            "[DETECTED] Credential hijacking - form submits to third-party domain!"
          );
          console.error(`Current domain: ${currentDomain}`);
          console.error(`Target domain: ${targetDomain}`);

          // BLOCK the form submission
          e.preventDefault();
          e.stopPropagation();

          safeSendMessage({
            type: "THREAT_DETECTED",
            threatType: "CREDENTIAL_HIJACKING_BLOCKED",
            details: `Login form attempted to send credentials to ${targetDomain}`,
          });

          return false;
        }
      } catch (error) {
        console.warn("[CREDENTIAL CHECK] Error parsing form action:", error);
      }
    },
    true
  );
}

// Install clipboard and API interceptors IMMEDIATELY (before page scripts run)
detectClipboardStealing();
detectKeylogger();
detectCameraAccess();
detectCredentialHijacking();

// Run immediately and on dynamic changes
function runAllDetections() {
  detectInlineScripts();
  detectSuspiciousAttributes();
  detectAndBlockAutoRedirect();
}

// Initialize after DOM content is loaded
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    waitForRules().then(() => {
      runAllDetections();

      // Mutation observer to detect added scripts dynamically
      const observer = new MutationObserver(runAllDetections);
      observer.observe(document, { childList: true, subtree: true });
    });
  });
} else {
  waitForRules().then(() => {
    runAllDetections();

    // Mutation observer to detect added scripts dynamically
    const observer = new MutationObserver(runAllDetections);
    observer.observe(document, { childList: true, subtree: true });
  });
}
