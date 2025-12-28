// Background service worker for network monitoring

// Import rules using importScripts for service workers
importScripts("rules.js");

let requestTimestamps = [];
let detectionCounts = {
  sqli: 0,
  redirect: 0,
  malware: 0,
  spam: 0,
};

// Track last user gesture per tab to spot background downloads
const lastUserGesturePerTab = {};

// Listen for ALL outgoing requests
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const url = details.url;
    console.log("[MONITORING] Request to:", url);
    console.log("[RULES LOADED]", typeof rules, rules ? "YES" : "NO");

    const now1 = Date.now();
    const lastGesture = lastUserGesturePerTab[details.tabId] || 0;
    const noRecentGesture = now1 - lastGesture > 2000; // 2s window

    const isExecLike = rules.malwareDownload.test(url);
    const isDoubleExt = rules.doubleExtension.test(url);

    // --- SQL Injection detection ---
    if (rules.sqli.test(url)) {
      console.warn("[DETECTED] SQLi-like pattern:", url);
      detectionCounts.sqli++;

      const alertMessage = `🚨 CRITICAL SECURITY ALERT!\n\nSQL Injection attack detected!\nSuspicious URL: ${url}\n\nThis request has been logged and monitored.`;

      // Send message to content script for in-page alert (use the tab that made the request)
      if (details.tabId && details.tabId > 0) {
        console.log("[BACKGROUND] Sending alert to tab:", details.tabId);
        chrome.tabs.sendMessage(
          details.tabId,
          {
            type: "SHOW_ALERT",
            title: "🛡️ SQL Injection Detected",
            message: alertMessage,
            severity: "critical",
          },
          (response) => {
            if (chrome.runtime.lastError) {
              console.warn(
                "[BACKGROUND] Content script not ready:",
                chrome.runtime.lastError.message
              );
            } else {
              console.log("[BACKGROUND] Alert delivered:", response);
            }
          }
        );
      }
    }

    // --- Weird redirect detection ---
    if (rules.redirect.test(url)) {
      console.warn("[DETECTED] Suspicious redirect:", url);
      detectionCounts.redirect++;
      showNotification(
        "Suspicious Redirect",
        `Redirect detected: ${url.substring(0, 50)}...`,
        "warning",
        details.tabId
      );
    }

    // --- Fake malware downloads / double extensions / no-gesture downloads ---
    if (isExecLike || isDoubleExt) {
      detectionCounts.malware++;

      if (isDoubleExt) {
        showNotification(
          "Double Extension Detected",
          `Suspicious filename pattern: ${url.substring(0, 90)}...`,
          "warning",
          details.tabId
        );
      }

      if (noRecentGesture) {
        showNotification(
          "Download Without User Gesture",
          `File requested without a recent click: ${url.substring(0, 90)}...`,
          "warning",
          details.tabId
        );
      }

      if (url.startsWith("http://")) {
        showNotification(
          "Insecure Download",
          `HTTP download detected: ${url.substring(0, 90)}...`,
          "warning",
          details.tabId
        );
      }

      // Always alert for exec-like download
      showNotification(
        "Suspicious Download",
        `Potential malware file: ${url.substring(0, 90)}...`,
        "warning",
        details.tabId
      );
    }

    // --- Spam request detection ---
    const now = Date.now();
    requestTimestamps.push(now);

    requestTimestamps = requestTimestamps.filter(
      (t) => now - t < rules.spam.timeframe
    );

    if (requestTimestamps.length >= rules.spam.threshold) {
      console.warn("[DETECTED] High-frequency spam requests");
      detectionCounts.spam++;
      showNotification(
        "Spam Requests Detected",
        `${requestTimestamps.length} requests in ${rules.spam.timeframe}ms`,
        "warning",
        details.tabId
      );
    }

    return {};
  },
  { urls: ["<all_urls>"] }
);

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "THREAT_DETECTED") {
    console.warn(
      `[CONTENT SCRIPT] ${message.threatType} detected:`,
      message.details
    );

    const tabId = sender.tab ? sender.tab.id : null;

    // Special handling for clipboard theft
    if (message.threatType === "CLIPBOARD_THEFT") {
      showNotification(
        "🚨 Clipboard Stealing Detected",
        "This page is attempting to read your clipboard data!",
        "critical",
        tabId
      );
    } else if (message.threatType === "CLIPBOARD_MANIPULATION") {
      showNotification(
        "🚨 Clipboard Data Manipulation",
        "This page is attempting to modify your clipboard!",
        "critical",
        tabId
      );
    } else if (message.threatType === "KEYLOGGER") {
      showNotification(
        "🚨 Keylogger Alert",
        "This page has installed multiple keyboard listeners - possible keylogger!",
        "critical",
        tabId
      );
    } else if (message.threatType === "CAMERA_ACCESS") {
      showNotification(
        "🚨 Camera Access Request",
        "This page is requesting access to your camera!",
        "warning",
        tabId
      );
    } else if (message.threatType === "MICROPHONE_ACCESS") {
      showNotification(
        "🚨 Microphone Access Request",
        "This page is requesting access to your microphone!",
        "warning",
        tabId
      );
    } else if (message.threatType === "AUTO_REDIRECT_BLOCKED") {
      showNotification(
        "🚨 Auto-Redirect Blocked",
        "Redirect was attempted but the extension blocked it!\n" +
          message.details,
        "warning",
        tabId
      );
    } else if (message.threatType === "CREDENTIAL_HIJACKING_BLOCKED") {
      showNotification(
        "🚨 Credential Hijacking Blocked",
        "Login form tried to send credentials to third-party domain!\n" +
          message.details +
          "\n\nForm submission was blocked!",
        "critical",
        tabId
      );
    } else {
      showNotification(
        `${message.threatType} Detected`,
        message.details,
        "warning",
        tabId
      );
    }
  }

  if (message.type === "USER_GESTURE" && sender.tab) {
    lastUserGesturePerTab[sender.tab.id] = Date.now();
  }
  return true; // Required for async response
});

// Function to show notifications
function showNotification(title, message, severity = "warning", tabId = null) {
  // Log to console
  console.log(`🚨 [ALERT] ${title}: ${message}`);

  // Send in-page alert to specified tab or active tab
  if (tabId && tabId > 0) {
    console.log("[BACKGROUND] Sending alert to tab:", tabId);
    chrome.tabs.sendMessage(
      tabId,
      {
        type: "SHOW_ALERT",
        title: title,
        message: message,
        severity: severity,
      },
      (response) => {
        if (chrome.runtime.lastError) {
          console.warn(
            "[BACKGROUND] Content script not ready:",
            chrome.runtime.lastError.message
          );
        } else {
          console.log("[BACKGROUND] Alert delivered:", response);
        }
      }
    );
  } else {
    // Fallback to active tab if no tabId specified
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      if (tabs[0]) {
        console.log("[BACKGROUND] Sending alert to active tab:", tabs[0].id);
        chrome.tabs.sendMessage(
          tabs[0].id,
          {
            type: "SHOW_ALERT",
            title: title,
            message: message,
            severity: severity,
          },
          (response) => {
            if (chrome.runtime.lastError) {
              console.warn(
                "[BACKGROUND] Content script not ready:",
                chrome.runtime.lastError.message
              );
            } else {
              console.log("[BACKGROUND] Alert delivered:", response);
            }
          }
        );
      }
    });
  }
}

// MIME vs extension mismatch detection
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    try {
      const url = details.url;
      const headers = details.responseHeaders || [];
      const ctHeader = headers.find(
        (h) => h.name.toLowerCase() === "content-type"
      );

      if (!ctHeader || !ctHeader.value) return;

      const contentType = ctHeader.value.toLowerCase().split(";")[0].trim();
      const pathname = new URL(url).pathname;
      const ext = pathname.split(".").pop().toLowerCase();
      if (!ext) return;

      // Define expected MIME types for common extensions
      const mimeTypeMap = {
        pdf: "application/pdf",
        doc: "application/msword",
        docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        xls: "application/vnd.ms-excel",
        xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        txt: "text/plain",
        jpg: "image/jpeg",
        jpeg: "image/jpeg",
        png: "image/png",
        gif: "image/gif",
        exe: "application/x-msdownload",
        zip: "application/zip",
        js: "application/javascript",
        html: "text/html",
        css: "text/css",
      };

      const execExts = ["exe", "scr", "pif", "bat", "cmd", "vbs", "jar", "iso"];
      const docLike = [
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "txt",
        "rtf",
      ];

      // Check 1: Document MIME type with executable extension
      const isExecExt = execExts.includes(ext);
      const isDocContent = docLike.some((t) => contentType.includes(t));

      if (isDocContent && isExecExt) {
        showNotification(
          "🚨 MIME Type Mismatch Alert",
          `Suspicious file detected!\nContent-Type: ${contentType}\nFile Extension: .${ext}\n\nThis could be a malware attempt!`,
          "critical",
          details.tabId
        );
        console.error(
          "[MIME MISMATCH] Document MIME with executable extension:",
          url
        );
      }

      // Check 2: General MIME type vs extension mismatch
      else if (mimeTypeMap[ext] && !contentType.includes(mimeTypeMap[ext])) {
        showNotification(
          "🚨 MIME Type Mismatch Alert",
          `File extension doesn't match content type!\nExpected: ${mimeTypeMap[ext]}\nActual: ${contentType}\nFile: .${ext}`,
          "warning",
          details.tabId
        );
        console.warn("[MIME MISMATCH] Extension/MIME mismatch:", url);
      }
    } catch (e) {
      console.warn("[MIME CHECK] Failed:", e);
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// Log extension startup
console.log("🛡️ Web Intrusion Detector - Background script loaded");
console.log("📊 Detection rules loaded:", Object.keys(rules));

// Periodic cleanup of old timestamps
setInterval(() => {
  const now = Date.now();
  requestTimestamps = requestTimestamps.filter(
    (t) => now - t < rules.spam.timeframe
  );
}, 5000);
