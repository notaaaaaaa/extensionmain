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

// High-level OWASP-style category counters
let categoryCounts = {
  INJECTION: 0,
  XSS: 0,
  MISCONFIGURATION: 0,
  SENSITIVE_DATA_EXPOSURE: 0,
  CLIENT_SIDE_ATTACKS: 0,
};

// Basic notification rate limiting to avoid spamming per tab/title
const notificationLastShown = {};
const NOTIFICATION_WINDOW_MS = 3000; // 3 seconds per (tab,title)

function shouldShowNotification(title, tabId) {
  const key = `${tabId || "global"}|${title}`;
  const now = Date.now();
  const last = notificationLastShown[key] || 0;
  if (now - last < NOTIFICATION_WINDOW_MS) {
    console.log("[NOTIFY] Suppressing duplicate notification for key", key);
    return false;
  }
  notificationLastShown[key] = now;
  return true;
}

// Centralized detection log size limit
const MAX_DETECTIONS = 500;

// Central event logger for all findings
function logDetection({
  url = "",
  type = "UNKNOWN",
  category = null,
  severity = "warning",
  details = "",
  ruleId = null,
}) {
  try {
    let origin = "unknown";
    try {
      if (url) {
        origin = new URL(url).origin;
      }
    } catch (e) {
      // leave origin as 'unknown'
    }

    // If ruleId not provided, try to look it up from ruleMetadata (from rules.js)
    if (!ruleId && typeof ruleMetadata !== "undefined" && ruleMetadata[type]) {
      ruleId = ruleMetadata[type].id;
    }

    const event = {
      time: Date.now(),
      url,
      origin,
      type,
      category,
      severity,
      details,
      ruleId,
    };

    // Debug log so we can verify what gets stored
    console.log("[LOG DETECTION] Storing event", event);

    chrome.storage.local.get({ detections: [] }, (data) => {
      let detections = Array.isArray(data.detections)
        ? data.detections
        : [];
      detections.push(event);
      if (detections.length > MAX_DETECTIONS) {
        detections = detections.slice(detections.length - MAX_DETECTIONS);
      }
      chrome.storage.local.set({ detections });
    });
  } catch (e) {
    console.warn("[LOG DETECTION] Failed to record event:", e);
  }
}

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
      categoryCounts.INJECTION++;

      logDetection({
        url,
        type: "SQLI_URL_PATTERN",
        category: "INJECTION",
        severity: "critical",
        details: url,
      });

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
            category: "INJECTION",
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
      categoryCounts.CLIENT_SIDE_ATTACKS++;
      logDetection({
        url,
        type: "REDIRECT_SUSPICIOUS",
        category: "CLIENT_SIDE_ATTACKS",
        severity: "warning",
        details: url,
      });
      showNotification(
        "Suspicious Redirect",
        `Redirect detected: ${url.substring(0, 50)}...`,
        "warning",
        details.tabId,
        "CLIENT_SIDE_ATTACKS"
      );
    }

    // --- Fake malware downloads / double extensions / no-gesture downloads ---
    if (isExecLike || isDoubleExt) {
      detectionCounts.malware++;
      categoryCounts.CLIENT_SIDE_ATTACKS++;

      if (isDoubleExt) {
        logDetection({
          url,
          type: "MALWARE_DOUBLE_EXTENSION",
          category: "MISCONFIGURATION",
          severity: "warning",
          details: url,
        });
        showNotification(
          "Double Extension Detected",
          `Suspicious filename pattern: ${url.substring(0, 90)}...`,
          "warning",
          details.tabId,
          "MISCONFIGURATION"
        );
      }

      if (noRecentGesture) {
        logDetection({
          url,
          type: "DOWNLOAD_WITHOUT_USER_GESTURE",
          category: "CLIENT_SIDE_ATTACKS",
          severity: "warning",
          details: url,
        });
        showNotification(
          "Download Without User Gesture",
          `File requested without a recent click: ${url.substring(0, 90)}...`,
          "warning",
          details.tabId,
          "CLIENT_SIDE_ATTACKS"
        );
      }

      if (url.startsWith("http://")) {
        logDetection({
          url,
          type: "DOWNLOAD_INSECURE_HTTP",
          category: "MISCONFIGURATION",
          severity: "warning",
          details: url,
        });
        showNotification(
          "Insecure Download",
          `HTTP download detected: ${url.substring(0, 90)}...`,
          "warning",
          details.tabId,
          "MISCONFIGURATION"
        );
      }

      // Always alert for exec-like download
      if (isExecLike) {
        logDetection({
          url,
          type: "MALWARE_EXECUTABLE_DOWNLOAD",
          category: "CLIENT_SIDE_ATTACKS",
          severity: "warning",
          details: url,
        });
      }
      showNotification(
        "Suspicious Download",
        `Potential malware file: ${url.substring(0, 90)}...`,
        "warning",
        details.tabId,
        "CLIENT_SIDE_ATTACKS"
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
      categoryCounts.CLIENT_SIDE_ATTACKS++;
      logDetection({
        url,
        type: "SPAM_REQUEST_BURST",
        category: "CLIENT_SIDE_ATTACKS",
        severity: "warning",
        details: `${requestTimestamps.length} requests in ${rules.spam.timeframe}ms`,
      });
      showNotification(
        "Spam Requests Detected",
        `${requestTimestamps.length} requests in ${rules.spam.timeframe}ms`,
        "warning",
        details.tabId,
        "CLIENT_SIDE_ATTACKS"
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
    const pageUrl = sender.tab && sender.tab.url ? sender.tab.url : "";

    // Special handling for clipboard theft
    const defaultCategory =
      message.category ||
      (message.threatType === "INLINE_SCRIPT" ||
      message.threatType === "SUSPICIOUS_ATTRIBUTE"
        ? "INJECTION"
        : "CLIENT_SIDE_ATTACKS");

    if (categoryCounts[defaultCategory] !== undefined) {
      categoryCounts[defaultCategory]++;
    }

    // Log all content-script reported threats centrally
    let severity = "warning";
    if (
      message.threatType === "CLIPBOARD_THEFT" ||
      message.threatType === "CLIPBOARD_MANIPULATION" ||
      message.threatType === "KEYLOGGER" ||
      message.threatType === "CREDENTIAL_HIJACKING_BLOCKED"
    ) {
      severity = "critical";
    }

    logDetection({
      url: pageUrl,
      type: message.threatType,
      category: defaultCategory,
      severity,
      details: message.details || "",
    });

    if (message.threatType === "CLIPBOARD_THEFT") {
      showNotification(
        "🚨 Clipboard Stealing Detected",
        "This page is attempting to read your clipboard data!",
        "critical",
        tabId,
        "CLIENT_SIDE_ATTACKS"
      );
    } else if (message.threatType === "CLIPBOARD_MANIPULATION") {
      showNotification(
        "🚨 Clipboard Data Manipulation",
        "This page is attempting to modify your clipboard!",
        "critical",
        tabId,
        "CLIENT_SIDE_ATTACKS"
      );
    } else if (message.threatType === "KEYLOGGER") {
      showNotification(
        "🚨 Keylogger Alert",
        "This page has installed multiple keyboard listeners - possible keylogger!",
        "critical",
        tabId,
        "CLIENT_SIDE_ATTACKS"
      );
    } else if (message.threatType === "CAMERA_ACCESS") {
      showNotification(
        "🚨 Camera Access Request",
        "This page is requesting access to your camera!",
        "warning",
        tabId,
        "CLIENT_SIDE_ATTACKS"
      );
    } else if (message.threatType === "MICROPHONE_ACCESS") {
      showNotification(
        "🚨 Microphone Access Request",
        "This page is requesting access to your microphone!",
        "warning",
        tabId,
        "CLIENT_SIDE_ATTACKS"
      );
    } else if (message.threatType === "AUTO_REDIRECT_BLOCKED") {
      showNotification(
        "🚨 Auto-Redirect Blocked",
        "Redirect was attempted but the extension blocked it!\n" +
          message.details,
        "warning",
        tabId,
        "CLIENT_SIDE_ATTACKS"
      );
    } else if (message.threatType === "CREDENTIAL_HIJACKING_BLOCKED") {
      showNotification(
        "🚨 Credential Hijacking Blocked",
        "Login form tried to send credentials to third-party domain!\n" +
          message.details +
          "\n\nForm submission was blocked!",
        "critical",
        tabId,
        "SENSITIVE_DATA_EXPOSURE"
      );
    } else {
      showNotification(
        `${message.threatType} Detected`,
        message.details,
        "warning",
        tabId,
        defaultCategory
      );
    }
  }

  if (message.type === "USER_GESTURE" && sender.tab) {
    lastUserGesturePerTab[sender.tab.id] = Date.now();
  }
  return true; // Required for async response
});

// Function to show notifications
function showNotification(
  title,
  message,
  severity = "warning",
  tabId = null,
  category = null
) {
  if (!shouldShowNotification(title, tabId)) {
    return;
  }
  
  // Log to console
  console.log(
    `🚨 [ALERT] ${title}: ${message}` +
      (category ? ` [CATEGORY=${category}]` : "")
  );

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
        categoryCounts.MISCONFIGURATION++;
        logDetection({
          url,
          type: "MIME_MISMATCH_EXECUTABLE",
          category: "MISCONFIGURATION",
          severity: "critical",
          details: `Content-Type=${contentType}, ext=.${ext}`,
        });
        showNotification(
          "🚨 MIME Type Mismatch Alert",
          `Suspicious file detected!\nContent-Type: ${contentType}\nFile Extension: .${ext}\n\nThis could be a malware attempt!`,
          "critical",
          details.tabId,
          "MISCONFIGURATION"
        );
        console.error(
          "[MIME MISMATCH] Document MIME with executable extension:",
          url
        );
      }

      // Check 2: General MIME type vs extension mismatch
      else if (mimeTypeMap[ext] && !contentType.includes(mimeTypeMap[ext])) {
        categoryCounts.MISCONFIGURATION++;
        logDetection({
          url,
          type: "MIME_MISMATCH_GENERAL",
          category: "MISCONFIGURATION",
          severity: "warning",
          details: `Expected=${mimeTypeMap[ext]}, actual=${contentType}, ext=.${ext}`,
        });
        showNotification(
          "🚨 MIME Type Mismatch Alert",
          `File extension doesn't match content type!\nExpected: ${mimeTypeMap[ext]}\nActual: ${contentType}\nFile: .${ext}`,
          "warning",
          details.tabId,
          "MISCONFIGURATION"
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

// Inspect security-related response headers for misconfigurations and weak cookies
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    try {
      const url = details.url;
      const headers = details.responseHeaders || [];
      const isHttps = url.startsWith("https://");

      const getHeader = (name) =>
        headers.find((h) => h.name.toLowerCase() === name.toLowerCase());

      const csp = getHeader("content-security-policy");
      const hsts = getHeader("strict-transport-security");
      const referrer = getHeader("referrer-policy");
      const xfo = getHeader("x-frame-options");

      // 1) Missing CSP on HTTPS
      if (isHttps && !csp) {
        categoryCounts.MISCONFIGURATION++;
        logDetection({
          url,
          type: "HEADER_MISSING_CSP",
          category: "MISCONFIGURATION",
          severity: "warning",
          details: "HTTPS response without Content-Security-Policy header",
        });
        showNotification(
          "Missing Content-Security-Policy",
          "Response over HTTPS has no CSP header – XSS protection weakened.",
          "warning",
          details.tabId,
          "MISCONFIGURATION"
        );
      }

      // 2) Missing HSTS on HTTPS
      if (isHttps && !hsts) {
        categoryCounts.MISCONFIGURATION++;
        logDetection({
          url,
          type: "HEADER_MISSING_HSTS",
          category: "MISCONFIGURATION",
          severity: "warning",
          details: "HTTPS response without Strict-Transport-Security header",
        });
        showNotification(
          "Missing Strict-Transport-Security",
          "HTTPS response has no HSTS header – vulnerable to downgrade/MITM.",
          "warning",
          details.tabId,
          "MISCONFIGURATION"
        );
      }

      // 3) Weak or missing Referrer-Policy
      if (!referrer) {
        categoryCounts.MISCONFIGURATION++;
        logDetection({
          url,
          type: "HEADER_WEAK_REFERRER_POLICY",
          category: "MISCONFIGURATION",
          severity: "warning",
          details: "Missing Referrer-Policy header",
        });
        showNotification(
          "Missing Referrer-Policy",
          "No Referrer-Policy header – sensitive URLs may leak via Referer.",
          "warning",
          details.tabId,
          "MISCONFIGURATION"
        );
      } else {
        const value = (referrer.value || "").toLowerCase();
        const strongPolicies = [
          "no-referrer",
          "same-origin",
          "strict-origin",
          "strict-origin-when-cross-origin",
        ];
        const isStrong = strongPolicies.some((p) => value.includes(p));
        if (!isStrong) {
          categoryCounts.MISCONFIGURATION++;
          logDetection({
            url,
            type: "HEADER_WEAK_REFERRER_POLICY",
            category: "MISCONFIGURATION",
            severity: "warning",
            details: `Referrer-Policy='${value}' considered weak`,
          });
          showNotification(
            "Weak Referrer-Policy",
            `Referrer-Policy is '${value}' – may leak more data than necessary.`,
            "warning",
            details.tabId,
            "MISCONFIGURATION"
          );
        }
      }

      // 4) Missing X-Frame-Options on sensitive responses
      if (!xfo) {
        categoryCounts.MISCONFIGURATION++;
        logDetection({
          url,
          type: "HEADER_MISSING_XFO",
          category: "MISCONFIGURATION",
          severity: "warning",
          details: "Missing X-Frame-Options header",
        });
        showNotification(
          "Missing X-Frame-Options",
          "No X-Frame-Options header – page may be vulnerable to clickjacking.",
          "warning",
          details.tabId,
          "MISCONFIGURATION"
        );
      }

      // 5) Weak cookies (session/auth tokens without HttpOnly or Secure)
      const cookieHeaders = headers.filter(
        (h) => h.name.toLowerCase() === "set-cookie"
      );

      cookieHeaders.forEach((cookieHeader) => {
        const value = cookieHeader.value || "";
        const lower = value.toLowerCase();

        // Extract cookie name before first '='
        const namePart = value.split("=")[0] || "";
        const nameLower = namePart.toLowerCase();

        const looksSensitive =
          nameLower.includes("session") ||
          nameLower.includes("auth") ||
          nameLower.includes("token") ||
          nameLower.includes("jwt");

        if (!looksSensitive) return;

        const hasHttpOnly = lower.includes("httponly");
        const hasSecure = lower.includes("secure");

        if (!hasHttpOnly || !hasSecure) {
          categoryCounts.SENSITIVE_DATA_EXPOSURE++;
          const missingFlags = !hasHttpOnly && !hasSecure
            ? "HttpOnly and Secure"
            : !hasHttpOnly
            ? "HttpOnly"
            : "Secure";

          logDetection({
            url,
            type: "COOKIE_WEAK_SENSITIVE",
            category: "SENSITIVE_DATA_EXPOSURE",
            severity: "warning",
            details:
              "Cookie '" +
              namePart +
              "' missing " +
              missingFlags +
              " flag(s)",
          });
          showNotification(
            "Weak Sensitive Cookie",
            "Sensitive cookie '" +
              namePart +
              "' missing " +
              missingFlags +
              " flag(s).",
            "warning",
            details.tabId,
            "SENSITIVE_DATA_EXPOSURE"
          );
        }
      });
    } catch (e) {
      console.warn("[HEADER CHECK] Failed:", e);
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
