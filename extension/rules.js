// Rules object for extension detection patterns
const rules = {
  sqli: /('|--|%27|OR 1=1|UNION SELECT|SELECT \* FROM|DROP TABLE|INSERT INTO)/i,

  redirect: /(redirect|goto|location|weird|suspicious|malicious)=/i,

  inlineJS: /(alert\(|eval\(|document\.write|innerHTML.*script|new Function)/i,

  malwareDownload: /\.(exe|zip|bat|scr|cmd|pif|js|vbs)$/i,

  doubleExtension:
    /\.(?:pdf|docx?|xlsx?|pptx?|txt|rtf|png|jpe?g|gif|bmp|zip)\.(exe|scr|pif|bat|cmd|js|vbs|jar|iso)$/i,

  spam: {
    threshold: 10,
    timeframe: 2000, // 2 seconds
  },

  suspiciousUrls: /(malware|virus|exploit|payload|phishing|evil-server)/i,

  cookieTheft: /(document\.cookie|localStorage|sessionStorage)/i,
};

// Metadata for each detection type / rule ID used in logging
// Keys here match the `type` field passed to logDetection or THREAT_DETECTED.threatType
const ruleMetadata = {
  // Network-level rules (background.js)
  SQLI_URL_PATTERN: {
    id: "INJ_SQLI_01",
    description: "URL contains SQL injection-like payload patterns.",
  },
  REDIRECT_SUSPICIOUS: {
    id: "CLIENT_REDIRECT_01",
    description: "Suspicious redirect parameter observed in URL.",
  },
  MALWARE_EXECUTABLE_DOWNLOAD: {
    id: "MALWARE_DL_01",
    description: "Executable-like file download detected.",
  },
  MALWARE_DOUBLE_EXTENSION: {
    id: "MISCONF_FILE_01",
    description: "File with suspicious double extension requested.",
  },
  DOWNLOAD_WITHOUT_USER_GESTURE: {
    id: "CLIENT_DOWNLOAD_01",
    description: "Download initiated without a recent user gesture.",
  },
  DOWNLOAD_INSECURE_HTTP: {
    id: "MISCONF_DOWNLOAD_01",
    description: "Download over insecure HTTP detected.",
  },
  SPAM_REQUEST_BURST: {
    id: "CLIENT_SPAM_01",
    description: "High-frequency burst of outgoing requests detected.",
  },
  MIME_MISMATCH_EXECUTABLE: {
    id: "MISCONF_MIME_01",
    description:
      "Document-like content type served with executable file extension.",
  },
  MIME_MISMATCH_GENERAL: {
    id: "MISCONF_MIME_02",
    description: "File extension does not match Content-Type header.",
  },
  HEADER_MISSING_CSP: {
    id: "MISCONF_HDR_01",
    description: "Missing Content-Security-Policy on HTTPS response.",
  },
  HEADER_MISSING_HSTS: {
    id: "MISCONF_HDR_02",
    description: "Missing Strict-Transport-Security on HTTPS response.",
  },
  HEADER_WEAK_REFERRER_POLICY: {
    id: "MISCONF_HDR_03",
    description: "Weak or absent Referrer-Policy header detected.",
  },
  HEADER_MISSING_XFO: {
    id: "MISCONF_HDR_04",
    description: "Missing X-Frame-Options header (possible clickjacking).",
  },
  COOKIE_WEAK_SENSITIVE: {
    id: "SDE_COOKIE_01",
    description:
      "Sensitive cookie missing HttpOnly and/or Secure flags detected.",
  },

  // Content-script THREAT_DETECTED types (content.js)
  INLINE_SCRIPT: {
    id: "XSS_INLINE_01",
    description: "Inline script content matching XSS-like patterns.",
  },
  SUSPICIOUS_ATTRIBUTE: {
    id: "INJ_EVENT_HANDLER_01",
    description:
      "Suspicious inline event handler using javascript: or eval-like code.",
  },
  CLIPBOARD_THEFT: {
    id: "CLIENT_CLIPBOARD_01",
    description: "Page attempted to read clipboard contents.",
  },
  CLIPBOARD_MANIPULATION: {
    id: "CLIENT_CLIPBOARD_02",
    description: "Page attempted to overwrite clipboard contents.",
  },
  KEYLOGGER: {
    id: "CLIENT_KEYLOGGER_01",
    description:
      "Multiple keyboard event listeners detected (possible keylogger).",
  },
  CAMERA_ACCESS: {
    id: "CLIENT_CAMERA_01",
    description: "Page requested access to the camera.",
  },
  MICROPHONE_ACCESS: {
    id: "CLIENT_MIC_01",
    description: "Page requested access to the microphone.",
  },
  AUTO_REDIRECT_BLOCKED: {
    id: "CLIENT_REDIRECT_02",
    description:
      "Automatic client-side redirect without user gesture detected.",
  },
  CREDENTIAL_HIJACKING_BLOCKED: {
    id: "AUTH_HIJACK_01",
    description:
      "Login form attempted to send credentials to third-party or insecure origin.",
  },
  RUNTIME_XSS_INNERHTML: {
    id: "XSS_SINK_01",
    description: "Potential XSS via assignment to innerHTML.",
  },
  RUNTIME_XSS_DOCUMENT_WRITE: {
    id: "XSS_SINK_02",
    description: "Potential XSS via document.write.",
  },
  RUNTIME_XSS_INSERT_ADJACENT_HTML: {
    id: "XSS_SINK_03",
    description: "Potential XSS via insertAdjacentHTML.",
  },
};

// Make rules and metadata available globally for content scripts
if (typeof window !== "undefined") {
  window.rules = rules;
  window.ruleMetadata = ruleMetadata;
}

// For service workers, make rules and metadata available globally
if (typeof self !== "undefined") {
  self.rules = rules;
  self.ruleMetadata = ruleMetadata;
}
