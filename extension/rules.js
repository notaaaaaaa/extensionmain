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

// Make rules available globally for content scripts
if (typeof window !== "undefined") {
  window.rules = rules;
}

// For service workers, make rules available globally

if (typeof self !== "undefined") {
  self.rules = rules;
}
