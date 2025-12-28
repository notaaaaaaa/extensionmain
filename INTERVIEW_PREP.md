# Web Intrusion Detector - Interview Preparation Guide

## 1. Problem Statement

**The Core Issue:**
Websites contain hidden security threats (SQL injection, redirects, clipboard stealing, keyloggers, credential hijacking) that users can't detect. Traditional antivirus only catches known malware, browsers block known bad URLs, and firewalls work at network level—none analyze real-time web behavior.

**The Goal:**
A browser extension that acts as a real-time security watchdog, monitoring network requests and page behavior to detect and alert users about suspicious activities before they cause harm.

---

## 2. Solution Overview

1. **Extension activates** on every webpage automatically
2. **Dual monitoring**: Background script monitors network requests; content script monitors page behavior
3. **Pattern matching**: Checks against regex rules and detects unusual behavior (downloads without clicks)
4. **Real-time alerts**: Visual on-page alerts showing threat type, details, and severity

---

## 3. Architecture Components

**A. Manifest.json** - Configuration defining permissions (webRequest, scripting, notifications) and scripts

**B. Rules.js** - Regex patterns for threats:
- SQL Injection: `/(SELECT \* FROM|DROP TABLE|OR 1=1)/i`
- Malware: `/\.(exe|zip|bat|scr)$/i`
- Spam: 10 requests in 2 seconds

**C. Background.js** - Service worker monitoring network:
- `onBeforeRequest`: Checks URLs for SQL injection, redirects, malware
- `onHeadersReceived`: Validates MIME types
- Tracks spam and downloads without user gestures

**D. Content.js** - Page behavior monitor:
- Detects inline JavaScript threats (eval, document.write)
- Intercepts clipboard/keyboard access
- Monitors camera/microphone requests
- Blocks credential hijacking to third-party domains

**Data Flow Example:**
```
User clicks: example.com?id=1' OR 1=1--
→ Background.js intercepts → Regex match found
→ Sends alert to content.js → Alert displayed on page
```

---

## 4. Tech Stack Breakdown

**1. JavaScript (ES6+)** - Core language for browser extensions, uses Chrome APIs, event-driven programming, regex pattern matching

**2. Chrome Extension Manifest V3** - Framework with APIs to intercept network requests and inject scripts. Service workers are more efficient than old background pages. Message passing enables communication between components.

**3. Regular Expressions (Regex)** - Fast pattern matching for threats. Detects attack variations without listing every possibility.

**4. Chrome WebRequest API** - Intercepts network traffic before requests are sent. Access to HTTP headers for validation.

**5. MutationObserver API** - Watches for dynamic DOM changes to catch scripts added after page loads.

### **Socket.IO & PostgreSQL Integration (Future Enhancement):**

**Socket.IO**: Real-time bidirectional communication for sending threat alerts to central server, sharing threat intelligence across users, and pushing updated rules.

**PostgreSQL**: Relational database storing detected threats with timestamps, tracking patterns across users, enabling analytics queries like "most common threats today", and supporting machine learning on threat patterns.

---

## 5. Key Technical Concepts

### **A. Chrome Extension Architecture**

Extensions have special permissions regular websites don't. My extension uses:
- **Service Worker**: Monitors network traffic independently
- **Content Scripts**: Injected into webpages, isolated from page JavaScript
- **Message Passing**: Communication via `chrome.runtime.sendMessage()`

**Interview explanation:** "My background service worker monitors network requests at the browser level, while content scripts run on each webpage to monitor behavior. This separation provides both power and security."

### **B. Regex Pattern Matching**

Catches attack variations without exact matches. Example SQL Injection:
```javascript
/('|--|%27|OR 1=1|UNION SELECT|DROP TABLE)/i
```
Checks for quotes, SQL keywords, boolean logic, and comment syntax. Case insensitive (`i` flag).

### **C. Function Interception**

Wraps native browser APIs to detect threats:
```javascript
const originalReadText = navigator.clipboard.readText;
navigator.clipboard.readText = function() {
  alert("Clipboard theft detected!");
  return originalReadText.apply(this, arguments);
};
```
Detects threats without breaking legitimate functionality.

---

## 6. Common Interview Questions with Answers

### **Q1: What are the limitations of your project?**

**Answer:**
"There are several limitations:

1. **False Positives**: Legitimate URLs might contain SQL keywords like 'SELECT' in product names. My regex patterns might flag these incorrectly.

2. **Performance Impact**: Checking every network request adds slight overhead. On websites with thousands of requests, this could slow things down.

3. **Sophisticated Attacks**: My detection is pattern-based. Advanced attackers might obfuscate their code to bypass regex patterns. For example, encoded or encrypted payloads wouldn't match.

4. **Browser Compatibility**: Built for Chrome/Chromium browsers only. Firefox uses a different extension API.

5. **No Machine Learning**: Currently uses static rules. Doesn't learn from new attack patterns automatically.

6. **Client-Side Only**: Only detects threats on the user's browser. Doesn't protect the actual server or database.

7. **Privacy Concerns**: Extension sees all network traffic, which requires user trust."

---

### **Q2: What's the future scope for this project?**

**Answer:**
"I see several enhancement opportunities:

1. **Machine Learning Integration**: 
   - Train models on attack datasets
   - Detect zero-day threats (never-seen-before attacks)
   - Reduce false positives with better pattern recognition

2. **Cloud-Based Threat Intelligence**:
   - Use Socket.IO to connect extensions to a central server
   - Share detected threats across all users in real-time
   - Build a threat database in PostgreSQL
   - Enable crowdsourced security

3. **Advanced Analytics Dashboard**:
   - Web portal showing threat statistics
   - Timeline of attacks
   - Geolocation of threat sources
   - Most targeted websites

4. **Proactive Protection**:
   - Not just detect, but actively block malicious requests
   - Sandbox suspicious scripts before execution
   - Auto-patch vulnerable patterns

5. **Cross-Browser Support**:
   - Port to Firefox, Safari, Edge
   - Use WebExtensions standard

6. **Integration with Security Tools**:
   - Export logs to SIEM systems
   - Integration with VirusTotal for file scanning
   - Report threats to security services

7. **User Reputation System**:
   - Whitelist trusted domains
   - Remember user preferences
   - Adaptive security levels"

---

### **Q1: What are the limitations?**

1. **False Positives**: Legitimate URLs with SQL keywords might be flagged
2. **Performance**: Slight overhead on websites with thousands of requests
3. **Sophisticated Attacks**: Pattern-based detection can be bypassed by obfuscation
4. **Browser Compatibility**: Chrome/Chromium only
5. **No Machine Learning**: Static rules don't learn from new patterns
6. **Client-Side Only**: Doesn't protect servers or databases

### **Q2: Future scope?**

1. **Machine Learning**: Train models to detect zero-day threats and reduce false positives
2. **Cloud Threat Intelligence**: Socket.IO server + PostgreSQL database for real-time threat sharing across users
3. **Analytics Dashboard**: Web portal with threat statistics, timelines, geolocation
4. **Proactive Blocking**: Actively block requests, sandbox suspicious scripts
5. **Cross-Browser Support**: Port to Firefox, Safari, Edge
6. **SIEM Integration**: Export logs, VirusTotal integration
7. **User Reputation**: Whitelist trusted domains, adaptive security

### **Q3: Walk me through the architecture**

Three layers:
1. **Detection Layer**: Rules.js with regex patterns
2. **Monitoring Layer**: Background worker (network) + Content script (page behavior)
3. **Alerting Layer**: Message passing to display visual alerts

Background has network access, content has DOM access—isolated for security.

### **Q4: How does SQL injection detection work?**

WebRequest API intercepts every URL → Tests against regex `/(SELECT \* FROM|DROP TABLE|OR 1=1)/i` → Checks for quotes, SQL keywords, boolean logic, comment syntax → If matched, sends alert to content script → User sees warning.

Fast and catches common patterns, but won't catch hex-encoded payloads.

### **Q5: How do you prevent false positives?**

**Current**: Precise regex, context awareness (e.g., downloads without user gesture), severity levels, user gesture tracking

**Future**: Whitelist system, machine learning from user feedback, reputation scoring, contextual analysis

### **Q6: Why browser extension vs proxy/firewall?**

**Advantages**: DOM access for client-side threats, user context awareness, zero config, portable, rich visual alerts

**Disadvantages**: Client-side only, per-browser install, uses device resources

**Best for**: Personal browsing protection. Organizations need both extensions and network-level protection.

### **Q7: How do you handle performance?**

Regex compiled once, short-circuit evaluation, targeted monitoring (skip images), lightweight alerts, efficient data structures (timestamp arrays), background processing. Overhead <5ms per request, <10MB memory.

### **Q8: How would you add Socket.IO and PostgreSQL?**

```
Extension → Socket.IO Client → Server → PostgreSQL
```

**Backend**: Node.js server receives threats via Socket.IO, stores in PostgreSQL, broadcasts to other users

**Extension**: Connects via WebSocket, emits threat events, receives alerts from other users

**PostgreSQL Schema**: Store threats with type, URL, timestamp, user_id, severity. Enable analytics and threat reputation scoring.ned (can't access)
```

**Why This Matters:**
Even if a website is malicious, it can't:
- Disable the extension
- Steal extension's code
- Interfere with threat detection
- Access extension's storage or permissions

---

### **Concept 3: MIME Type Mismatch Detection**

**What is MIME Type?**
MIME (Multipurpose Internet Mail Extensions) tells the browser what type of content is being received.

**Common MIME Types:**
- `text/html` - HTML webpage
- `application/pdf` - PDF file
- `image/jpeg` - JPEG image
- `application/x-msdownload` - Executable file

**The Attack:**
Malicious servers send executable files but label them as documents:
```
Filename: "report.pdf"
MIME Type: "application/x-msdownload" (executable!)
```

User thinks they're downloading a PDF, but it's actually malware.

**My Detection Logic**:
```javascript
// Get file extension from URL
const ext = url.split('.').pop(); // "pdf"

// Get MIME type from HTTP header
const mimeType = headers['Content-Type']; // "application/x-msdownload"

// Compare with expected MIME type
const expectedMime = mimeTypeMap["pdf"]; // "application/pdf"

if (mimeType !== expectedMime) {
  alert("MIME Type Mismatch - Possible Malware!");
}
```

**Interview Tip:**
"MIME mismatch detection catches disguised malware. Attackers try to trick users by naming executables as documents. I validate that the HTTP Content-Type header matches the file extension. Mismatches trigger critical alerts."

---

### **Concept 4: Rate Limiting and Spam Detection**

**The Algorithm:**
Sliding window rate limiting tracks request frequency.

**Implementation**:
```javascript
let requestTimestamps = []; // Array of timestamps

// When new request comes
const now = Date.now();
requestTimestamps.push(now);

// Remove old timestamps outside the time window
requestTimestamps = requestTimestamps.filter(
  t => now - t < 2000  // Keep only last 2 seconds
);

// Check if threshold exceeded
if (requestTimestamps.length >= 10) {
  alert("Spam detected: Too many requests!");
}
```

**Visual Example**:
```
Time window: 2 seconds
Threshold: 10 requests

0s ----●●●----1s----●●●●●●●----2s----●----3s
       3 reqs       7 reqs      1 req
       
Total in window: 10 requests → SPAM DETECTED!
```

**Why This Approach?**
- **Memory Efficient**: Only stores timestamps, not full request data
- **Accurate**: Sliding window is more precise than fixed intervals
- **Adjustable**: Easy to change threshold or timeframe

**Real-World Use Case:**
Detects:
- DDoS attacks from compromised browsers
- Malicious scripts making rapid API calls
- Credential stuffing attempts
- Resource exhaustion attacks

---

### **Concept 5: Function Interception Pattern**

**The Pattern:**
Wrapper pattern to intercept native browser APIs.

**Generic Template**:
```javascript
// Step 1: Save original function
const originalFunction = object.method;

// Step 2: Replace with wrapper
object.method = function(...args) {
  // Step 3: Pre-processing (security check)
  console.log("Method called with:", args);
  detectMaliciousUsage(args);
  
  // Step 4: Call original function
  const result = originalFunction.apply(this, args);
  
  // Step 5: Post-processing (log result)
  console.log("Method returned:", result);
  
  return result;
};
```

**Applied to Clipboard Theft**:
```javascript
const originalReadText = navigator.clipboard.readText;

navigator.clipboard.readText = function() {
  // Security check
  alert("⚠️ Website is trying to read your clipboard!");
  
  // Log the attempt
  logSecurityEvent("clipboard_theft_attempt");
  
  // Allow original operation (for legitimate use)
  return originalReadText.apply(this, arguments);
};
```

**Why This Works:**
- **Transparent**: Website's code continues to function
- **Non-invasive**: Doesn't break legitimate usage
- **Proactive**: Detects threats before they succeed
- **Informative**: Alerts user to suspicious behavior

**Other Applications:**
- Detecting geolocation access
- Monitoring localStorage access
- Tracking form data interception
- Detecting WebRTC access (IP leak prevention)

---

## 8. Additional Technical Questions

### **Q: What's the difference between content script and injected script?**

**Answer:**
"Content scripts are part of the extension and run in isolated context. Injected scripts (using `<script>` tags) run in the page's context and can interact with page variables. Content scripts are more secure but can't directly access page JavaScript. For my security extension, I use content scripts to maintain isolation from potentially malicious page code."

---

### **Q: How do you handle HTTPS vs HTTP?**

**Answer:**
"My extension works with both, but I flag HTTP downloads as extra suspicious since they're unencrypted. HTTPS protects data in transit, but my extension also protects against application-layer attacks (SQL injection, XSS) that HTTPS doesn't prevent. I check URLs regardless of protocol but add severity for HTTP-based threats."

---

### **Q: What happens if a website uses obfuscated JavaScript?**

**Answer:**
"Obfuscation would evade my regex patterns. To address this:
1. Current: I detect the use of obfuscation itself (eval, Function constructor) as suspicious
2. Future: Could add a de-obfuscation layer or use AST (Abstract Syntax Tree) analysis
3. Alternative: Use behavior-based detection instead of pattern matching - watch what the code actually does rather than what it looks like."

---

## 9. Key Talking Points Summary

When discussing your project, emphasize:

1. **Real-world Problem**: Users face invisible web threats daily
2. **Comprehensive Approach**: Both network and behavior monitoring
3. **User-Friendly**: Visual alerts anyone can understand
4. **Architecture**: Clean separation between background monitoring and content-side detection
5. **Scalability**: Designed with future cloud integration in mind (Socket.IO + PostgreSQL)
6. **Performance**: Lightweight with minimal overhead
7. **Learning Opportunity**: Gained expertise in Chrome APIs, security patterns, and full-stack potential

---

## 10. Demo Talking Points

When demonstrating:

1. **Start Simple**: "Let me show you SQL injection detection"
2. **Show Normal Case**: "Here's a normal URL - no alert"
3. **Show Attack**: "Now watch what happens with a malicious URL"
4. **Explain the Alert**: "Notice the red alert with details"
5. **Show Multiple Threats**: "The extension detects many attack types"
6. **Discuss Limitations**: "Of course, sophisticated attacks might evade detection"
7. **Future Vision**: "With Socket.IO, we could share threats across users in real-time"

---

## Good Luck with Your Interview! 🚀

Remember:
- Speak confidently about what you built
- Be honest about limitations
- Show enthusiasm for future improvements
- Explain concepts in simple terms
- Use concrete examples
- Relate it to real-world security needs

You've built a sophisticated security tool that demonstrates understanding of:
- Browser internals
- SecuAdditional Technical Concepts

### **Service Workers (Manifest V3)**
Event-driven, sleep when idle (vs old persistent background pages). More efficient for battery/memory. Lifecycle: Install → Activate → Listen → Process → Sleep after 30s → Wake on event.

### **Isolated Contexts**
Content scripts run separately from webpage JavaScript. Malicious websites can't disable extension, steal code, or interfere with detection.

### **MIME Type Mismatch Detection**
Validates HTTP Content-Type header matches file extension. Example: `report.pdf` with MIME `application/x-msdownload` = disguised malware.

```javascript
const ext = url.split('.').pop(); // "pdf"
const mimeType = headers['Content-Type'];
if (mimeType !== expectedMimeMap[ext]) alert("Possible Malware!");
```

### **Rate Limiting (Sliding Window)**
Tracks timestamps in array, removes old entries outside 2-second window, alerts if ≥10 requests. Detects DDoS, rapid API calls, credential stuffing.

### **Function Interception Pattern**
```javascript
const original = navigator.clipboard.readText;
navigator.clipboard.readText = function() {
  alert("Clipboard theft detected!");
  return original.apply(this, arguments);
};
```
Transparent, non-invasive, proactive detection.8. Key Points to Emphasize

- **Real-world problem**: Invisible web threats daily
- **Comprehensive**: Network + behavior monitoring
- **Clean architecture**: Separation between background and content monitoring
- **Scalable**: Future cloud integration (Socket.IO + PostgreSQL)
- **Performance**: Lightweight (<5ms overhead, <10MB memory)
- **Skills demonstrated**: Chrome APIs, security patterns, event-driven architecture

---

## 9. Demo Flow

1. Show SQL injection detection with normal vs attack URL
2. Demonstrate multiple threat types (clipboard, keylogger, downloads)
3. Explain the visual alerts
4. Discuss limitations honestly
5. Share future vision (real-time threat sharing)

---

## Good Luck! 🚀

**Remember**: Speak confidently, be honest about limitations, use concrete examples, and relate it to real-world security needs. You built a sophisticated security tool—o