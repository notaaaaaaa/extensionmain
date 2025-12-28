// Advanced spam and suspicious network activity simulation

class SpamGenerator {
  constructor() {
    this.isRunning = false;
    this.requestCount = 0;
    this.startTime = null;
    this.intervals = [];
  }

  // High-frequency API calls
  startAPISpam() {
    console.log("🚨 Starting API spam attack simulation...");
    this.isRunning = true;
    this.startTime = Date.now();
    this.requestCount = 0;

    const apiEndpoints = [
      "/api/users",
      "/api/posts",
      "/api/comments",
      "/api/auth/login",
      "/api/data/export",
      "/api/admin/settings",
      "/api/payment/process",
      "/api/user/profile",
    ];

    // Rapid fire requests - 10 requests per second
    const rapidInterval = setInterval(() => {
      if (!this.isRunning) {
        clearInterval(rapidInterval);
        return;
      }

      const endpoint =
        apiEndpoints[Math.floor(Math.random() * apiEndpoints.length)];
      const url = `${endpoint}?spam=true&count=${
        this.requestCount
      }&timestamp=${Date.now()}`;

      fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Spam-Test": "true",
        },
        body: JSON.stringify({
          spamData: `spam_${this.requestCount}`,
          maliciousPayload: "test_payload_" + Math.random(),
        }),
      }).catch((e) => {
        // Expected to fail - we're just testing the behavior
      });

      this.requestCount++;

      if (this.requestCount >= 200) {
        this.stopSpam();
      }
    }, 100); // 10 requests per second

    this.intervals.push(rapidInterval);
  }

  // WebSocket spam simulation
  startWebSocketSpam() {
    console.log("🚨 Starting WebSocket spam simulation...");

    try {
      // Attempt to create multiple WebSocket connections
      for (let i = 0; i < 10; i++) {
        setTimeout(() => {
          try {
            const ws = new WebSocket("wss://echo.websocket.org/");

            ws.onopen = () => {
              console.log(`WebSocket connection ${i} opened`);

              // Spam messages through WebSocket
              const spamInterval = setInterval(() => {
                if (ws.readyState === WebSocket.OPEN) {
                  ws.send(
                    JSON.stringify({
                      type: "spam",
                      message: `Spam message ${Date.now()}`,
                      malicious: true,
                    })
                  );
                } else {
                  clearInterval(spamInterval);
                }
              }, 50);

              this.intervals.push(spamInterval);

              // Close connection after a while
              setTimeout(() => {
                ws.close();
              }, 5000);
            };

            ws.onerror = (error) => {
              console.log(`WebSocket ${i} error:`, error);
            };
          } catch (e) {
            console.log(`Failed to create WebSocket ${i}:`, e);
          }
        }, i * 200);
      }
    } catch (error) {
      console.log("WebSocket spam failed:", error);
    }
  }

  // Image loading spam (bandwidth consumption)
  startImageSpam() {
    console.log("🚨 Starting image loading spam...");

    const imageUrls = [
      "https://picsum.photos/800/600?random=",
      "https://via.placeholder.com/1000x800?text=Spam",
      "https://httpbin.org/image/jpeg?spam=",
    ];

    for (let i = 0; i < 50; i++) {
      setTimeout(() => {
        const img = new Image();
        const baseUrl = imageUrls[i % imageUrls.length];
        img.src = `${baseUrl}${Math.random()}`;

        img.onload = () => console.log(`Spam image ${i} loaded`);
        img.onerror = () => console.log(`Spam image ${i} failed`);

        // Remove image from DOM to prevent memory buildup
        setTimeout(() => {
          img.src = "";
        }, 1000);
      }, i * 100);
    }
  }

  // DNS lookup spam
  startDNSSpam() {
    console.log("🚨 Starting DNS lookup spam...");

    const suspiciousDomains = [
      "malware-test-domain-1.com",
      "phishing-simulator.net",
      "fake-banking-site.org",
      "suspicious-download.info",
      "malicious-payload.biz",
      "virus-test-domain.co",
      "exploit-kit-test.ru",
      "command-control-sim.tk",
    ];

    suspiciousDomains.forEach((domain, index) => {
      setTimeout(() => {
        // Attempt to resolve domain (will fail, but generates DNS traffic)
        fetch(`https://${domain}/test`, {
          mode: "no-cors",
          method: "HEAD",
        }).catch((e) => {
          console.log(`DNS lookup for ${domain}: ${e.message}`);
        });
      }, index * 500);
    });
  }

  // Port scanning simulation
  startPortScan() {
    console.log("🚨 Starting port scan simulation...");

    const commonPorts = [
      21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 3389, 5900,
    ];
    const targetHost = "scanme.nmap.org"; // Legitimate test host

    commonPorts.forEach((port, index) => {
      setTimeout(() => {
        fetch(`https://${targetHost}:${port}`, {
          method: "HEAD",
          mode: "no-cors",
        }).catch((e) => {
          console.log(`Port scan ${targetHost}:${port} - ${e.message}`);
        });
      }, index * 200);
    });
  }

  // Cross-origin request spam
  startCORSSpam() {
    console.log("🚨 Starting CORS spam...");

    const externalSites = [
      "https://google.com",
      "https://facebook.com",
      "https://amazon.com",
      "https://microsoft.com",
      "https://apple.com",
      "https://github.com",
      "https://stackoverflow.com",
      "https://reddit.com",
    ];

    externalSites.forEach((site, index) => {
      setTimeout(() => {
        fetch(site, {
          method: "GET",
          mode: "no-cors",
        }).catch((e) => {
          console.log(`CORS request to ${site}: ${e.message}`);
        });
      }, index * 300);
    });
  }

  // Background resource consumption
  startResourceExhaustion() {
    console.log("🚨 Starting resource exhaustion simulation...");

    // Memory consumption
    const memoryHog = [];
    for (let i = 0; i < 1000; i++) {
      memoryHog.push(new Array(10000).fill("spam"));
    }

    // CPU intensive task
    const cpuInterval = setInterval(() => {
      const start = Date.now();
      while (Date.now() - start < 50) {
        Math.random() * Math.random();
      }
    }, 100);

    this.intervals.push(cpuInterval);

    // Clean up after 10 seconds
    setTimeout(() => {
      clearInterval(cpuInterval);
      memoryHog.length = 0;
      console.log("Resource exhaustion simulation ended");
    }, 10000);
  }

  // Stop all spam activities
  stopSpam() {
    console.log("Stopping all spam activities...");
    this.isRunning = false;

    this.intervals.forEach((interval) => clearInterval(interval));
    this.intervals = [];

    const endTime = Date.now();
    const duration = (endTime - this.startTime) / 1000;
    console.log(
      `Spam simulation ended. Duration: ${duration}s, Requests: ${this.requestCount}`
    );
  }

  // Run all spam types
  runFullSpamSuite() {
    console.log("🚨 Starting full spam test suite...");

    this.startAPISpam();

    setTimeout(() => this.startWebSocketSpam(), 1000);
    setTimeout(() => this.startImageSpam(), 2000);
    setTimeout(() => this.startDNSSpam(), 3000);
    setTimeout(() => this.startPortScan(), 4000);
    setTimeout(() => this.startCORSSpam(), 5000);
    setTimeout(() => this.startResourceExhaustion(), 6000);

    // Auto-stop after 30 seconds
    setTimeout(() => this.stopSpam(), 30000);
  }
}

// Make it globally available
window.SpamGenerator = SpamGenerator;

// Auto-start if loaded directly
if (window.location.pathname.includes("spam.js")) {
  const spammer = new SpamGenerator();
  spammer.runFullSpamSuite();
}

// Export for use in other files
if (typeof module !== "undefined" && module.exports) {
  module.exports = SpamGenerator;
}
