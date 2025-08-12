// WebAuthn Authentication Client
class WebAuthnClient {
  constructor() {
    this.baseURL = "http://localhost:8080";
    this.accessToken = null;
    this.isAuthenticated = false;
    this.init();
  }

  async init() {
    this.setupEventListeners();
    await this.checkBackendConnection();
    this.checkAuthStatus();
    this.log("Client initialized", "info");
  }

  // Setup all event listeners
  setupEventListeners() {
    // Registration form
    document.getElementById("register-form").addEventListener("submit", (e) => {
      e.preventDefault();
      this.handleRegistration();
    });

    // Login form
    document.getElementById("login-form").addEventListener("submit", (e) => {
      e.preventDefault();
      this.handleLogin();
    });

    // Check backend connection every 10 seconds
    setInterval(() => this.checkBackendConnection(), 10000);
  }

  // Check if backend is reachable
  async checkBackendConnection() {
    try {
      const response = await fetch(`${this.baseURL}/`, {
        method: "OPTIONS",
        credentials: "include",
      });

      if (response.ok) {
        this.updateConnectionStatus(true);
      } else {
        this.updateConnectionStatus(false);
      }
    } catch (error) {
      this.updateConnectionStatus(false);
    }
  }

  // Update connection status indicator
  updateConnectionStatus(isConnected) {
    const statusElement = document.getElementById("connection-status");
    const dot = statusElement.querySelector(".status-dot");
    const text = statusElement.querySelector("span:last-child");

    if (isConnected) {
      dot.className = "status-dot online";
      text.textContent = "Backend: Connected";
    } else {
      dot.className = "status-dot offline";
      text.textContent = "Backend: Disconnected";
    }
  }

  // Update authentication status
  updateAuthStatus(isAuthenticated, username = "") {
    this.isAuthenticated = isAuthenticated;
    const statusElement = document.getElementById("auth-status");
    const dot = statusElement.querySelector(".status-dot");
    const text = statusElement.querySelector("span:last-child");

    if (isAuthenticated) {
      dot.className = "status-dot authenticated";
      text.textContent = `Authenticated: ${username}`;
    } else {
      dot.className = "status-dot";
      text.textContent = "Not authenticated";
    }
  }

  // Check current authentication status
  checkAuthStatus() {
    const token = this.accessToken;
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split(".")[1]));
        const now = Date.now() / 1000;
        if (payload.exp > now) {
          this.updateAuthStatus(true, payload.username);
          this.displayAccessToken(token);
          return;
        }
      } catch (error) {
        this.log("Invalid token format", "error");
      }
    }
    this.updateAuthStatus(false);
  }

  // Handle user registration
  async handleRegistration() {
    const username = document.getElementById("register-username").value.trim();
    const role = document.getElementById("register-role").value.trim();

    if (!username || username.length < 3) {
      this.log("Username must be at least 3 characters", "error");
      return;
    }

    this.resetSteps("reg");
    this.log(`Starting registration for user: ${username}`, "info");

    try {
      // Step 1: Begin registration
      this.updateStep("reg-step-1", "pending");
      const beginResponse = await this.beginRegistration(username, role);
      this.updateStep("reg-step-1", "success");
      this.log("Registration challenge received", "success");

      // Step 2: Create credentials
      this.updateStep("reg-step-2", "pending");
      const credential = await this.createCredentials(
        beginResponse.options.publicKey,
      );
      this.updateStep("reg-step-2", "success");
      this.log("Credentials created successfully", "success");

      // Step 3: Finish registration
      this.updateStep("reg-step-3", "pending");
      await this.finishRegistration(
        username,
        beginResponse.session_id,
        credential,
      );
      this.updateStep("reg-step-3", "success");
      this.log(
        `Registration completed successfully for ${username}`,
        "success",
      );
    } catch (error) {
      this.handleRegistrationError(error);
    }
  }

  // Begin registration with backend
  async beginRegistration(username, role) {
    const payload = { username };
    if (role) payload.role = role;

    this.log(
      "Sending registration begin request: " + JSON.stringify(payload),
      "info",
    );

    const response = await fetch(`${this.baseURL}/register/begin`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const error = await response.json();
      this.log("Registration begin failed: " + JSON.stringify(error), "error");
      throw new Error(error.message || "Registration begin failed");
    }

    const result = await response.json();
    this.log(
      "Registration begin response: " + JSON.stringify(result, null, 2),
      "info",
    );
    return result;
  }

  // Create WebAuthn credentials
  async createCredentials(options) {
    this.log(
      "Creating credentials with options: " + JSON.stringify(options, null, 2),
      "info",
    );

    // Validate that required fields exist
    if (!options.challenge) {
      throw new Error("Missing challenge in credential options");
    }
    if (!options.user || !options.user.id) {
      throw new Error("Missing user.id in credential options");
    }

    // Convert base64url strings to ArrayBuffers
    options.challenge = this.base64urlToArrayBuffer(options.challenge);
    options.user.id = this.base64urlToArrayBuffer(options.user.id);

    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map((cred) => ({
        ...cred,
        id: this.base64urlToArrayBuffer(cred.id),
      }));
    }

    const credential = await navigator.credentials.create({
      publicKey: options,
    });

    return {
      id: credential.id,
      rawId: this.arrayBufferToBase64url(credential.rawId),
      response: {
        attestationObject: this.arrayBufferToBase64url(
          credential.response.attestationObject,
        ),
        clientDataJSON: this.arrayBufferToBase64url(
          credential.response.clientDataJSON,
        ),
      },
      type: credential.type,
    };
  }

  // Finish registration with backend
  async finishRegistration(username, sessionId, credentials) {
    const response = await fetch(`${this.baseURL}/register/finish`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify({
        username,
        session_id: sessionId,
        credentials,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || "Registration finish failed");
    }

    return await response.json();
  }

  // Handle registration errors
  handleRegistrationError(error) {
    this.log(`Registration failed: ${error.message}`, "error");

    // Update appropriate step to error state
    const steps = ["reg-step-1", "reg-step-2", "reg-step-3"];
    for (const stepId of steps) {
      const step = document.getElementById(stepId);
      if (step.classList.contains("pending")) {
        this.updateStep(stepId, "error");
        break;
      }
    }
  }

  // Handle user login
  async handleLogin() {
    const username = document.getElementById("login-username").value.trim();

    if (!username || username.length < 3) {
      this.log("Username must be at least 3 characters", "error");
      return;
    }

    this.resetSteps("login");
    this.log(`Starting login for user: ${username}`, "info");

    try {
      // Step 1: Begin login
      this.updateStep("login-step-1", "pending");
      const beginResponse = await this.beginLogin(username);
      this.updateStep("login-step-1", "success");
      this.log("Login challenge received", "success");

      // Step 2: Get assertion
      this.updateStep("login-step-2", "pending");
      const assertion = await this.getAssertion(
        beginResponse.options.publicKey,
      );
      this.updateStep("login-step-2", "success");
      this.log("Authentication assertion created", "success");

      // Step 3: Finish login
      this.updateStep("login-step-3", "pending");
      const loginResult = await this.finishLogin(
        username,
        beginResponse.session_id,
        assertion,
      );
      this.updateStep("login-step-3", "success");

      this.accessToken = loginResult.access_token;
      this.updateAuthStatus(true, username);
      this.displayAccessToken(loginResult.access_token);
      this.log(`Login completed successfully for ${username}`, "success");
    } catch (error) {
      this.handleLoginError(error);
    }
  }

  // Begin login with backend
  async beginLogin(username) {
    this.log("Sending login begin request for user: " + username, "info");

    const response = await fetch(`${this.baseURL}/login/begin`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify({ username }),
    });

    if (!response.ok) {
      const error = await response.json();
      this.log("Login begin failed: " + JSON.stringify(error), "error");
      throw new Error(error.message || "Login begin failed");
    }

    const result = await response.json();
    this.log(
      "Login begin response: " + JSON.stringify(result, null, 2),
      "info",
    );
    return result;
  }

  // Get WebAuthn assertion
  // Get assertion from authenticator
  async getAssertion(options) {
    this.log(
      "Getting assertion with options: " + JSON.stringify(options, null, 2),
      "info",
    );

    // Validate that required fields exist
    if (!options.challenge) {
      throw new Error("Missing challenge in assertion options");
    }

    // Convert base64url strings to ArrayBuffers
    options.challenge = this.base64urlToArrayBuffer(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map((cred) => ({
        ...cred,
        id: this.base64urlToArrayBuffer(cred.id),
      }));
    }

    const assertion = await navigator.credentials.get({
      publicKey: options,
    });

    return {
      id: assertion.id,
      rawId: this.arrayBufferToBase64url(assertion.rawId),
      response: {
        authenticatorData: this.arrayBufferToBase64url(
          assertion.response.authenticatorData,
        ),
        clientDataJSON: this.arrayBufferToBase64url(
          assertion.response.clientDataJSON,
        ),
        signature: this.arrayBufferToBase64url(assertion.response.signature),
        userHandle: assertion.response.userHandle
          ? this.arrayBufferToBase64url(assertion.response.userHandle)
          : null,
      },
      type: assertion.type,
    };
  }

  // Finish login with backend
  async finishLogin(username, sessionId, assertion) {
    const response = await fetch(`${this.baseURL}/login/finish`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify({
        username,
        session_id: sessionId,
        credentials: assertion,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || "Login finish failed");
    }

    return await response.json();
  }

  // Handle login errors
  handleLoginError(error) {
    this.log(`Login failed: ${error.message}`, "error");

    // Update appropriate step to error state
    const steps = ["login-step-1", "login-step-2", "login-step-3"];
    for (const stepId of steps) {
      const step = document.getElementById(stepId);
      if (step.classList.contains("pending")) {
        this.updateStep(stepId, "error");
        break;
      }
    }
  }

  // Display access token in the tokens tab
  displayAccessToken(token) {
    const tokenTextarea = document.getElementById("access-token");
    const tokenStatus = document.getElementById("access-token-status");

    tokenTextarea.value = token;

    try {
      const payload = JSON.parse(atob(token.split(".")[1]));
      const expiresAt = new Date(payload.exp * 1000);
      const now = new Date();
      const isValid = expiresAt > now;

      tokenStatus.textContent = isValid
        ? `Valid until ${expiresAt.toLocaleString()}`
        : "Expired";
      tokenStatus.style.color = isValid ? "#28a745" : "#dc3545";
    } catch (error) {
      tokenStatus.textContent = "Invalid token format";
      tokenStatus.style.color = "#dc3545";
    }
  }

  // Update step status
  updateStep(stepId, status) {
    const step = document.getElementById(stepId);
    step.className = `step ${status}`;
  }

  // Reset all steps for a process
  resetSteps(prefix) {
    for (let i = 1; i <= 3; i++) {
      const step = document.getElementById(`${prefix}-step-${i}`);
      step.className = "step";
    }
  }

  // Utility: Convert base64url to ArrayBuffer
  base64urlToArrayBuffer(base64url) {
    // Handle null or undefined values
    if (!base64url) {
      this.log("Error: base64url value is null or undefined", "error");
      throw new Error(
        "Cannot convert null or undefined base64url value to ArrayBuffer",
      );
    }

    const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
    const padding = base64.length % 4;
    const padded = padding ? base64 + "=".repeat(4 - padding) : base64;
    const binary = atob(padded);
    const buffer = new ArrayBuffer(binary.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
      view[i] = binary.charCodeAt(i);
    }
    return buffer;
  }

  // Utility: Convert ArrayBuffer to base64url
  arrayBufferToBase64url(buffer) {
    const binary = String.fromCharCode(...new Uint8Array(buffer));
    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  // Log message to the logs section
  log(message, type = "info") {
    const logsContainer = document.getElementById("logs");
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = document.createElement("div");
    logEntry.className = `log-entry ${type}`;
    logEntry.innerHTML = `<span class="log-timestamp">[${timestamp}]</span> ${message}`;

    logsContainer.appendChild(logEntry);

    // Auto-scroll if enabled
    const autoScroll = document.getElementById("auto-scroll").checked;
    if (autoScroll) {
      logsContainer.scrollTop = logsContainer.scrollHeight;
    }

    // Keep only last 100 log entries
    while (logsContainer.children.length > 100) {
      logsContainer.removeChild(logsContainer.firstChild);
    }
  }
}

// Global functions for UI interactions
function showTab(tabName) {
  // Hide all tab contents
  document.querySelectorAll(".tab-content").forEach((tab) => {
    tab.classList.remove("active");
  });

  // Remove active class from all tab buttons
  document.querySelectorAll(".tab-button").forEach((button) => {
    button.classList.remove("active");
  });

  // Show selected tab
  document.getElementById(`${tabName}-tab`).classList.add("active");

  // Add active class to clicked button
  event.target.classList.add("active");
}

// Refresh token function
async function refreshToken() {
  if (!window.webauthnClient) return;

  try {
    window.webauthnClient.log("Refreshing token...", "info");

    const response = await fetch(`${window.webauthnClient.baseURL}/refresh`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify({}),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || "Token refresh failed");
    }

    const result = await response.json();
    window.webauthnClient.accessToken = result.access_token;
    window.webauthnClient.displayAccessToken(result.access_token);
    window.webauthnClient.log("Token refreshed successfully", "success");

    // Update auth status
    const payload = JSON.parse(atob(result.access_token.split(".")[1]));
    window.webauthnClient.updateAuthStatus(true, payload.username);
  } catch (error) {
    window.webauthnClient.log(
      `Token refresh failed: ${error.message}`,
      "error",
    );
    window.webauthnClient.updateAuthStatus(false);
  }
}

// Logout function
async function logout() {
  if (!window.webauthnClient) return;

  try {
    window.webauthnClient.log("Logging out...", "info");

    const response = await fetch(`${window.webauthnClient.baseURL}/logout`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "include",
      body: JSON.stringify({}),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || "Logout failed");
    }

    // Clear local state
    window.webauthnClient.accessToken = null;
    window.webauthnClient.updateAuthStatus(false);

    // Clear token display
    document.getElementById("access-token").value = "";
    document.getElementById("access-token-status").textContent =
      "Not available";
    document.getElementById("access-token-status").style.color = "#6c757d";

    window.webauthnClient.log("Logged out successfully", "success");
  } catch (error) {
    window.webauthnClient.log(`Logout failed: ${error.message}`, "error");
  }
}

// Test protected endpoint (placeholder)
async function testProtectedEndpoint() {
  window.webauthnClient.log(
    "Testing protected endpoint (not implemented)",
    "warning",
  );

  const resultBox = document.getElementById("protected-result");
  resultBox.textContent =
    "Protected endpoint testing is not implemented in the backend yet.";
  resultBox.className = "result-box";
}

// Clear logs function
function clearLogs() {
  document.getElementById("logs").innerHTML = "";
}

// Initialize client when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  // Check WebAuthn support
  if (!window.PublicKeyCredential) {
    alert(
      "WebAuthn is not supported in this browser. Please use a modern browser with WebAuthn support.",
    );
    return;
  }

  // Initialize the WebAuthn client
  window.webauthnClient = new WebAuthnClient();
});

// Handle browser compatibility warnings
if (!window.PublicKeyCredential) {
  document.addEventListener("DOMContentLoaded", () => {
    const container = document.querySelector(".container");
    const warning = document.createElement("div");
    warning.className = "card";
    warning.style.background = "#f8d7da";
    warning.style.borderLeft = "4px solid #dc3545";
    warning.innerHTML = `
            <h3 style="color: #721c24;">⚠️ Browser Compatibility Warning</h3>
            <p style="color: #721c24;">WebAuthn is not supported in this browser. Please use a modern browser like:</p>
            <ul style="color: #721c24; margin-left: 20px;">
                <li>Chrome 67+</li>
                <li>Firefox 60+</li>
                <li>Safari 14+</li>
                <li>Edge 79+</li>
            </ul>
        `;
    container.insertBefore(warning, container.firstChild);
  });
}
