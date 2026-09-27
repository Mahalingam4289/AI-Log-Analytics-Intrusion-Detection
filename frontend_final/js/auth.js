// js/auth.js
const TOKEN_KEY = "sentinel_token";
const USER_KEY = "sentinel_user";

const Auth = {
  getToken() {
    return localStorage.getItem(TOKEN_KEY);
  },
  getUsername() {
    return localStorage.getItem(USER_KEY);
  },
  isAuthenticated() {
    return !!this.getToken();
  },
  async login(username, password) {
    const res = await fetch(`${window.SENTINEL_CONFIG.API_BASE}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || "Login failed");
    }
    const data = await res.json();
    localStorage.setItem(TOKEN_KEY, data.access_token);
    localStorage.setItem(USER_KEY, data.username);
    return data;
  },
  logout() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    window.location.href = "login.html";
  },
  requireAuth() {
    if (!this.isAuthenticated()) {
      window.location.href = "login.html";
    }
  },
};
