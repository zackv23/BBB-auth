/* ─────────────────────────────────────────────────────────────────────────────
   BBB-auth: Dedicated Authentication & Security Layer
   Decouples authentication, OAuth flows (Google, Apple, GitHub), credential
   verification, and token lifecycle from the presentation/UI layer.
   ───────────────────────────────────────────────────────────────────────────── */

(function (window) {
  'use strict';

  var GOOGLE_CLIENT_ID = window.BBB_GOOGLE_CLIENT_ID || '371666322360-m0h8rhffcdh75hvnlaudcbnonv9nk3jf.apps.googleusercontent.com';
  var TOKEN_STORAGE_KEY = 'bbb_access_token';
  var REFRESH_STORAGE_KEY = 'bbb_refresh_token';
  var USER_STORAGE_KEY = 'bbb_user_profile';

  var _authListeners = [];

  function _notifyAuthChange(user) {
    _authListeners.forEach(function (listener) {
      try {
        listener(user);
      } catch (e) {
        console.error('[BigBBAuth] Listener error:', e);
      }
    });
  }

  function _getApiBase() {
    return (window.BigBB_API || window.BBB_API_BASE || '').replace(/\/$/, '');
  }

  function _sanitizeDestination(returnTo) {
    if (!returnTo) return 'command-center.html';
    // Reject javascript:, data:, or other malicious schemes
    if (/^(javascript|data|vbscript):/i.test(returnTo)) return 'command-center.html';
    // Allow relative paths
    if (returnTo.startsWith('/') && !returnTo.startsWith('//')) return returnTo;
    if (returnTo.endsWith('.html') && !returnTo.includes('://')) return returnTo;

    try {
      var u = new URL(returnTo, window.location.origin);
      var allowedHosts = ['bigbankbonus.com', 'www.bigbankbonus.com', 'localhost', '127.0.0.1'];
      if (allowedHosts.includes(u.hostname) || u.hostname.endsWith('.bigbankbonus.com')) {
        return u.href;
      }
    } catch (_) {
      // fallback
    }
    return 'command-center.html';
  }

  var BigBBAuth = {
    // ── Configuration ───────────────────────────────────────────────────────

    configure: function (config) {
      if (config.googleClientId) GOOGLE_CLIENT_ID = config.googleClientId;
      if (config.apiBase) window.BigBB_API = config.apiBase;
      if (config.tokenStorageKey) TOKEN_STORAGE_KEY = config.tokenStorageKey;
      if (config.refreshStorageKey) REFRESH_STORAGE_KEY = config.refreshStorageKey;
    },

    // ── Session & Token Management ──────────────────────────────────────────

    getAccessToken: function () {
      return localStorage.getItem(TOKEN_STORAGE_KEY) || null;
    },

    getRefreshToken: function () {
      return localStorage.getItem(REFRESH_STORAGE_KEY) || null;
    },

    setTokens: function (accessToken, refreshToken, userProfile) {
      if (accessToken) {
        localStorage.setItem(TOKEN_STORAGE_KEY, accessToken);
      }
      if (refreshToken) {
        localStorage.setItem(REFRESH_STORAGE_KEY, refreshToken);
      }
      if (userProfile) {
        localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(userProfile));
      }
      _notifyAuthChange(userProfile || BigBBAuth.getUser());
    },

    clearTokens: function () {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
      localStorage.removeItem(REFRESH_STORAGE_KEY);
      localStorage.removeItem(USER_STORAGE_KEY);
      _notifyAuthChange(null);
    },

    isAuthenticated: function () {
      return !!BigBBAuth.getAccessToken();
    },

    getUser: function () {
      var raw = localStorage.getItem(USER_STORAGE_KEY);
      if (raw) {
        try { return JSON.parse(raw); } catch (_) {}
      }
      var token = BigBBAuth.getAccessToken();
      if (!token) return null;
      try {
        var base64Url = token.split('.')[1];
        if (!base64Url) return null;
        var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        var jsonPayload = decodeURIComponent(
          atob(base64)
            .split('')
            .map(function (c) { return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2); })
            .join('')
        );
        return JSON.parse(jsonPayload);
      } catch (_) {
        return null;
      }
    },

    onAuthStateChange: function (listener) {
      if (typeof listener === 'function') {
        _authListeners.push(listener);
      }
      return function unsubscribe() {
        var idx = _authListeners.indexOf(listener);
        if (idx !== -1) _authListeners.splice(idx, 1);
      };
    },

    // ── One-Time OAuth Code Exchange & Safe URL Cleanup ──────────────────────

    /**
     * Inspects the current URL for ?oauth_code=, strips sensitive tokens
     * from history immediately to prevent Referer / history leakage,
     * exchanges the one-time code for JWTs, and returns a promise.
     */
    handleRedirectAuth: async function () {
      try {
        var params = new URLSearchParams(window.location.search);
        var code = params.get('oauth_code');
        var legacyToken = params.get('token') || params.get('access_token');
        var legacyRefresh = params.get('refresh_token');

        // Immediately sanitize browser address bar
        if (code || legacyToken) {
          params.delete('oauth_code');
          params.delete('token');
          params.delete('access_token');
          params.delete('refresh_token');
          var cleanQuery = params.toString() ? '?' + params.toString() : '';
          var cleanUrl = window.location.pathname + cleanQuery + window.location.hash;
          window.history.replaceState({}, document.title, cleanUrl);
        }

        if (legacyToken) {
          BigBBAuth.setTokens(legacyToken, legacyRefresh);
          return { success: true, tokens: { access_token: legacyToken } };
        }

        if (!code) {
          return { success: false, reason: 'no_code' };
        }

        var apiBase = _getApiBase();
        var fetchFn = window._rawFetch || window.fetch;
        var resp = await fetchFn(apiBase + '/api/v1/auth/oauth/exchange', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code: code }),
          credentials: 'include',
        });

        if (!resp.ok) {
          var errText = await resp.text();
          console.error('[BigBBAuth] OAuth exchange failed:', errText);
          return { success: false, error: errText };
        }

        var data = await resp.json();
        BigBBAuth.setTokens(data.access_token, data.refresh_token, data.user);

        // If on the root or index page, forward to default destination
        if (window.location.pathname.endsWith('/index.html') || window.location.pathname === '/') {
          window.location.href = 'command-center.html';
        }

        return { success: true, tokens: data };
      } catch (err) {
        console.error('[BigBBAuth] handleRedirectAuth error:', err);
        return { success: false, error: err.message };
      }
    },

    // ── Google Authentication ────────────────────────────────────────────────

    /**
     * Google Sign-In orchestration:
     * Attempts Google One Tap / GIS popup first if loaded and supported.
     * Automatically falls back to secure backend OAuth redirect.
     */
    signInWithGoogle: function (options) {
      options = options || {};
      var dest = _sanitizeDestination(options.returnTo || 'command-center.html');

      // Check if Google Identity Services is available
      if (typeof google !== 'undefined' && google.accounts && google.accounts.id && options.preferOneTap !== false) {
        try {
          google.accounts.id.initialize({
            client_id: GOOGLE_CLIENT_ID,
            callback: async function (response) {
              if (response && response.credential) {
                var res = await BigBBAuth.verifyGoogleCredential(response.credential);
                if (res.success) {
                  window.location.href = dest;
                  return;
                }
              }
              // If credential verification failed, fallback to redirect
              BigBBAuth.redirectToGoogleOAuth(dest);
            },
          });

          google.accounts.id.prompt(function (notification) {
            if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
              BigBBAuth.redirectToGoogleOAuth(dest);
            }
          });
          return;
        } catch (_) {
          // If GIS prompt throws, fall through to redirect
        }
      }

      BigBBAuth.redirectToGoogleOAuth(dest);
    },

    redirectToGoogleOAuth: function (returnTo) {
      var dest = _sanitizeDestination(returnTo);
      var apiBase = _getApiBase();
      window.location.href = apiBase + '/api/v1/auth/oauth/google?return_to=' + encodeURIComponent(dest);
    },

    verifyGoogleCredential: async function (credential) {
      try {
        var apiBase = _getApiBase();
        var fetchFn = window._apiFetch || window.fetch;
        var res = await fetchFn(apiBase + '/api/v1/auth/oauth/google/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ credential: credential }),
        });

        if (!res.ok) {
          var err = await res.json().catch(function () { return { detail: 'Verification failed' }; });
          return { success: false, error: err.detail || 'Google sign-in failed' };
        }

        var data = await res.json();
        BigBBAuth.setTokens(data.access_token, data.refresh_token, data.user);
        return { success: true, data: data };
      } catch (e) {
        return { success: false, error: e.message || 'Network error during Google verification' };
      }
    },

    // ── Apple Authentication ─────────────────────────────────────────────────

    /**
     * Apple Sign-In orchestration:
     * Redirects to the backend Apple OAuth endpoint with sanitized destination.
     * The backend coordinates state generation in Redis and CSRF protection.
     */
    signInWithApple: function (options) {
      options = options || {};
      var dest = _sanitizeDestination(options.returnTo || 'command-center.html');
      var apiBase = _getApiBase();
      window.location.href = apiBase + '/api/v1/auth/oauth/apple?return_to=' + encodeURIComponent(dest);
    },

    // ── GitHub Authentication ────────────────────────────────────────────────

    signInWithGitHub: function (options) {
      options = options || {};
      var dest = _sanitizeDestination(options.returnTo || 'command-center.html');
      var apiBase = _getApiBase();
      window.location.href = apiBase + '/api/v1/auth/oauth/github?return_to=' + encodeURIComponent(dest);
    },

    // ── Sign Out ─────────────────────────────────────────────────────────────

    signOut: function (redirectPath) {
      BigBBAuth.clearTokens();
      if (redirectPath) {
        window.location.href = redirectPath;
      }
    },
  };

  // Expose global security layer
  window.BigBBAuth = BigBBAuth;

  // Auto-listen for redirect auth codes on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      BigBBAuth.handleRedirectAuth();
    });
  } else {
    BigBBAuth.handleRedirectAuth();
  }

})(window);
