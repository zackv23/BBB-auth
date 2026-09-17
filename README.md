# BBB-auth 🛡️

Decoupled, zero-leakage authentication and social sign-in security layer for modern web applications.

`BBB-auth` separates identity protocol mechanics, CSRF defense, and token lifecycles from the user interface. Built for high-security environments like FinTech, it prevents token leakage in browser history and defends against Open Redirect attacks.

---

## ✨ Features

- **Decoupled Architecture**: UI elements never handle raw credentials, network protocols, or token parsing.
- **One-Time Code Exchange**: Authentication providers issue a single-use exchange code (`oauth_code`) with a 90-second TTL stored in Redis. Tokens never travel in browser URLs or leak into `Referer` headers or browser history.
- **Immediate URL Sanitization**: Client-side layer sanitizes `window.location` using `history.replaceState` before any network calls complete.
- **Strict Open Redirect Defense**: All `return_to` destination parameters are rigorously validated (`_safe_redirect_url`) to prevent code leakage to attacker domains.
- **Redis CSRF State Protection**: Apple and Google OAuth flows generate cryptographically random states stored in Redis and validated on callback before processing credentials.
- **Multi-Provider Support**:
  - Google Sign-In (OpenID Connect redirect + One Tap / GSI popup verification)
  - Apple Sign-In (secure `form_post` callback with ES256 client secrets and JWKS validation)
  - GitHub OAuth

---

## 📁 Repository Structure

```
BBB-auth/
├── client/
│   └── auth-service.js     # Browser Auth Security Layer (window.BigBBAuth)
├── server/
│   ├── oauth.py            # FastAPI OAuth router with Redis state & Open Redirect defense
│   └── requirements.txt    # Python dependencies
├── examples/
│   └── index.html          # Reference decoupled UI implementation
├── tests/
│   └── test_oauth_security.py # Security test suite
├── LICENSE
└── README.md
```

---

## 🚀 Quickstart

### 1. Client-Side (Browser)

Include `client/auth-service.js` in your HTML `<head>`:

```html
<script src="https://accounts.google.com/gsi/client" async defer></script>
<script src="js/auth-service.js"></script>
```

Trigger sign-ins from your UI buttons without embedding auth logic:

```javascript
// Google Sign-In (tries One Tap / GSI popup, falls back to redirect)
BigBBAuth.signInWithGoogle({ returnTo: '/dashboard.html' });

// Apple Sign-In
BigBBAuth.signInWithApple({ returnTo: '/dashboard.html' });

// GitHub Sign-In
BigBBAuth.signInWithGitHub({ returnTo: '/dashboard.html' });

// Listen to auth state changes across components
BigBBAuth.onAuthStateChange((user) => {
  console.log('Current user:', user);
});
```

### 2. Server-Side (Standalone FastAPI OAuth Layer)

Run BBB-auth as a standalone public OAuth service:

```bash
cd server
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```

Required runtime environment variables:

- `JWT_SECRET` (required outside development/local/test)
- `ALLOWED_ORIGINS` (comma-separated UI origins)
- Provider credentials as needed (`GOOGLE_*`, `APPLE_*`, `GITHUB_*`)

Optional token configuration:

- `REDIS_URL` (default `redis://localhost:6379/0`)
- Dev/local/test fallback JWT secret defaults to fixed value `dev-only-insecure-jwt-secret` when `JWT_SECRET` is unset
- `JWT_ISSUER` (defaults to `BACKEND_URL`)
- `JWT_AUDIENCE` (defaults to `bbb-api`)
- `ACCESS_TOKEN_MINUTES` (default `15`)
- `REFRESH_TOKEN_DAYS` (default `30`)

Health endpoints:

- `GET /health/live`
- `GET /health/ready`

Alternative integration (mount into an existing FastAPI app):

```python
from fastapi import FastAPI
from server.oauth import create_oauth_router, OAuthSettings

app = FastAPI()

settings = OAuthSettings(
    google_client_id="YOUR_GOOGLE_CLIENT_ID",
    google_client_secret="YOUR_GOOGLE_CLIENT_SECRET",
    apple_client_id="YOUR_APPLE_CLIENT_ID",
    apple_team_id="YOUR_APPLE_TEAM_ID",
    apple_key_id="YOUR_APPLE_KEY_ID",
    apple_private_key="YOUR_ES256_PRIVATE_KEY",
)

oauth_router = create_oauth_router(
    settings=settings,
    get_redis=get_redis_dependency,
    token_issuer=issue_jwt_tokens,
    user_upsert=upsert_user_in_db,
)

app.include_router(oauth_router)
```

---

## 🔒 Security Architecture

1. **Open Redirect Defense**:
   Attacker URLs like `https://evil.com/steal` supplied in `return_to` or OAuth `state` are automatically rejected and clamped to trusted origin domains.
2. **CSRF Mitigation**:
   OAuth callbacks reject unverified state tokens, preventing state injection or CSRF attacks.
3. **Token Privacy**:
   Access and refresh tokens are stored securely in local storage and never exposed in browser navigation history or referrer logs.

---

## 📄 License

MIT © Zachary Valos / Big Bank Bonus
