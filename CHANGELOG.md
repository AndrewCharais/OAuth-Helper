# Changelog

All notable changes to OAuth Helper will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2025

### Added
- Client Credentials grant type with three authentication methods: HTTP Basic, POST Body, and Private Key JWT
- Per-profile token injection into Proxy, Repeater, Intruder, and Scanner
- Configurable injection header name and token prefix
- Automatic token refresh on expiry (Auto-Refresh mode) with silent refresh token support
- Session monitoring — detects token rejection via configurable HTTP status codes and/or response body text
- Auto re-fetch on consecutive rejection threshold
- Start / Stop / Resume auto-refresh per profile
- Profile persistence to Burp project file (Burp Professional)
- Import profiles from JSON
- Export profiles to JSON
- Multiple profiles with independent settings
- Live TTL countdown with colour-coded expiry warnings
- Refresh token status indicator
- Friendly error messages mapped from common OAuth error responses
- Full Burp Logger visibility for all token requests (uses `api.http().sendRequest()`)
- BApp Store compliant: unload handler, background thread safety, suite frame parenting, Montoya API networking

### Notes
- Authorization Code + PKCE flow is implemented but disabled in this release pending further testing
