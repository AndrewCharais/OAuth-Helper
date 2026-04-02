# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] — 2026

### Added
- Client Secret JWT authentication (HMAC signing with HS256/HS384/HS512)
- Private Key JWT now supports EC keys (ES256/ES384) in addition to RSA
- Configurable signing algorithm dropdown (RS256/RS384/RS512/ES256/ES384/HS256/HS384/HS512)
- Configurable JWT audience field — override the default token URL for IdPs that expect the realm issuer URL
- Configurable assertion lifetime (default 300s, minimum 60s)
- Clock skew compensation in JWT assertions to prevent "token issued in the future" rejections

### Changed
- Refresh token support removed — Client Credentials cannot issue refresh tokens per RFC 6749 §4.4; the extension now always re-fetches using stored credentials
- HTTP Basic auth no longer sends `client_id` in the request body (RFC 6749 §2.3.1 compliance)
- JWT audience sent as a JSON array for broader IdP compatibility
- Token Injection and Session Monitoring settings moved inside Advanced Settings
- Auto-Refresh is now the default refresh mode for new profiles
- Private Key field replaced with a scrollable text area — handles multi-line PEM keys correctly
- All text fields capped to a fixed height to prevent layout expansion

### Fixed
- Scope parameter was not being sent in token requests
- Export JSON was corrupted due to quote escaping issues in the serialisation code

---

## [1.0.0] — 2025

### Added
- Client Credentials grant type with HTTP Basic, POST Body, and Private Key JWT (RS256)
- Token injection into Proxy, Repeater, Intruder, and Scanner
- Auto-refresh on token expiry
- Session monitoring with configurable status codes and response body text
- Multiple profiles with independent settings
- Profile persistence to Burp project file (Professional)
- Import / Export profiles as JSON
- Live TTL countdown with expiry warnings
- Full Burp Logger visibility for all token requests
