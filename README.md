# OAuth Helper for Burp Suite

A Burp Suite extension that fetches OAuth 2.0 access tokens using stored credentials and automatically adds or replaces the token in outgoing requests as it expires.

Built with the [Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/).

---

## What it does

1. Fetches an access token from an authorization server using configured credentials
2. Adds or updates the `Authorization` header in outgoing requests for your configured Burp tools
3. Re-fetches a new token automatically when the current one expires (if Auto-Refresh is enabled)
4. Optionally monitors in-scope responses for signs that the token has been rejected and re-fetches when needed — this is disabled by default and configured in Advanced Settings

---

## Requirements

- Burp Suite Professional or Community 2024.1+
- Java 21+

---

## Installation

1. Download `oauth-helper-*.jar` from the [Releases](../../releases) page
2. In Burp Suite: **Extensions → Installed → Add → Java** → select the JAR
3. The **OAuth Helper** tab will appear in the toolbar

---

## Quick Start

1. Click **+ New Profile** and give it a name
2. Enter your **Token URL** and **Client ID**
3. Choose an **Authentication Method** and fill in the credentials
4. Click **Save Settings**
5. Add your target to Burp's scope (**Target → Scope**)
6. Open **Advanced Settings** and select which Burp tools should have their `Authorization` header maintained
7. Click **Get Token**

---

## Authentication Methods

| Method | Description |
|---|---|
| HTTP Basic | Client ID and secret in the `Authorization` header |
| POST Body | Client ID and secret as form fields in the request body |
| Private Key JWT | Signed JWT assertion using a PKCS#8 RSA or EC private key |
| Client Secret JWT | Signed JWT assertion using the client secret as an HMAC key |

All methods use the Client Credentials grant (RFC 6749 §4.4).

### Private Key JWT — key setup

```bash
# Generate private key and certificate
openssl genrsa -out private.pem 2048
openssl req -new -x509 -key private.pem -out cert.pem -days 365 -subj "/CN=my-client"

# Convert to PKCS#8 format (required by the extension)
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private.pem -out private_pkcs8.pem
```

Register `cert.pem` with your IdP and paste `private_pkcs8.pem` into the **Private Key (PEM)** field.

The **Audience** field defaults to the Token URL. Some IdPs (e.g. Keycloak) expect the realm issuer URL instead — check your IdP's `/.well-known/openid-configuration` for the correct `issuer` value.

---

## Advanced Settings

**Tool selection** — which Burp tools (Proxy, Repeater, Intruder, Scanner) have their token kept up to date.

**Header Name** — the HTTP request header the token is written into. Defaults to `Authorization`.

**Token Prefix** — text prepended before the token value in the header. Defaults to `Bearer`, producing `Authorization: Bearer <token>`. Leave blank to write the raw token value.

**Token Refresh Mode** — Auto-Refresh re-fetches a new token automatically when the current one expires. Manual requires clicking Get Token yourself. Defaults to Auto-Refresh.

**Session Monitoring** — disabled by default. When configured, watches in-scope responses for signs that the current token is no longer valid. Set the HTTP status codes that indicate rejection (e.g. `401, 403`), optionally a response body string to match, and how many consecutive failures trigger a re-fetch.

---

## Profile Import / Export

**Export:** Select a profile → **Export** → saves as `.json`

**Import:** Click **Import** → select a `.json` file — always creates a new profile, never overwrites

> Exported files contain credentials including client secrets and private keys.

---

## Roadmap

- [ ] Authorization Code + PKCE flow
- [ ] OAuth security testing checks (redirect_uri manipulation, token audience bypass, scope escalation)

---

## License

MIT — see [LICENSE](LICENSE).

---

## Disclaimer

Only use against systems you are authorised to test, whether through ownership, a bug bounty programme, or explicit client permission.

---

Built with AI assistance (Claude by Anthropic) — **Author:** Andrew Charis
