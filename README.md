# OAuth Helper for Burp Suite

A Burp Suite extension that automates OAuth 2.0 token generation and injects tokens into HTTP traffic across Proxy, Repeater, Intruder, and Scanner.

Built with the [Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/).

---

## Features

- **Client Credentials** grant with HTTP Basic, POST Body, Private Key JWT, and Client Secret JWT
- **Automatic token injection** into configured Burp tools
- **Auto-refresh** — silently re-fetches tokens on expiry using stored credentials
- **Session monitoring** — detects rejected tokens by status code or response body text and re-fetches
- **Multiple profiles** — manage different OAuth clients side by side
- **Import / Export** — share profiles as JSON between engagements or team members
- **Profile persistence** — saved to the Burp project file (Professional) or held in memory (Community)

> Authorization Code + PKCE is planned for a future release.

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
6. Open **Advanced Settings** and enable the Burp tools to inject into
7. Click **Get Token**

The extension injects the token automatically into all in-scope traffic for the enabled tools.

---

## Authentication Methods

| Method | Description |
|---|---|
| HTTP Basic | Client ID and secret in the `Authorization` header |
| POST Body | Client ID and secret as form fields in the request body |
| Private Key JWT | Signed JWT assertion using a PKCS#8 RSA or EC private key |
| Client Secret JWT | Signed JWT assertion using the client secret as an HMAC key |

### Private Key JWT setup

```bash
# Generate private key and certificate
openssl genrsa -out private.pem 2048
openssl req -new -x509 -key private.pem -out cert.pem -days 365 -subj "/CN=my-client"

# Convert to PKCS#8 (required by the extension)
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private.pem -out private_pkcs8.pem
```

Register `cert.pem` with your IdP and paste `private_pkcs8.pem` into the **Private Key (PEM)** field.

The **JWT Audience** field defaults to the Token URL. Some IdPs (e.g. Keycloak) expect the realm issuer URL — check your IdP's `/.well-known/openid-configuration` for the `issuer` value.

---

## Advanced Settings

The collapsible **Advanced Settings** section contains:

- **Tool selection** — which Burp tools receive the injected token, plus header name and prefix
- **Token Refresh Mode** — Auto-Refresh (default) re-fetches on expiry; Manual requires clicking Get Token
- **Session Monitoring** — detects rejected tokens by status code (e.g. `401, 403`) or response body text, and re-fetches after a configurable number of consecutive failures

---

## Profile Import / Export

**Export:** Select a profile → **Export** → save as `.json`

**Import:** Click **Import** → select a `.json` file — always creates a new profile, never overwrites

> Exported files contain credentials. Treat them as sensitive.

---

## Roadmap

- [ ] Authorization Code + PKCE
- [ ] OAuth security testing checks (redirect_uri manipulation, token audience bypass, etc.)

---

## License

MIT — see [LICENSE](LICENSE).

---

## Disclaimer

For authorised security testing only. Only use against systems you own or have explicit written permission to test.

---

Built with AI assistance (Claude by Anthropic) — **Author:** Andrew Charis
