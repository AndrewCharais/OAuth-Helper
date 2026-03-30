# OAuth Helper for Burp Suite

A Burp Suite extension that automates OAuth 2.0 token generation and injects tokens into in-scope HTTP traffic across all Burp tools.

## Author

Andrew Charais  
Built with the help of AI-assisted development tools.

---

## Features

- **Automatic token injection** into Proxy, Repeater, Intruder, and Scanner traffic
- **Multiple profiles** — configure different OAuth clients side by side, one per engagement or endpoint
- **Client Credentials** grant type with HTTP Basic, POST Body, and Private Key JWT authentication methods
- **Token refresh** — manual or fully automatic (silent re-fetch on expiry)
- **Refresh token support** — uses `refresh_token` grant silently when available; falls back to full re-fetch
- **Session monitoring** — watches in-scope responses for configurable status codes (e.g. 401, 403) or response body text that indicates a revoked token
- **Auto re-fetch on failure** — automatically gets a new token after a configurable number of consecutive rejections
- **Profile persistence** — profiles are saved to the Burp project file and restored on next open (Burp Professional)
- **Import / Export** — share profiles as JSON files between team members or engagements
- **Start / Stop auto-refresh** — toggle the background refresh scheduler per profile without losing the token

> **Note:** Authorization Code + PKCE flow is planned for a future release. The current release supports Client Credentials only.

---

## Requirements

| Requirement | Version |
|---|---|
| Burp Suite | Professional 2024.1+ or Community 2024.1+ |
| Java | 21+ |
| Gradle | 8.7+ (for building from source) |

Profile persistence requires Burp Suite Professional. On Community Edition, profiles are held in memory for the session but are not saved to disk.

---

## Installation

### Option A — Pre-built JAR (recommended)

1. Download `oauth-helper-1.0.0.jar` from the [Releases](../../releases) page.
2. In Burp Suite, go to **Extensions → Installed → Add**.
3. Set **Extension type** to **Java**.
4. Select the downloaded JAR and click **Next**.
5. The **OAuth Helper** tab will appear in the Burp Suite toolbar.

### Option B — Build from source

```bash
git clone https://github.com/AndrewCharais/oauth-helper-burp.git
cd oauth-helper-burp
./gradlew jar
```

The compiled JAR will be at `build/libs/oauth-helper-1.0.0.jar`. Follow the steps above to load it.

---

## Quick Start

1. Open the **OAuth Helper** tab in Burp Suite.
2. Click **New** to create a profile.
3. Fill in **Profile Setup** and **Endpoints** — at minimum:
   - Profile Name
   - Grant Type (Client Credentials)
   - Token URL
4. Fill in **Client Authentication** — Client ID and Client Secret (or Private Key for JWT).
5. Click **Save Settings**.
6. Add your target to Burp's scope (**Target → Scope**).
7. Expand **Apply Token to Selected Tools** and enable the tools you want to inject into.
8. Click **Get Token**.
9. Browse your target — the `Authorization: Bearer <token>` header will be injected automatically.

---

## Configuration Reference

### Profile Setup

| Field | Description |
|---|---|
| Profile Name | A label for this profile — shown in the profiles list |
| Grant Type | OAuth grant type. Currently: **Client Credentials** |

### Endpoints

| Field | Description |
|---|---|
| Token URL | The authorization server's token endpoint (e.g. `https://auth.example.com/token`) |

### Client Authentication

| Field | Description |
|---|---|
| Client ID | The client identifier issued by the authorization server |
| Authentication Method | **HTTP Basic** — credentials in the Authorization header. **POST Body** — credentials as form fields. **Private Key JWT** — signed JWT assertion |
| Client Secret | Secret credential (not required for Private Key JWT) |
| Private Key (PEM) | PKCS#8 private key in PEM format (Private Key JWT only) |
| Scopes | Space-separated OAuth scopes (e.g. `openid profile email`). Leave blank for server defaults |

### Apply Token to Selected Tools (collapsible)

| Field | Description |
|---|---|
| Proxy / Repeater / Intruder / Scanner | Which Burp tools receive the injected token |
| Header Name | HTTP header to write the token into (default: `Authorization`) |
| Token Prefix | Text prepended before the token value (default: `Bearer`) |

### Session Monitoring (collapsible)

| Field | Description |
|---|---|
| Monitor responses... | Enable session termination detection |
| Failure Status Codes | Comma-separated HTTP status codes that indicate a rejected token (default: `401, 403`) |
| Failure Response Text | Optional text to match in response bodies (e.g. `session expired`) |
| Automatically fetch a new token | Re-fetch automatically when the failure threshold is reached |
| Failures Before Refresh | Number of consecutive rejections before triggering a re-fetch (default: 3) |

### Advanced Settings (collapsible)

| Field | Description |
|---|---|
| Token Refresh Mode | **Manual** — click Get Token yourself. **Auto-Refresh** — silently re-fetches when the token expires |

---

## Profile Import / Export

Profiles can be saved as JSON files and shared between users or engagements.

**Export:** Select a profile → click **Export** → choose a save location. The current form state is saved automatically before export.

**Import:** Click **Import** → select a `.json` file. A new profile is created without overwriting any existing profiles.

### JSON format

```json
{
  "name": "My API",
  "grantType": "CLIENT_CREDENTIALS",
  "clientAuthMethod": "HTTP_BASIC",
  "tokenUrl": "https://auth.example.com/token",
  "clientId": "my-client-id",
  "clientSecret": "my-secret",
  "scopes": "openid profile",
  "headerName": "Authorization",
  "tokenPrefix": "Bearer",
  "injectProxy": true,
  "injectRepeater": true,
  "injectIntruder": true,
  "injectScanner": false,
  "refreshMode": "AUTO_SILENT",
  "scanEnabled": true,
  "scanCodes": "401, 403",
  "sessionPhrase": "",
  "regenEnabled": true,
  "regenThreshold": 3
}
```

> **Note:** `clientSecret` and `privateKeyPem` are included in exports. Treat exported files as sensitive credentials.

---

## Roadmap

- [ ] Authorization Code + PKCE flow
- [ ] OAuth security testing checks (state parameter validation, redirect_uri manipulation, token audience bypass, etc.)

---

## Building

```bash
# Build
./gradlew jar

# Output
build/libs/oauth-helper-1.0.0.jar
```

The extension has no runtime dependencies beyond the Burp Montoya API, which is declared `compileOnly` and not bundled into the JAR.

---

## Contributing

Pull requests are welcome. Please open an issue first to discuss significant changes.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'Add my feature'`
4. Push: `git push origin feature/my-feature`
5. Open a Pull Request

---

## License

MIT License — see [LICENSE](LICENSE).

---

## Disclaimer

This tool is intended for authorised security testing only. Only use it against systems you own or have explicit written permission to test. The authors accept no liability for misuse.
