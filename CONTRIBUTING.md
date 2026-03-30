# Contributing to OAuth Helper

Thank you for considering a contribution. This document covers how to get set up, the code structure, and what to keep in mind before submitting.

---

## Getting started

```bash
git clone https://github.com/AndrewCharais/oauth-helper-burp.git
cd oauth-helper-burp
./gradlew jar
```

Load `build/libs/oauth-helper-1.0.0.jar` into Burp Suite via **Extensions → Installed → Add**.

### Requirements

- Java 21+
- Gradle 8.7+ (the wrapper `./gradlew` handles this automatically)
- Burp Suite Professional or Community 2024.1+

---

## Code structure

```
src/main/java/
├── Extension.java                      Entry point — wires all components
└── com/oauthhelper/
    ├── http/
    │   └── TrafficHandler.java         ProxyRequestHandler + HttpHandler
    │                                   Token injection and session monitoring
    ├── oauth/
    │   ├── OAuthClient.java            Token requests via Burp HTTP stack
    │   ├── OAuthProfile.java           Data model — all profile settings
    │   └── PkceFlowHandler.java        Auth Code + PKCE (disabled, in progress)
    ├── persistence/
    │   └── ProfileStore.java           Burp PersistedObject read/write
    ├── token/
    │   ├── TokenEntry.java             Immutable token snapshot
    │   └── TokenManager.java           Token storage + auto-refresh scheduler
    └── ui/
        └── ConfigPanel.java            Full extension UI
```

---

## Conventions

**Burp API usage**
- All HTTP requests use `api.http().sendRequest()` — never `java.net.URL` or `HttpURLConnection`
- All dialogs use `api.userInterface().swingUtils().suiteFrame()` as parent
- All Swing updates happen on the EDT via `SwingUtilities.invokeLater()`
- Background threads wrap their entire body in `try/catch(Throwable)` and write stack traces to `api.logging().logToError()`

**Thread safety**
- Shared collections use `ConcurrentHashMap` or `CopyOnWriteArrayList`
- The `fetchInProgress` flag is `volatile`
- Counter operations use `AtomicInteger`

**No external dependencies**
- The extension uses zero runtime dependencies beyond the JDK and Montoya API
- The Montoya API is declared `compileOnly` and must not be bundled in the JAR

**Fonts**
- No hardcoded fonts — use `UIManager.getFont("Label.font")` and derive from it so the UI matches Burp's current look and feel

---

## Submitting a pull request

1. Open an issue first if you're planning a significant change — helps avoid duplicate effort
2. Keep PRs focused — one feature or fix per PR
3. Test against both Burp Professional and Community if possible
4. Make sure the JAR builds cleanly: `./gradlew jar`
5. Update `CHANGELOG.md` under `[Unreleased]`

---

## Reporting bugs

Please include:
- Burp Suite version and edition (Professional / Community)
- Java version (`java -version`)
- Steps to reproduce
- What you expected vs what happened
- Any relevant output from **Extensions → OAuth Helper → Output** or **Errors** tabs
