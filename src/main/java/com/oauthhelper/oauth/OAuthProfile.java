package com.oauthhelper.oauth;

public class OAuthProfile {

    public enum GrantType {
        CLIENT_CREDENTIALS
        // AUTH_CODE_PKCE — not yet supported in this release
    }

    public enum ClientAuthMethod {
        HTTP_BASIC,
        POST_BODY,
        PRIVATE_KEY_JWT
    }

    public enum RefreshMode {
        MANUAL,
        AUTO_SILENT
    }

    private String name = "New Profile";
    private GrantType grantType = GrantType.CLIENT_CREDENTIALS;
    private ClientAuthMethod clientAuthMethod = ClientAuthMethod.HTTP_BASIC;
    private String tokenUrl = "";
    private String authorizationUrl = "";
    private String clientId = "";
    private String clientSecret = "";
    private String privateKeyPem = "";
    private String jwtAlgorithm = "RS256";
    private String scopes = "";

    // Per-tool injection toggles — all on by default
    private boolean injectProxy    = true;
    private boolean injectRepeater = true;
    private boolean injectIntruder = true;
    private boolean injectScanner  = true;

    // Injection header settings
    private String  headerName       = "Authorization";
    private String  tokenPrefix      = "Bearer";
    private boolean addIfMissing     = true;
    private boolean replaceIfPresent = true;

    // Token header scanning / auto-regen
    private boolean scanEnabled     = true;  // watch in-scope responses for session termination
    private String  scanCodes       = "401, 403"; // comma-separated HTTP status codes to watch
    private String  sessionPhrase   = "";     // optional body phrase indicating session terminated
    private boolean regenEnabled    = true;  // auto re-fetch when threshold hit
    private int     regenThreshold  = 3;     // consecutive hits before regen

    // Refresh
    private RefreshMode refreshMode        = RefreshMode.MANUAL;
    private int         refreshBufferSeconds = 300;

    public OAuthProfile(String name) { this.name = name; }

    // ── Getters / setters ─────────────────────────────────────────────────────

    public String getName()                        { return name; }
    public void   setName(String v)                { this.name = v; }
    public GrantType getGrantType()                { return grantType; }
    public void      setGrantType(GrantType v)     { this.grantType = v; }
    public ClientAuthMethod getClientAuthMethod()          { return clientAuthMethod; }
    public void             setClientAuthMethod(ClientAuthMethod v) { this.clientAuthMethod = v; }
    public String getTokenUrl()                    { return tokenUrl; }
    public void   setTokenUrl(String v)            { this.tokenUrl = v; }
    public String getAuthorizationUrl()            { return authorizationUrl; }
    public void   setAuthorizationUrl(String v)    { this.authorizationUrl = v; }
    public String getClientId()                    { return clientId; }
    public void   setClientId(String v)            { this.clientId = v; }
    public String getClientSecret()                { return clientSecret; }
    public void   setClientSecret(String v)        { this.clientSecret = v; }
    public String getPrivateKeyPem()               { return privateKeyPem; }
    public void   setPrivateKeyPem(String v)       { this.privateKeyPem = v; }
    public String getJwtAlgorithm()                { return jwtAlgorithm; }
    public void   setJwtAlgorithm(String v)        { this.jwtAlgorithm = v; }
    public String getScopes()                      { return scopes; }
    public void   setScopes(String v)              { this.scopes = v; }

    public boolean isInjectProxy()                 { return injectProxy; }
    public void    setInjectProxy(boolean v)       { this.injectProxy = v; }
    public boolean isInjectRepeater()              { return injectRepeater; }
    public void    setInjectRepeater(boolean v)    { this.injectRepeater = v; }
    public boolean isInjectIntruder()              { return injectIntruder; }
    public void    setInjectIntruder(boolean v)    { this.injectIntruder = v; }
    public boolean isInjectScanner()               { return injectScanner; }
    public void    setInjectScanner(boolean v)     { this.injectScanner = v; }

    /** True if injection is enabled for at least one tool. */
    public boolean isAnyInjectionEnabled() {
        return injectProxy || injectRepeater || injectIntruder || injectScanner;
    }

    public String  getHeaderName()                 { return headerName; }
    public void    setHeaderName(String v)         { this.headerName = v; }
    public String  getTokenPrefix()                { return tokenPrefix; }
    public void    setTokenPrefix(String v)        { this.tokenPrefix = v; }
    public boolean isAddIfMissing()                { return addIfMissing; }
    public void    setAddIfMissing(boolean v)      { this.addIfMissing = v; }
    public boolean isReplaceIfPresent()            { return replaceIfPresent; }
    public void    setReplaceIfPresent(boolean v)  { this.replaceIfPresent = v; }

    public RefreshMode getRefreshMode()            { return refreshMode; }
    public void        setRefreshMode(RefreshMode v) { this.refreshMode = v; }
    public int  getRefreshBufferSeconds()          { return refreshBufferSeconds; }
    public void setRefreshBufferSeconds(int v)     { this.refreshBufferSeconds = v; }

    public boolean isScanEnabled()               { return scanEnabled; }
    public void    setScanEnabled(boolean v)       { this.scanEnabled = v; }
    public String  getScanCodes()                { return scanCodes; }
    public void    setScanCodes(String v)          { this.scanCodes = v; }
    public String  getSessionPhrase()            { return sessionPhrase; }
    public void    setSessionPhrase(String v)      { this.sessionPhrase = v; }

    /** Parse scanCodes into a set of integers, ignoring invalid entries. */
    public java.util.Set<Integer> parsedScanCodes() {
        java.util.Set<Integer> codes = new java.util.HashSet<>();
        if (scanCodes == null || scanCodes.isBlank()) { codes.add(401); codes.add(403); return codes; }
        for (String part : scanCodes.split(",")) {
            try { codes.add(Integer.parseInt(part.trim())); }
            catch (NumberFormatException ignored) {}
        }
        return codes;
    }
    public boolean isRegenEnabled()              { return regenEnabled; }
    public void    setRegenEnabled(boolean v)      { this.regenEnabled = v; }
    public int     getRegenThreshold()             { return regenThreshold; }
    public void    setRegenThreshold(int v)        { this.regenThreshold = v; }

    @Override
    public String toString() { return name; }
}
