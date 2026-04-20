package com.oauthhelper.oauth;

public class OAuthProfile {

    public enum GrantType { CLIENT_CREDENTIALS, RESOURCE_OWNER_PASSWORD }

    public enum ClientAuthMethod {
        HTTP_BASIC, POST_BODY, PRIVATE_KEY_JWT, CLIENT_SECRET_JWT
    }

    public enum RefreshMode { MANUAL, AUTO_SILENT }

    public enum JwtAlgorithm {
        RS256, RS384, RS512, ES256, ES384, HS256, HS384, HS512
    }

    private String name                       = "New Profile";
    private GrantType grantType               = GrantType.CLIENT_CREDENTIALS;
    private ClientAuthMethod clientAuthMethod = ClientAuthMethod.HTTP_BASIC;
    private String tokenUrl                   = "";
    private String authorizationUrl           = "";
    private String clientId                   = "";
    private String clientSecret               = "";
    private String privateKeyPem              = "";
    private JwtAlgorithm jwtAlgorithm         = JwtAlgorithm.RS256;
    private String jwtAudience                = "";
    private int    jwtLifetimeSeconds         = 300;
    private String scopes                     = "";
    private String ropcUsername               = "";
    private String ropcPassword               = "";
    private boolean injectProxy               = true;
    private boolean injectRepeater            = true;
    private boolean injectIntruder            = true;
    private boolean injectScanner             = true;
    private boolean injectSequencer           = true;
    private boolean injectTarget              = true;
    private boolean injectionEnabled          = true;
    private String  httpVersion               = "HTTP/1.1";
    private String  headerName                = "Authorization";
    private String  tokenPrefix               = "Bearer";
    private boolean addIfMissing              = true;
    private boolean replaceIfPresent          = true;
    private boolean scanEnabled               = false;
    private String  scanCodes                 = "";
    private String  sessionPhrase             = "";
    private boolean regenEnabled              = true;
    private int     regenThreshold            = 3;
    private RefreshMode refreshMode           = RefreshMode.AUTO_SILENT;
    private int         refreshBufferSeconds  = 300;

    public OAuthProfile(String name) { this.name = name; }

    public String getName()                              { return name; }
    public void   setName(String v)                      { this.name = v; }
    public GrantType getGrantType()                      { return grantType; }
    public void      setGrantType(GrantType v)           { this.grantType = v; }
    public ClientAuthMethod getClientAuthMethod()        { return clientAuthMethod; }
    public void             setClientAuthMethod(ClientAuthMethod v) { this.clientAuthMethod = v; }
    public String getTokenUrl()                          { return tokenUrl; }
    public void   setTokenUrl(String v)                  { this.tokenUrl = v; }
    public String getAuthorizationUrl()                  { return authorizationUrl; }
    public void   setAuthorizationUrl(String v)          { this.authorizationUrl = v; }
    public String getClientId()                          { return clientId; }
    public void   setClientId(String v)                  { this.clientId = v; }
    public String getClientSecret()                      { return clientSecret; }
    public void   setClientSecret(String v)              { this.clientSecret = v; }
    public String getPrivateKeyPem()                     { return privateKeyPem; }
    public void   setPrivateKeyPem(String v)             { this.privateKeyPem = v; }
    public JwtAlgorithm getJwtAlgorithm()                { return jwtAlgorithm != null ? jwtAlgorithm : JwtAlgorithm.RS256; }
    public void         setJwtAlgorithm(JwtAlgorithm v)  { this.jwtAlgorithm = v; }
    public String getJwtAudience()                       { return jwtAudience; }
    public void   setJwtAudience(String v)               { this.jwtAudience = v; }
    public int    getJwtLifetimeSeconds()                { return jwtLifetimeSeconds; }
    public void   setJwtLifetimeSeconds(int v)           { this.jwtLifetimeSeconds = v; }
    public String getScopes()                            { return scopes; }
    public void   setScopes(String v)                    { this.scopes = v; }
    public String getRopcUsername()                      { return ropcUsername; }
    public void   setRopcUsername(String v)              { this.ropcUsername = v; }
    public String getRopcPassword()                      { return ropcPassword; }
    public void   setRopcPassword(String v)              { this.ropcPassword = v; }
    public boolean isInjectProxy()                       { return injectProxy; }
    public void    setInjectProxy(boolean v)             { this.injectProxy = v; }
    public boolean isInjectRepeater()                    { return injectRepeater; }
    public void    setInjectRepeater(boolean v)          { this.injectRepeater = v; }
    public boolean isInjectIntruder()                    { return injectIntruder; }
    public void    setInjectIntruder(boolean v)          { this.injectIntruder = v; }
    public boolean isInjectScanner()                     { return injectScanner; }
    public void    setInjectScanner(boolean v)           { this.injectScanner = v; }
    public boolean isInjectSequencer()                   { return injectSequencer; }
    public void    setInjectSequencer(boolean v)         { this.injectSequencer = v; }
    public boolean isInjectTarget()                      { return injectTarget; }
    public void    setInjectTarget(boolean v)            { this.injectTarget = v; }
    public boolean isInjectionEnabled()                  { return injectionEnabled; }
    public void    setInjectionEnabled(boolean v)        { this.injectionEnabled = v; }
    public String  getHttpVersion()                      { return httpVersion; }
    public void    setHttpVersion(String v)              { this.httpVersion = v; }

    public boolean isAnyInjectionEnabled() {
        return injectionEnabled && (injectProxy || injectRepeater || injectIntruder
                || injectScanner || injectSequencer || injectTarget);
    }

    public String  getHeaderName()                       { return headerName; }
    public void    setHeaderName(String v)               { this.headerName = v; }
    public String  getTokenPrefix()                      { return tokenPrefix; }
    public void    setTokenPrefix(String v)              { this.tokenPrefix = v; }
    public boolean isAddIfMissing()                      { return addIfMissing; }
    public void    setAddIfMissing(boolean v)            { this.addIfMissing = v; }
    public boolean isReplaceIfPresent()                  { return replaceIfPresent; }
    public void    setReplaceIfPresent(boolean v)        { this.replaceIfPresent = v; }
    public RefreshMode getRefreshMode()                  { return refreshMode; }
    public void        setRefreshMode(RefreshMode v)     { this.refreshMode = v; }
    public int  getRefreshBufferSeconds()                { return refreshBufferSeconds; }
    public void setRefreshBufferSeconds(int v)           { this.refreshBufferSeconds = v; }
    public boolean isScanEnabled()                       { return scanEnabled; }
    public void    setScanEnabled(boolean v)             { this.scanEnabled = v; }
    public String  getScanCodes()                        { return scanCodes; }
    public void    setScanCodes(String v)                { this.scanCodes = v; }
    public String  getSessionPhrase()                    { return sessionPhrase; }
    public void    setSessionPhrase(String v)            { this.sessionPhrase = v; }

    public java.util.Set<Integer> parsedScanCodes() {
        java.util.Set<Integer> codes = new java.util.HashSet<>();
        if (scanCodes == null || scanCodes.isBlank()) return codes;
        for (String part : scanCodes.split(",")) {
            try { codes.add(Integer.parseInt(part.trim())); }
            catch (NumberFormatException ignored) {}
        }
        return codes;
    }

    public boolean isRegenEnabled()                      { return regenEnabled; }
    public void    setRegenEnabled(boolean v)            { this.regenEnabled = v; }
    public int     getRegenThreshold()                   { return regenThreshold; }
    public void    setRegenThreshold(int v)              { this.regenThreshold = v; }

    @Override public String toString() { return name; }
}
