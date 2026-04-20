package com.oauthhelper.token;

import java.time.Instant;

public class TokenEntry {

    private final String profileName;
    private final String accessToken;
    private final String tokenType;
    private final String refreshToken;
    private final Instant fetchedAt;
    private final Instant expiresAt;
    private final String decodedPayload;
    private final String rawResponse;

    public TokenEntry(String profileName, String accessToken, String tokenType,
                      String refreshToken, Instant fetchedAt, Instant expiresAt,
                      String decodedPayload, String rawResponse) {
        this.profileName   = profileName;
        this.accessToken   = accessToken;
        this.tokenType     = tokenType;
        this.refreshToken  = refreshToken;
        this.fetchedAt     = fetchedAt;
        this.expiresAt     = expiresAt;
        this.decodedPayload = decodedPayload;
        this.rawResponse   = rawResponse;
    }

    public boolean isExpired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }

    public boolean isExpiringSoon(int bufferSeconds) {
        if (expiresAt == null) return false;
        return Instant.now().isAfter(expiresAt.minusSeconds(bufferSeconds));
    }

    public long secondsRemaining() {
        if (expiresAt == null) return -1;
        return Math.max(0, expiresAt.getEpochSecond() - Instant.now().getEpochSecond());
    }

    public String getProfileName()    { return profileName; }
    public String getAccessToken()    { return accessToken; }
    public String getTokenType()      { return tokenType; }
    public String getRefreshToken()   { return refreshToken; }
    public Instant getFetchedAt()     { return fetchedAt; }
    public Instant getExpiresAt()     { return expiresAt; }
    public String getDecodedPayload() { return decodedPayload; }
    public String getRawResponse()    { return rawResponse; }
}
