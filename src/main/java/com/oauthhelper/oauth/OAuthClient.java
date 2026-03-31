package com.oauthhelper.oauth;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.oauthhelper.token.TokenEntry;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Fetches OAuth tokens using Burp's own HTTP stack (api.http().sendRequest()).
 *
 * This respects Burp's upstream proxy settings, session handling rules, and
 * network configuration — required for BApp Store compliance.
 * Requests appear in Burp's Logger tab (all tools).
 */
public class OAuthClient {

    private MontoyaApi api;

    public void setApi(MontoyaApi api) { this.api = api; }

    public TokenEntry fetchToken(OAuthProfile profile) throws Exception {
        return clientCredentials(profile);
    }

    private TokenEntry clientCredentials(OAuthProfile profile) throws Exception {
        StringBuilder body = new StringBuilder("grant_type=client_credentials");
        appendScopes(body, profile);
        appendClientAuth(body, profile);
        api.logging().logToOutput("[OAuth Helper] Token request body: " + body);
        return post(profile, body.toString());
    }


    /**
     * Use a stored refresh token to get a new access token without user interaction.
     * Works for both Client Credentials tokens (if IdP issues refresh tokens) and
     * PKCE tokens.
     */
    public TokenEntry refreshToken(OAuthProfile profile, String refreshToken) throws Exception {
        StringBuilder body = new StringBuilder("grant_type=refresh_token");
        body.append("&refresh_token=").append(enc(refreshToken));
        appendClientAuth(body, profile);
        return post(profile, body.toString());
    }

    public TokenEntry exchangeCode(OAuthProfile profile, String code,
                                   String verifier, String redirectUri) throws Exception {
        StringBuilder body = new StringBuilder("grant_type=authorization_code");
        body.append("&code=").append(enc(code));
        body.append("&redirect_uri=").append(enc(redirectUri));
        body.append("&code_verifier=").append(enc(verifier));
        appendClientAuth(body, profile);
        return post(profile, body.toString());
    }

    // ── Core sender — uses Burp HTTP stack ────────────────────────────────────

    private TokenEntry post(OAuthProfile profile, String formBody) throws Exception {
        URI uri    = URI.create(profile.getTokenUrl());
        String host  = uri.getHost();
        boolean tls  = "https".equals(uri.getScheme());
        int port     = uri.getPort() == -1 ? (tls ? 443 : 80) : uri.getPort();
        String path  = uri.getRawPath().isBlank() ? "/" : uri.getRawPath();

        StringBuilder raw = new StringBuilder();
        raw.append("POST ").append(path).append(" HTTP/1.1\r\n");
        raw.append("Host: ").append(host).append("\r\n");
        raw.append("Content-Type: application/x-www-form-urlencoded\r\n");
        raw.append("Accept: application/json\r\n");
        raw.append("Content-Length: ").append(
                formBody.getBytes(StandardCharsets.UTF_8).length).append("\r\n");

        if (profile.getClientAuthMethod() == OAuthProfile.ClientAuthMethod.HTTP_BASIC) {
            String creds = profile.getClientId() + ":" + profile.getClientSecret();
            raw.append("Authorization: Basic ").append(
                    Base64.getEncoder().encodeToString(
                            creds.getBytes(StandardCharsets.UTF_8))).append("\r\n");
        }

        raw.append("Connection: close\r\n\r\n");
        raw.append(formBody);

        HttpService service = HttpService.httpService(host, port, tls);
        HttpRequest request = HttpRequest.httpRequest(service, raw.toString());
        HttpRequestResponse rr = api.http().sendRequest(request);

        int status = rr.response().statusCode();
        String responseBody = rr.response().bodyToString();

        if (status < 200 || status >= 300) {
            String err = extract(responseBody, "error_description");
            if (err == null) err = extract(responseBody, "error");
            if (err == null) err = "HTTP " + status;
            throw new Exception(err + " (status " + status + ")");
        }

        return parse(profile.getName(), responseBody);
    }

    // ── Parser ────────────────────────────────────────────────────────────────

    private TokenEntry parse(String profileName, String json) throws Exception {
        String accessToken  = extract(json, "access_token");
        String tokenType    = extract(json, "token_type");
        String refreshToken = extract(json, "refresh_token");
        String expiresIn    = extract(json, "expires_in");

        if (accessToken == null)
            throw new Exception(
                "Server did not return an access_token. Check Burp Logger for the full response.");

        Instant now = Instant.now();
        Instant expiresAt = null;

        if (expiresIn != null) {
            try { expiresAt = now.plusSeconds(Long.parseLong(expiresIn)); }
            catch (NumberFormatException ignored) {}
        }
        if (expiresAt == null) {
            String payload = decodeJwt(accessToken);
            if (payload != null) {
                String exp = extract(payload, "exp");
                if (exp != null) {
                    try { expiresAt = Instant.ofEpochSecond(Long.parseLong(exp)); }
                    catch (NumberFormatException ignored) {}
                }
            }
        }

        return new TokenEntry(profileName, accessToken,
                tokenType != null ? tokenType : "Bearer",
                refreshToken, now, expiresAt, null, json);
    }

    // ── Auth helpers ──────────────────────────────────────────────────────────

    private void appendClientAuth(StringBuilder body, OAuthProfile profile) {
        switch (profile.getClientAuthMethod()) {
            case POST_BODY -> {
                body.append("&client_id=").append(enc(profile.getClientId()));
                body.append("&client_secret=").append(enc(profile.getClientSecret()));
            }
            case PRIVATE_KEY_JWT -> {
                // client identity is proved by the signed JWT assertion (iss claim).
                // RFC 7523 §3: client_id in the body is optional and omitted here
                // to avoid ambiguity with strict IdPs.
                body.append("&client_assertion_type=")
                    .append(enc("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
                body.append("&client_assertion=").append(enc(buildJwt(profile)));
            }
            case CLIENT_SECRET_JWT -> {
                // Signs the JWT assertion with the client secret (HMAC).
                // RFC 7523 + OIDC Core §9 — symmetric variant.
                // client_id is sent in the body so the IdP knows which client is authenticating
                // (the HMAC key is the secret itself, not a registered asymmetric key).
                body.append("&client_id=").append(enc(profile.getClientId()));
                body.append("&client_assertion_type=")
                    .append(enc("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
                body.append("&client_assertion=").append(enc(buildJwt(profile)));
            }
            case HTTP_BASIC -> {
                // Credentials are in the Authorization: Basic header (built in post()).
                // RFC 6749 §2.3.1: client MUST NOT send credentials in the request body
                // when using HTTP Basic authentication.
            }
        }
    }

    private void appendScopes(StringBuilder body, OAuthProfile profile) {
        if (profile.getScopes() != null && !profile.getScopes().isBlank())
            body.append("&scope=").append(enc(profile.getScopes()));
    }

    private String buildJwt(OAuthProfile profile) {
        try {
            OAuthProfile.JwtAlgorithm alg = profile.getJwtAlgorithm();
            String header  = b64url("{\"alg\":\"" + alg.name() + "\",\"typ\":\"JWT\"}");
            long now       = Instant.now().getEpochSecond();
            long exp       = now + profile.getJwtLifetimeSeconds();

            String aud = (profile.getJwtAudience() != null && !profile.getJwtAudience().isBlank())
                    ? profile.getJwtAudience()
                    : profile.getTokenUrl();

            // aud must be a JSON array — Keycloak and many other IdPs require this
            // even though RFC 7523 permits a plain string value.
            String payload = b64url("{\"iss\":\"" + profile.getClientId()
                    + "\",\"sub\":\"" + profile.getClientId()
                    + "\",\"aud\":[\"" + aud + "\"]"
                    + ",\"jti\":\"" + UUID.randomUUID()
                    + "\",\"iat\":" + now + ",\"exp\":" + exp + "}");

            String input = header + "." + payload;
            byte[] jwtSig;

            if (isHmac(alg)) {
                // Symmetric signing with client secret (Client Secret JWT)
                String macAlg = jcaMacAlgorithm(alg);
                javax.crypto.Mac mac = javax.crypto.Mac.getInstance(macAlg);
                javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(
                        profile.getClientSecret().getBytes(StandardCharsets.UTF_8), macAlg);
                mac.init(secretKey);
                jwtSig = mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
            } else {
                // Asymmetric signing with private key (Private Key JWT)
                PrivateKey key = loadKey(profile.getPrivateKeyPem(), alg);
                String jcaAlg = jcaSignatureAlgorithm(alg);
                java.security.Signature sig = java.security.Signature.getInstance(jcaAlg);
                sig.initSign(key);
                sig.update(input.getBytes(StandardCharsets.UTF_8));
                byte[] rawSig = sig.sign();
                // EC signatures from JCA are DER-encoded; JWT requires raw R||S format
                jwtSig = isEc(alg) ? derToJose(rawSig, alg) : rawSig;
            }

            return input + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(jwtSig);
        } catch (Exception e) {
            throw new IllegalStateException("JWT build failed: " + e.getMessage(), e);
        }
    }

    /** Maps our JwtAlgorithm enum to the JCA Signature algorithm name (asymmetric only). */
    private static String jcaSignatureAlgorithm(OAuthProfile.JwtAlgorithm alg) {
        return switch (alg) {
            case RS256 -> "SHA256withRSA";
            case RS384 -> "SHA384withRSA";
            case RS512 -> "SHA512withRSA";
            case ES256 -> "SHA256withECDSA";
            case ES384 -> "SHA384withECDSA";
            default    -> throw new IllegalArgumentException("Not an asymmetric algorithm: " + alg);
        };
    }

    private static boolean isEc(OAuthProfile.JwtAlgorithm alg) {
        return alg == OAuthProfile.JwtAlgorithm.ES256 || alg == OAuthProfile.JwtAlgorithm.ES384;
    }

    private static boolean isHmac(OAuthProfile.JwtAlgorithm alg) {
        return alg == OAuthProfile.JwtAlgorithm.HS256
            || alg == OAuthProfile.JwtAlgorithm.HS384
            || alg == OAuthProfile.JwtAlgorithm.HS512;
    }

    private static String jcaMacAlgorithm(OAuthProfile.JwtAlgorithm alg) {
        return switch (alg) {
            case HS256 -> "HmacSHA256";
            case HS384 -> "HmacSHA384";
            case HS512 -> "HmacSHA512";
            default    -> "HmacSHA256";
        };
    }

    /** Returns the expected R/S component size in bytes for an EC algorithm. */
    private static int ecKeySize(OAuthProfile.JwtAlgorithm alg) {
        return switch (alg) {
            case ES256 -> 32;
            case ES384 -> 48;
            default    -> 32;
        };
    }

    /**
     * Converts a DER-encoded ECDSA signature (JCA output) to the raw R||S
     * concatenated format required by JWT (RFC 7518 §3.4).
     */
    private static byte[] derToJose(byte[] der, OAuthProfile.JwtAlgorithm alg) {
        int coordLen = ecKeySize(alg);
        // DER structure: 0x30 <len> 0x02 <rLen> <r> 0x02 <sLen> <s>
        int offset = 3; // skip 0x30 <total-len> 0x02
        int rLen   = der[offset++] & 0xFF;
        byte[] r   = new byte[rLen];
        System.arraycopy(der, offset, r, 0, rLen);
        offset += rLen + 1; // skip 0x02
        int sLen = der[offset++] & 0xFF;
        byte[] s = new byte[sLen];
        System.arraycopy(der, offset, s, 0, sLen);

        byte[] jose = new byte[coordLen * 2];
        // Right-align each component, stripping any leading 0x00 padding byte
        copyRight(r, jose, 0,         coordLen);
        copyRight(s, jose, coordLen,  coordLen);
        return jose;
    }

    private static void copyRight(byte[] src, byte[] dst, int dstOffset, int len) {
        int srcStart = 0;
        // skip leading zero byte added by DER to keep sign bit clear
        if (src.length > len && src[0] == 0) srcStart = 1;
        int srcLen  = src.length - srcStart;
        int dstStart = dstOffset + len - srcLen;
        System.arraycopy(src, srcStart, dst, dstStart, srcLen);
    }

    /**
     * Loads a PKCS#8 private key from PEM. Detects RSA vs EC automatically
     * from the key material — no need for the user to specify key type.
     */
    private PrivateKey loadKey(String pem, OAuthProfile.JwtAlgorithm alg) throws Exception {
        String stripped = pem.replaceAll("-----[^-]+-----", "").replaceAll("\\s", "");
        byte[] decoded  = Base64.getDecoder().decode(stripped);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        String keyAlg = isEc(alg) ? "EC" : "RSA";
        return KeyFactory.getInstance(keyAlg).generatePrivate(spec);
    }

    public static String generateCodeVerifier() {
        byte[] b = new byte[64];
        new SecureRandom().nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    public static String generateCodeChallenge(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static String enc(String v) {
        if (v == null) return "";
        return java.net.URLEncoder.encode(v, StandardCharsets.UTF_8);
    }

    private static String b64url(String s) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    static String extract(String json, String key) {
        if (json == null) return null;
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx + search.length());
        if (colon < 0) return null;
        int s = json.indexOf('"', colon + 1);
        if (s >= 0 && s < colon + 8) {
            int e = json.indexOf('"', s + 1);
            return e >= 0 ? json.substring(s + 1, e) : null;
        }
        int ns = colon + 1;
        while (ns < json.length() && Character.isWhitespace(json.charAt(ns))) ns++;
        int ne = ns;
        while (ne < json.length() && !",}\n".contains(String.valueOf(json.charAt(ne)))) ne++;
        String raw = json.substring(ns, ne).trim();
        return raw.isEmpty() ? null : raw;
    }

    private static String decodeJwt(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) return null;
            String p = parts[1];
            while (p.length() % 4 != 0) p += "=";
            return new String(Base64.getUrlDecoder().decode(p), StandardCharsets.UTF_8);
        } catch (Exception e) { return null; }
    }
}
