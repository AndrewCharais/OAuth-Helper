package com.oauthhelper.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.*;
import com.oauthhelper.oauth.OAuthProfile;
import com.oauthhelper.token.TokenEntry;
import com.oauthhelper.token.TokenManager;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Handles both token injection and token header scanning.
 *
 * Injection: ProxyRequestHandler + HttpHandler (Proxy, Repeater, Intruder, Scanner).
 *
 * Scanner: watches in-scope responses for 401/403.
 *   - Counts consecutive hits per profile (reset when a new token is stored).
 *   - When the hit count reaches the profile's regenThreshold, fires a listener
 *     so ConfigPanel can trigger a re-fetch.
 *   - Only counts responses where the matching token was actually injected
 *     (same access token as currently stored), so it doesn't false-fire on
 *     endpoints that legitimately return 401 for other reasons.
 */
public class TrafficHandler implements ProxyRequestHandler, HttpHandler {

    public interface RegenListener {
        void onRegenNeeded(OAuthProfile profile);
    }

    private final MontoyaApi api;
    private final TokenManager tokenManager;
    private final List<OAuthProfile> profiles   = new CopyOnWriteArrayList<>();
    private final List<RegenListener> regenListeners = new CopyOnWriteArrayList<>();

    // Per-profile consecutive 401/403 counter.
    // Key: profile name. Reset when storeToken() is called.
    private final Map<String, AtomicInteger> authFailCounts = new ConcurrentHashMap<>();

    public TrafficHandler(MontoyaApi api, TokenManager tokenManager) {
        this.api = api;
        this.tokenManager = tokenManager;
        // Reset counters when a new token is stored
        tokenManager.addListener(new TokenManager.TokenChangeListener() {
            @Override public void onTokenChanged(String profileName, TokenEntry entry) {
                authFailCounts.computeIfAbsent(profileName, k -> new AtomicInteger()).set(0);
            }
            @Override public void onRefreshNeeded(OAuthProfile profile) {}
        });
    }

    // ── ProxyRequestHandler ───────────────────────────────────────────────────

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest req) {
        return ProxyRequestReceivedAction.continueWith(req);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest req) {
        if (!api.scope().isInScope(req.url()))
            return ProxyRequestToBeSentAction.continueWith(req);
        HttpRequest modified = tryInject(req, ToolType.PROXY);
        return ProxyRequestToBeSentAction.continueWith(modified != null ? modified : req);
    }

    // ── HttpHandler ───────────────────────────────────────────────────────────

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        if (req.toolSource().isFromTool(ToolType.PROXY))
            return RequestToBeSentAction.continueWith(req);
        if (req.toolSource().isFromTool(ToolType.EXTENSIONS))
            return RequestToBeSentAction.continueWith(req);
        if (!api.scope().isInScope(req.url()))
            return RequestToBeSentAction.continueWith(req);
        HttpRequest modified = tryInject(req, req.toolSource().toolType());
        return RequestToBeSentAction.continueWith(modified != null ? modified : req);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived res) {
        // Only scan in-scope responses
        if (!api.scope().isInScope(res.initiatingRequest().url()))
            return ResponseReceivedAction.continueWith(res);

        int status = res.statusCode();
        String body = res.bodyToString();
        for (OAuthProfile profile : profiles) {
            if (!profile.isScanEnabled()) continue;
            boolean codeMatch   = profile.parsedScanCodes().contains(status);
            boolean phraseMatch = profile.getSessionPhrase() != null
                    && !profile.getSessionPhrase().isBlank()
                    && body.contains(profile.getSessionPhrase());
            if (codeMatch || phraseMatch) {
                checkAuthFailure(res.initiatingRequest(), profile,
                        codeMatch ? "HTTP " + status : "phrase match");
            }
        }
        return ResponseReceivedAction.continueWith(res);
    }

    // ── Token header scan ─────────────────────────────────────────────────────

    private void checkAuthFailure(HttpRequest req, OAuthProfile profile, String reason) {
        // Only count if the request actually carried this profile's token
        TokenEntry token = tokenManager.getToken(profile.getName());
        if (token == null) return;

        String headerValue = profile.getTokenPrefix().isBlank()
                ? token.getAccessToken()
                : profile.getTokenPrefix() + " " + token.getAccessToken();

        boolean hadToken = req.headers().stream()
                .anyMatch(h -> h.name().equalsIgnoreCase(profile.getHeaderName())
                        && h.value().equals(headerValue));
        if (!hadToken) return;

        int count = authFailCounts
                .computeIfAbsent(profile.getName(), k -> new AtomicInteger())
                .incrementAndGet();

        api.logging().logToOutput("[OAuth Helper] Session termination signal [" + reason + "] for '"
                + profile.getName() + "' (" + count + "/" + profile.getRegenThreshold()
                + ") — " + req.url());

        if (profile.isRegenEnabled() && count >= profile.getRegenThreshold()) {
            authFailCounts.get(profile.getName()).set(0);
            api.logging().logToOutput("[OAuth Helper] Threshold reached for '"
                    + profile.getName() + "' — triggering token re-fetch.");
            for (RegenListener l : regenListeners) {
                try { l.onRegenNeeded(profile); }
                catch (Exception e) {
                    api.logging().logToError("RegenListener error: " + e.getMessage());
                }
            }
        }
    }

    // ── Shared injection logic ────────────────────────────────────────────────

    private HttpRequest tryInject(HttpRequest request, ToolType tool) {
        for (OAuthProfile profile : profiles) {
            if (!isEnabledForTool(profile, tool)) continue;
            TokenEntry token = tokenManager.getToken(profile.getName());
            if (token == null) continue;
            HttpRequest modified = inject(request, profile, token);
            if (modified != request) {
                api.logging().logToOutput("[OAuth Helper][" + tool.toolName() + "] Injected '"
                        + profile.getHeaderName() + "' → " + request.url());
            }
            return modified;
        }
        return null;
    }

    private boolean isEnabledForTool(OAuthProfile profile, ToolType tool) {
        return switch (tool) {
            case PROXY    -> profile.isInjectProxy();
            case REPEATER -> profile.isInjectRepeater();
            case INTRUDER -> profile.isInjectIntruder();
            case SCANNER  -> profile.isInjectScanner();
            default       -> false;
        };
    }

    private HttpRequest inject(HttpRequest request, OAuthProfile profile, TokenEntry token) {
        String headerName  = profile.getHeaderName();
        String headerValue = profile.getTokenPrefix().isBlank()
                ? token.getAccessToken()
                : profile.getTokenPrefix() + " " + token.getAccessToken();

        boolean exists = request.headers().stream()
                .anyMatch(h -> h.name().equalsIgnoreCase(headerName));

        if (exists && profile.isReplaceIfPresent())
            return request.withRemovedHeader(headerName).withAddedHeader(headerName, headerValue);
        if (!exists && profile.isAddIfMissing())
            return request.withAddedHeader(headerName, headerValue);
        return request;
    }

    // ── Profile management ────────────────────────────────────────────────────

    public void setProfiles(List<OAuthProfile> p) { profiles.clear(); profiles.addAll(p); }
    public void addProfile(OAuthProfile p)         { profiles.add(p); }
    public void removeProfile(String name)         { profiles.removeIf(p -> p.getName().equals(name)); }
    public List<OAuthProfile> getProfiles()        { return List.copyOf(profiles); }
    public void addRegenListener(RegenListener l)  { regenListeners.add(l); }
}
