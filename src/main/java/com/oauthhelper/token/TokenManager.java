package com.oauthhelper.token;

import burp.api.montoya.MontoyaApi;
import com.oauthhelper.oauth.OAuthProfile;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Stores active tokens and drives auto-refresh.
 *
 * Auto-refresh strategy: instead of a one-shot timer (which fails if the token
 * is already past the buffer when checked), we run a periodic check every 30s
 * per profile. When the token is expired or within the buffer window, we fire
 * onRefreshNeeded once. A per-profile flag prevents double-firing while a
 * refresh is already in flight.
 */
public class TokenManager {

    private static final long CHECK_INTERVAL_SECONDS = 10;  // check every 10s
    // Refresh as soon as token is expired (remaining <= 0)
    private static final long REFRESH_BUFFER_SECONDS = 0;

    private final MontoyaApi api;
    private final Map<String, TokenEntry> activeTokens = new ConcurrentHashMap<>();
    private final List<TokenChangeListener> listeners  = new java.util.concurrent.CopyOnWriteArrayList<>();

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "oauth-refresh-scheduler");
        t.setDaemon(true);
        return t;
    });

    // Per-profile periodic check futures
    private final Map<String, ScheduledFuture<?>> checks = new ConcurrentHashMap<>();
    // Guard: profile names currently undergoing a refresh — prevents double-fire
    private final java.util.Set<String> refreshInFlight =
            java.util.Collections.newSetFromMap(new ConcurrentHashMap<>());

    public TokenManager(MontoyaApi api) { this.api = api; }

    // ── Token storage ─────────────────────────────────────────────────────────

    public void storeToken(OAuthProfile profile, TokenEntry entry) {
        activeTokens.put(profile.getName(), entry);
        // Clear in-flight flag so the next check cycle can fire again if needed
        refreshInFlight.remove(profile.getName());
        api.logging().logToOutput("[OAuth Helper] Token stored for: " + profile.getName()
                + " | TTL: " + entry.secondsRemaining() + "s");
        notifyChanged(profile.getName(), entry);
        // Ensure periodic check is running for this profile
        ensureCheckRunning(profile);
    }

    public TokenEntry getToken(String name) { return activeTokens.get(name); }

    public TokenEntry getValidToken(String name) {
        TokenEntry e = activeTokens.get(name);
        return (e == null || e.isExpired()) ? null : e;
    }

    public void clearToken(String name) {
        activeTokens.remove(name);
        cancelCheck(name);
        refreshInFlight.remove(name);
        notifyChanged(name, null);
    }

    // ── Periodic expiry check ─────────────────────────────────────────────────

    private void ensureCheckRunning(OAuthProfile profile) {
        if (profile.getRefreshMode() != OAuthProfile.RefreshMode.AUTO_SILENT) {
            cancelCheck(profile.getName());
            return;
        }
        // Only start if not already running
        if (checks.containsKey(profile.getName())) return;

        ScheduledFuture<?> f = scheduler.scheduleAtFixedRate(
                () -> checkAndRefreshIfNeeded(profile),
                CHECK_INTERVAL_SECONDS,   // first check after 10s
                CHECK_INTERVAL_SECONDS,   // then every 10s
                TimeUnit.SECONDS);
        checks.put(profile.getName(), f);
        api.logging().logToOutput("[OAuth Helper] Expiry check started for: " + profile.getName());
    }

    private void checkAndRefreshIfNeeded(OAuthProfile profile) {
        try {
            TokenEntry entry = activeTokens.get(profile.getName());
            if (entry == null) return;
            if (entry.getExpiresAt() == null) return;

            long remaining = entry.secondsRemaining();
            boolean needsRefresh = remaining <= REFRESH_BUFFER_SECONDS;

            if (needsRefresh && refreshInFlight.add(profile.getName())) {
                api.logging().logToOutput("[OAuth Helper] Token expired, auto-refreshing: "
                        + profile.getName() + " | remaining: " + remaining + "s");
                notifyRefreshNeeded(profile);
            }
        } catch (Exception e) {
            api.logging().logToError("[OAuth Helper] Unexpected error in refresh check for '"
                    + profile.getName() + "': " + e.getMessage());
            java.io.PrintWriter pw = new java.io.PrintWriter(
                    new java.io.StringWriter());
            e.printStackTrace(pw);
            api.logging().logToError(pw.toString());
        }
    }

    /** Cancel scheduled auto-refresh for one profile. */
    public void cancelAutoRefresh(String name) {
        cancelCheck(name);
        refreshInFlight.remove(name);
    }

    /** Resume auto-refresh for a profile — requires a token to already be stored. */
    public void startAutoRefresh(OAuthProfile profile) {
        ensureCheckRunning(profile);
    }

    /** True if the periodic expiry-check scheduler is currently running for this profile. */
    public boolean isAutoRefreshRunning(String name) {
        return checks.containsKey(name);
    }

    private void cancelCheck(String name) {
        ScheduledFuture<?> f = checks.remove(name);
        if (f != null) f.cancel(false);
    }

    // ── Listeners ─────────────────────────────────────────────────────────────

    /** Called by the unload handler — cancels all scheduled checks and stops the executor. */
    public void shutdown() {
        checks.forEach((name, f) -> f.cancel(false));
        checks.clear();
        scheduler.shutdownNow();
        api.logging().logToOutput("[OAuth Helper] TokenManager shut down.");
    }

    public void addListener(TokenChangeListener l) { listeners.add(l); }

    private void notifyChanged(String name, TokenEntry entry) {
        for (TokenChangeListener l : listeners) {
            try { l.onTokenChanged(name, entry); }
            catch (Exception e) { api.logging().logToError("Listener error: " + e.getMessage()); }
        }
    }

    private void notifyRefreshNeeded(OAuthProfile profile) {
        for (TokenChangeListener l : listeners) {
            try { l.onRefreshNeeded(profile); }
            catch (Exception e) {
                refreshInFlight.remove(profile.getName()); // allow retry on next cycle
                api.logging().logToError("Refresh listener error: " + e.getMessage());
            }
        }
    }

    public interface TokenChangeListener {
        void onTokenChanged(String profileName, TokenEntry entry);
        void onRefreshNeeded(OAuthProfile profile);
    }
}
