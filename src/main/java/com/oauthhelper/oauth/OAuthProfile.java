package com.oauthhelper.persistence;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import com.oauthhelper.oauth.OAuthProfile;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Persists profiles to the Burp project file via api.persistence().extensionData().
 *
 * Layout under extensionData root:
 *   "profile_names"   → StringList — ordered list of profile names
 *   "profile:<name>"  → ChildObject — all profile fields as typed primitives
 *
 * Professional only — on Community, extensionData() is in-memory and does not
 * survive restarts. Save/load still work within the session; this is handled
 * gracefully with no errors shown to the user.
 */
public class ProfileStore {

    private static final String KEY_NAMES = "profile_names";
    private static final String PREFIX    = "profile:";

    private final MontoyaApi api;

    public ProfileStore(MontoyaApi api) { this.api = api; }

    // ── Save all profiles ─────────────────────────────────────────────────────

    public void saveAll(List<OAuthProfile> profiles) {
        try {
            PersistedObject root = api.persistence().extensionData();

            PersistedList<String> nameList = PersistedList.persistedStringList();
            for (OAuthProfile p : profiles) nameList.add(p.getName());
            root.setStringList(KEY_NAMES, nameList);

            for (OAuthProfile p : profiles) {
                PersistedObject obj = PersistedObject.persistedObject();
                writeProfile(obj, p);
                root.setChildObject(PREFIX + p.getName(), obj);
            }

            // Remove stale entries for deleted profiles
            for (String key : root.childObjectKeys()) {
                if (!key.startsWith(PREFIX)) continue;
                String storedName = key.substring(PREFIX.length());
                boolean still = profiles.stream().anyMatch(p -> p.getName().equals(storedName));
                if (!still) root.deleteChildObject(key);
            }
        } catch (Exception e) {
            api.logging().logToOutput("[OAuth Helper] Could not save profiles: " + e.getMessage());
        }
    }

    // ── Load all profiles ─────────────────────────────────────────────────────

    public List<OAuthProfile> loadAll() {
        List<OAuthProfile> result = new ArrayList<>();
        try {
            PersistedObject root = api.persistence().extensionData();
            PersistedList<String> nameList = root.getStringList(KEY_NAMES);
            if (nameList == null || nameList.isEmpty()) return result;

            for (String name : nameList) {
                PersistedObject obj = root.getChildObject(PREFIX + name);
                if (obj == null) continue;
                result.add(readProfile(name, obj));
            }
            api.logging().logToOutput("[OAuth Helper] Loaded " + result.size() + " profile(s) from project.");
        } catch (Exception e) {
            api.logging().logToOutput("[OAuth Helper] Could not load profiles: " + e.getMessage());
        }
        return result;
    }

    // ── Serialisation ─────────────────────────────────────────────────────────

    private static void writeProfile(PersistedObject o, OAuthProfile p) {
        o.setString("name",              p.getName());
        o.setString("grantType",         p.getGrantType().name());
        o.setString("clientAuthMethod",  p.getClientAuthMethod().name());
        o.setString("tokenUrl",          p.getTokenUrl());
        o.setString("authorizationUrl",  p.getAuthorizationUrl());
        o.setString("clientId",          p.getClientId());
        o.setString("clientSecret",      p.getClientSecret());
        o.setString("privateKeyPem",     p.getPrivateKeyPem());
        o.setString("jwtAlgorithm",      p.getJwtAlgorithm().name());
        o.setString("jwtAudience",       p.getJwtAudience());
        o.setInteger("jwtLifetime",      p.getJwtLifetimeSeconds());
        o.setString("scopes",            p.getScopes());
        o.setBoolean("injectProxy",      p.isInjectProxy());
        o.setBoolean("injectRepeater",   p.isInjectRepeater());
        o.setBoolean("injectIntruder",   p.isInjectIntruder());
        o.setBoolean("injectScanner",    p.isInjectScanner());
        o.setString("headerName",        p.getHeaderName());
        o.setString("tokenPrefix",       p.getTokenPrefix());
        o.setBoolean("addIfMissing",     p.isAddIfMissing());
        o.setBoolean("replaceIfPresent", p.isReplaceIfPresent());
        o.setString("refreshMode",       p.getRefreshMode().name());
        o.setBoolean("scanEnabled",      p.isScanEnabled());
        o.setString("scanCodes",          p.getScanCodes());
        o.setString("sessionPhrase",      p.getSessionPhrase());
        o.setBoolean("regenEnabled",     p.isRegenEnabled());
        o.setInteger("regenThreshold",   p.getRegenThreshold());
    }

    private static OAuthProfile readProfile(String name, PersistedObject o) {
        OAuthProfile p = new OAuthProfile(name);
        safeEnum(o.getString("grantType"),        OAuthProfile.GrantType.class,        p::setGrantType);
        safeEnum(o.getString("clientAuthMethod"), OAuthProfile.ClientAuthMethod.class, p::setClientAuthMethod);
        safeStr(o.getString("tokenUrl"),          p::setTokenUrl);
        safeStr(o.getString("authorizationUrl"),  p::setAuthorizationUrl);
        safeStr(o.getString("clientId"),          p::setClientId);
        safeStr(o.getString("clientSecret"),      p::setClientSecret);
        safeStr(o.getString("privateKeyPem"),     p::setPrivateKeyPem);
        safeEnum(o.getString("jwtAlgorithm"),     OAuthProfile.JwtAlgorithm.class, p::setJwtAlgorithm);
        safeStr(o.getString("jwtAudience"),       p::setJwtAudience);
        Integer jwtLife = o.getInteger("jwtLifetime");
        if (jwtLife != null) p.setJwtLifetimeSeconds(jwtLife);
        safeStr(o.getString("scopes"),            p::setScopes);
        safeBool(o.getBoolean("injectProxy"),      p::setInjectProxy);
        safeBool(o.getBoolean("injectRepeater"),   p::setInjectRepeater);
        safeBool(o.getBoolean("injectIntruder"),   p::setInjectIntruder);
        safeBool(o.getBoolean("injectScanner"),    p::setInjectScanner);
        safeStr(o.getString("headerName"),         p::setHeaderName);
        safeStr(o.getString("tokenPrefix"),        p::setTokenPrefix);
        safeBool(o.getBoolean("addIfMissing"),     p::setAddIfMissing);
        safeBool(o.getBoolean("replaceIfPresent"), p::setReplaceIfPresent);
        safeEnum(o.getString("refreshMode"),       OAuthProfile.RefreshMode.class, p::setRefreshMode);
        safeBool(o.getBoolean("scanEnabled"),      p::setScanEnabled);
        safeStr(o.getString("scanCodes"),           p::setScanCodes);
        safeStr(o.getString("sessionPhrase"),       p::setSessionPhrase);
        safeBool(o.getBoolean("regenEnabled"),     p::setRegenEnabled);
        Integer thresh = o.getInteger("regenThreshold");
        if (thresh != null) p.setRegenThreshold(thresh);
        return p;
    }

    private static void safeStr(String v, Consumer<String> s)  { if (v != null) s.accept(v); }
    private static void safeBool(Boolean v, Consumer<Boolean> s) { if (v != null) s.accept(v); }
    private static <E extends Enum<E>> void safeEnum(String v, Class<E> cls, Consumer<E> s) {
        if (v == null) return;
        try { s.accept(Enum.valueOf(cls, v)); } catch (IllegalArgumentException ignored) {}
    }
}
