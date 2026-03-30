package com.oauthhelper.oauth;

import burp.api.montoya.MontoyaApi;
import com.oauthhelper.token.TokenEntry;

import java.awt.Desktop;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Authorization Code + PKCE flow.
 *
 * User experience:
 *   1. Click "Fetch Token" in the extension.
 *   2. The system's default browser opens to the IdP login page automatically.
 *   3. User logs in. IdP redirects to http://localhost:<port>/callback.
 *   4. The loopback server catches the code. Browser tab shows "Done!".
 *   5. Token appears in the extension. Done.
 *
 * No copying URLs. No Burp dialogs to dismiss. No manual steps beyond logging in.
 *
 * IdP setup (one time):
 *   Add "http://localhost" to Valid Redirect URIs.
 *   Keycloak and RFC-8252-compliant IdPs accept any port for loopback URIs.
 */
public class PkceFlowHandler {

    private static final int TIMEOUT_SECONDS = 300;

    private final MontoyaApi api;
    private final OAuthClient oAuthClient;

    public PkceFlowHandler(MontoyaApi api, OAuthClient oAuthClient) {
        this.api = api;
        this.oAuthClient = oAuthClient;
    }

    public TokenEntry run(OAuthProfile profile) throws Exception {
        String verifier    = OAuthClient.generateCodeVerifier();
        String challenge   = OAuthClient.generateCodeChallenge(verifier);
        int port           = findFreePort();
        String redirectUri = "http://localhost:" + port + "/callback";

        // Start loopback server before opening the browser
        CompletableFuture<String> codeFuture = new CompletableFuture<>();
        Thread server = new Thread(() -> runServer(port, codeFuture), "pkce-loopback");
        server.setDaemon(true);
        server.start();

        String authUrl = profile.getAuthorizationUrl()
                + "?response_type=code"
                + "&client_id="             + enc(profile.getClientId())
                + "&redirect_uri="          + enc(redirectUri)
                + "&scope="                 + enc(profile.getScopes())
                + "&code_challenge="        + enc(challenge)
                + "&code_challenge_method=S256";

        api.logging().logToOutput("[PKCE] Opening browser for login...");
        api.logging().logToOutput("[PKCE] Redirect URI: " + redirectUri);

        // Open the system browser — user just logs in, nothing else to do
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            Desktop.getDesktop().browse(URI.create(authUrl));
        } else {
            throw new IOException(
                "Cannot open a browser on this system. Copy the auth URL from Burp Logger and open it manually:\n"
                + authUrl);
        }

        // Wait for the callback
        String code;
        try {
            code = codeFuture.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            throw new TimeoutException(
                "Timed out waiting for the PKCE callback (" + TIMEOUT_SECONDS + "s). "
                + "Make sure 'http://localhost' is registered as a Valid Redirect URI in your IdP.");
        } catch (java.util.concurrent.ExecutionException e) {
            throw new Exception(e.getCause().getMessage(), e.getCause());
        }

        api.logging().logToOutput("[PKCE] Callback received. Exchanging code for token...");
        return oAuthClient.exchangeCode(profile, code, verifier, redirectUri);
    }

    private void runServer(int port, CompletableFuture<String> future) {
        try (ServerSocket ss = new ServerSocket(port, 1, InetAddress.getLoopbackAddress())) {
            ss.setSoTimeout(TIMEOUT_SECONDS * 1000);
            try (Socket client = ss.accept()) {
                String req  = new String(
                        client.getInputStream().readNBytes(8192), StandardCharsets.UTF_8);
                String code  = extractParam(req, "code");
                String error = extractParam(req, "error");

                String body = code != null
                        ? "<html><body style='font-family:sans-serif;padding:40px'>"
                          + "<h2>&#10003; Done!</h2>"
                          + "<p>You're authenticated. You can close this tab and return to Burp.</p>"
                          + "</body></html>"
                        : "<html><body style='font-family:sans-serif;padding:40px'>"
                          + "<h2>&#10007; Error</h2>"
                          + "<p>" + (error != null ? error : "Unknown error") + "</p>"
                          + "</body></html>";

                byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
                String response = "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: text/html; charset=utf-8\r\n"
                        + "Content-Length: " + bodyBytes.length + "\r\n"
                        + "Connection: close\r\n\r\n";

                try (OutputStream os = client.getOutputStream()) {
                    os.write(response.getBytes(StandardCharsets.UTF_8));
                    os.write(bodyBytes);
                }

                if (code != null) future.complete(code);
                else future.completeExceptionally(
                        new IOException("IdP returned error: " + error));
            }
        } catch (Exception e) {
            future.completeExceptionally(e);
        }
    }

    private static int findFreePort() throws IOException {
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return s.getLocalPort();
        }
    }

    private static String extractParam(String httpRequest, String param) {
        String key = param + "=";
        int i = httpRequest.indexOf(key);
        if (i < 0) return null;
        int s = i + key.length(), e = s;
        while (e < httpRequest.length()
                && httpRequest.charAt(e) != '&'
                && httpRequest.charAt(e) != ' '
                && httpRequest.charAt(e) != '\r') e++;
        String val = httpRequest.substring(s, e);
        return val.isBlank() ? null : val;
    }

    private static String enc(String v) {
        if (v == null) return "";
        return java.net.URLEncoder.encode(v, StandardCharsets.UTF_8);
    }
}
