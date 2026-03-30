import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.oauthhelper.http.TrafficHandler;
import com.oauthhelper.oauth.OAuthClient;
import com.oauthhelper.persistence.ProfileStore;
import com.oauthhelper.token.TokenManager;
import com.oauthhelper.ui.ConfigPanel;

public class Extension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("OAuth Helper");

        OAuthClient oAuthClient       = new OAuthClient();
        oAuthClient.setApi(api);

        TokenManager   tokenManager   = new TokenManager(api);
        TrafficHandler trafficHandler = new TrafficHandler(api, tokenManager);
        ProfileStore   profileStore   = new ProfileStore(api);
        ConfigPanel    configPanel    = new ConfigPanel(api, tokenManager, trafficHandler, oAuthClient);

        configPanel.setProfileStore(profileStore);
        configPanel.setRegenListener(trafficHandler);

        api.proxy().registerRequestHandler(trafficHandler);
        api.http().registerHttpHandler(trafficHandler);
        api.userInterface().registerSuiteTab("OAuth Helper", configPanel.uiComponent());

        api.extension().registerUnloadingHandler(() -> {
            tokenManager.shutdown();
            api.logging().logToOutput("OAuth Helper unloaded.");
        });

        api.logging().logToOutput("OAuth Helper loaded.");
    }
}
