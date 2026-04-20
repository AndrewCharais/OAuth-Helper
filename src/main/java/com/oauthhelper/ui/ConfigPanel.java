package com.oauthhelper.ui;

import burp.api.montoya.MontoyaApi;
import com.oauthhelper.persistence.ProfileStore;
import com.oauthhelper.http.TrafficHandler;
import com.oauthhelper.oauth.OAuthClient;
import com.oauthhelper.oauth.OAuthProfile;
import com.oauthhelper.token.TokenEntry;
import com.oauthhelper.token.TokenManager;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.net.URI;
import java.util.List;

public class ConfigPanel implements TokenManager.TokenChangeListener {

    private final MontoyaApi      api;
    private final TokenManager    tokenManager;
    private final TrafficHandler  trafficHandler;
    private final OAuthClient     oAuthClient;
    private       ProfileStore    profileStore;

    // Derived at runtime so they match Burp's current LAF exactly.
    // Components that don't need a special font simply inherit — no explicit setFont.
    private static Font burpBold() {
        Font f = UIManager.getFont("Label.font");
        return f != null ? f.deriveFont(Font.BOLD) : new JLabel().getFont().deriveFont(Font.BOLD);
    }
    private static Font burpMono() {
        Font f = UIManager.getFont("Label.font");
        float sz = f != null ? f.getSize2D() : 12f;
        return new Font(Font.MONOSPACED, Font.PLAIN, Math.round(sz));
    }
    private static final Color SECTION_FG = new Color(80, 80, 80);

    private final DefaultListModel<OAuthProfile> profileModel = new DefaultListModel<>();
    private final JList<OAuthProfile>            profileList  = new JList<>(profileModel);
    private OAuthProfile selected = null;

    private JPanel rightPane;
    private JPanel formPanel;

    private JTextField    tfName, tfTokenUrl, tfClientId, tfScopes, tfJwtAudience;
    private JPasswordField pfSecret;
    private JTextArea        taPrivateKey;
    private JComboBox<OAuthProfile.JwtAlgorithm> cbJwtAlgorithm;
    private JSpinner spJwtLifetime;
    private JComboBox<OAuthProfile.GrantType>        cbGrant;
    private JComboBox<OAuthProfile.ClientAuthMethod> cbAuth;
    private JComboBox<String>                        cbRefresh;

    private JCheckBox chkInjectProxy, chkInjectRepeater, chkInjectIntruder, chkInjectScanner;
    private JCheckBox chkInjectSequencer, chkInjectTarget;
    private JCheckBox chkInjectionEnabled;
    private JCheckBox chkDebugMode;
    private JTextField tfRopcUsername;
    private JPasswordField pfRopcPassword;
    private JPanel rowRopcUsername, rowRopcPassword, rowRopcWarning;
    private JComboBox<String> cbHttpVersion;
    private JTextField tfHeaderName, tfTokenPrefix;

    private JSpinner   spRegenThreshold;
    private JTextField tfScanCodes, tfSessionPhrase;

    private JPanel rowSecret, rowPrivateKey, rowJwtAudience, rowJwtAlgorithm, rowJwtLifetime, rowRefreshMode, rowAuthMethod;
    private JPanel pnlInjectionBody;
    private JPanel pnlInjectionTools;
    private JPanel pnlMonitorBody;
    private JLabel lblScopesLabel;

    private JButton  btnFetch, btnTest, btnCopy, btnSave;
    private JLabel   lblStatus, lblTtl;
    private JTextArea taToken;
    private Timer    ttlTimer;

    private volatile boolean fetchInProgress = false;

    private java.awt.Frame suiteFrame;

    private static final String[] REFRESH_LABELS = { "Manual", "Auto-Refresh" };

    public ConfigPanel(MontoyaApi api, TokenManager tokenManager,
                       TrafficHandler trafficHandler, OAuthClient oAuthClient) {
        this.api            = api;
        this.tokenManager   = tokenManager;
        this.trafficHandler = trafficHandler;
        this.oAuthClient    = oAuthClient;
        tokenManager.addListener(this);
    }

    public void setProfileStore(ProfileStore ps) { this.profileStore = ps; }

    public void setRegenListener(TrafficHandler th) {
        th.addRegenListener(profile -> {
            if (profile.isRegenEnabled()) {
                api.logging().logToOutput("[OAuth Helper] Auto-regen triggered for: " + profile.getName());
                runFetch(profile, false);
            }
        });
    }

    public Component uiComponent() {
        ToolTipManager.sharedInstance().setInitialDelay(150);
        ToolTipManager.sharedInstance().setDismissDelay(10000);
        suiteFrame = api.userInterface().swingUtils().suiteFrame();

        JPanel root = new JPanel(new BorderLayout());

        // ── Left: profile list ────────────────────────────────────────────────
        JPanel left = new JPanel(new BorderLayout(0, 3));
        left.setPreferredSize(new Dimension(160, 0));
        left.setBorder(new EmptyBorder(8, 8, 8, 4));

        // Trash icon via char code to avoid file encoding issues
        // ── [ + New Profile ] above the list ──────────────────────────────
        // ── Full-width [ + New Profile ] button ──────────────────────────────
        JButton btnNew = new JButton("+ New Profile");
        btnNew.setMargin(new Insets(3, 4, 3, 4));
        btnNew.addActionListener(e -> onAdd());
        JPanel topBtns = new JPanel(new BorderLayout());
        topBtns.setOpaque(false);
        topBtns.setBorder(new EmptyBorder(0, 0, 3, 0));
        topBtns.add(btnNew, BorderLayout.CENTER);
        left.add(topBtns, BorderLayout.NORTH);

        // ── Profile list ─────────────────────────────────────────────────────
        profileList.setFixedCellHeight(22);
        profileList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        profileList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) onSelect(profileList.getSelectedValue());
        });
        JScrollPane listScroll = new JScrollPane(profileList);
        listScroll.setBorder(BorderFactory.createLineBorder(new Color(200, 200, 200)));
        left.add(listScroll, BorderLayout.CENTER);

        // ── Three equal-width buttons spanning the full panel width ───────────
        JButton btnImport = new JButton("Import");
        JButton btnExport = new JButton("Export");
        JButton btnDel    = new JButton("Delete");
        for (JButton b : new JButton[]{btnImport, btnExport, btnDel}) {
            b.setMargin(new Insets(2, 2, 2, 2));
        }
        btnImport.addActionListener(e -> onLoadProfile());
        btnExport.addActionListener(e -> onExportProfile());
        btnDel.addActionListener(e -> onDelete());
        btnDel.setEnabled(false);
        profileList.addListSelectionListener(ev -> {
            btnDel.setEnabled(profileList.getSelectedValue() != null);
        });
        JPanel southBtns = new JPanel(new GridLayout(1, 3, 2, 0));
        southBtns.setOpaque(false);
        southBtns.setBorder(new EmptyBorder(3, 0, 0, 0));
        southBtns.add(btnImport);
        southBtns.add(btnExport);
        southBtns.add(btnDel);
        left.add(southBtns, BorderLayout.SOUTH);

        // ── Right: card layout ────────────────────────────────────────────────
        JLabel emptyLbl = new JLabel("Select or create a profile to begin.", SwingConstants.CENTER);
        emptyLbl.setForeground(Color.GRAY);

        formPanel = buildForm();

        JPanel formWrapper = new JPanel(new BorderLayout());
        formWrapper.add(formPanel, BorderLayout.NORTH);
        JScrollPane formScroll = new JScrollPane(formWrapper);
        formScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        formScroll.setBorder(null);

        rightPane = new JPanel(new CardLayout());
        rightPane.add(emptyLbl, "empty");
        rightPane.add(formScroll, "form");
        rightPane.setBorder(new EmptyBorder(6, 4, 6, 6));

        root.add(left,      BorderLayout.WEST);
        root.add(rightPane, BorderLayout.CENTER);


        if (profileStore != null) {
            for (OAuthProfile p : profileStore.loadAll()) {
                profileModel.addElement(p);
                trafficHandler.addProfile(p);
            }
            if (profileModel.size() > 0) profileList.setSelectedIndex(0);
        }

        updateVisibility();

        ttlTimer = new Timer(1000, e -> updateTtl());
        ttlTimer.start();

        return root;
    }

    private JPanel buildForm() {
        cbGrant = combo(OAuthProfile.GrantType.values(),
                v -> grantLabel((OAuthProfile.GrantType) v));
        cbGrant.addActionListener(e -> updateVisibility());

        cbAuth = combo(OAuthProfile.ClientAuthMethod.values(),
                v -> authLabel((OAuthProfile.ClientAuthMethod) v));
        cbAuth.addActionListener(e -> updateVisibility());
        cbJwtAlgorithm = new JComboBox<>(OAuthProfile.JwtAlgorithm.values());
        cbJwtAlgorithm.addActionListener(e -> updateVisibility());
        spJwtLifetime = new JSpinner(new SpinnerNumberModel(300, 60, 3600, 30));

        cbRefresh = new JComboBox<>(REFRESH_LABELS);
        cbRefresh.setSelectedIndex(1); // default to Auto-Refresh
        cbRefresh.addActionListener(e -> updateVisibility());

        chkInjectProxy    = chk("Proxy");
        chkInjectRepeater = chk("Repeater");
        chkInjectIntruder = chk("Intruder");
        chkInjectScanner   = chk("Scanner");
        chkInjectSequencer = chk("Sequencer");
        chkInjectTarget    = chk("Target");
        tfRopcUsername = field();
        pfRopcPassword = new JPasswordField();
        pfRopcPassword.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 24));
        chkInjectionEnabled = chk("Token updates enabled");
        chkInjectionEnabled.setSelected(true);
        chkInjectionEnabled.setToolTipText("Uncheck to disable token updates in all tools without losing your settings.");
        chkDebugMode = chk("Debug mode");
        chkDebugMode.setToolTipText("When enabled, verbose output is written to Extensions → OAuth Helper → Output.");
        cbHttpVersion = new JComboBox<>(new String[]{"HTTP/1.1", "HTTP/2"});
        java.awt.event.ActionListener toolToggle = e -> updateVisibility();
        for (JCheckBox c : new JCheckBox[]{chkInjectProxy, chkInjectRepeater,
                chkInjectIntruder, chkInjectScanner,
                chkInjectSequencer, chkInjectTarget})
            c.addActionListener(toolToggle);

        spRegenThreshold = new JSpinner(new SpinnerNumberModel(3, 1, 20, 1));

        tfScanCodes     = field(); setPlaceholder(tfScanCodes,     "e.g. 401, 403");
        tfSessionPhrase = field(); setPlaceholder(tfSessionPhrase, "e.g. invalid_token, session expired");
        tfName          = field();
        tfTokenUrl      = field();
        tfClientId      = field();
        pfSecret        = pwField();
        pfSecret.setMaximumSize(new Dimension(Integer.MAX_VALUE, 24));
        taPrivateKey = new JTextArea(4, 30);
        taPrivateKey.setLineWrap(true);
        taPrivateKey.setWrapStyleWord(false);
        taPrivateKey.setFont(burpMono());
        tfJwtAudience   = field();
        tfScopes        = field();
        tfHeaderName    = new JTextField("Authorization");
        tfTokenPrefix   = new JTextField("Bearer");

        lblStatus        = lbl("No token fetched."); lblStatus.setForeground(Color.GRAY);
        lblTtl           = lbl("");

        // ── Button declarations ────────────────────────────────────────────────
        btnSave        = btn("Save Settings");
        btnTest        = btn("Test Connection");
        btnFetch       = btn("Get Token");
        btnCopy        = btn("Copy Token");   btnCopy.setVisible(false);

        // ── Outer form panel ───────────────────────────────────────────────────
        JPanel form = new JPanel();
        form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));
        form.setBorder(new EmptyBorder(8, 12, 16, 12));

        // ── PROFILE SETUP ──────────────────────────────────────────────────────
        form.add(sectionLabel("Profile Setup"));
        form.add(row("Profile Name", tfName));
        form.add(row("Grant Type",   cbGrant));

        // ── ENDPOINTS ─────────────────────────────────────────────────────────
        form.add(sectionLabel("Endpoints"));
        form.add(row("Token URL", tfTokenUrl,
                "The authorization server's token endpoint URL."));

        // ── CLIENT AUTHENTICATION ─────────────────────────────────────────────
        form.add(sectionLabel("Client Authentication"));
        form.add(row("Client ID", tfClientId));
        rowAuthMethod = row("Authentication Method", cbAuth);
        form.add(rowAuthMethod);
        rowSecret    = row("Client Secret",    pfSecret);
        // Private key needs a scrollable text area — PEM keys are multi-line
        JScrollPane privateKeyScroll = new JScrollPane(taPrivateKey);
        privateKeyScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 80));
        privateKeyScroll.setPreferredSize(new Dimension(300, 75));
        rowPrivateKey = row("Private Key (PEM)", privateKeyScroll,
                "Paste your PKCS#8 private key in PEM format.\n"
                + "Must start with -----BEGIN PRIVATE KEY-----");
        form.add(rowSecret);
        form.add(rowPrivateKey);
        rowPrivateKey.setMaximumSize(new Dimension(Integer.MAX_VALUE, 84));
        rowJwtAudience = row("Audience", tfJwtAudience,
                "The audience claim in the JWT assertion. Defaults to the Token URL if blank.\n" +
                "Keycloak: use the realm URL (e.g. http://host:port/realms/myrealm).\n" +
                "Other IdPs: use the token endpoint URL.");
        form.add(rowJwtAudience);
        rowJwtAlgorithm = row("Signing Algorithm", cbJwtAlgorithm,
                "RS256/RS384/RS512 for RSA keys. ES256/ES384 for EC (elliptic curve) keys.");
        form.add(rowJwtAlgorithm);
        rowJwtLifetime = row("Assertion Lifetime", spJwtLifetime,
                "How many seconds until the JWT assertion expires. Most IdPs accept 300 (5 min).\n"
                + "Reduce if your IdP rejects assertions with too long a lifetime.");
        form.add(rowJwtLifetime);
        lblScopesLabel = lbl("Scopes (optional)");
        lblScopesLabel.setPreferredSize(new Dimension(210, 22));
        JLabel ropcWarningLbl = new JLabel("⚠ Resource Owner Password is deprecated in OAuth 2.1 and not recommended for new implementations.");
        ropcWarningLbl.setForeground(new Color(180, 100, 0));
        ropcWarningLbl.setFont(ropcWarningLbl.getFont().deriveFont(java.awt.Font.ITALIC));
        rowRopcWarning = inlineRow(ropcWarningLbl);
        form.add(rowRopcWarning);
        rowRopcUsername = row("Username", tfRopcUsername, "Resource owner username.");
        form.add(rowRopcUsername);
        rowRopcPassword = row("Password", pfRopcPassword, "Resource owner password.");
        form.add(rowRopcPassword);
        form.add(rowWithLabel(lblScopesLabel, tfScopes,
                "Space-separated OAuth scopes (e.g. openid profile). Leave blank for server defaults."));

        // ── ADVANCED SETTINGS (collapsible) ───────────────────────────────────
        form.add(vGap(6));
        JPanel advancedSection = collapsibleSection("Advanced Settings", false, () -> {
            JPanel body = new JPanel();
            body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
            body.setOpaque(false);

            // Token updates enabled + Debug mode — left aligned
            JPanel toggleRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
            toggleRow.setOpaque(false);
            toggleRow.add(chkInjectionEnabled);
            toggleRow.add(Box.createHorizontalStrut(16));
            toggleRow.add(chkDebugMode);
            body.add(stretchy(toggleRow, 26));
            body.add(vGap(4));
            // Tool checkboxes — Target first, then the rest
            JPanel toolRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
            toolRow.setOpaque(false);
            toolRow.add(chkInjectTarget);
            toolRow.add(Box.createHorizontalStrut(12));
            toolRow.add(chkInjectProxy);
            toolRow.add(Box.createHorizontalStrut(12));
            toolRow.add(chkInjectRepeater);
            toolRow.add(Box.createHorizontalStrut(12));
            toolRow.add(chkInjectIntruder);
            toolRow.add(Box.createHorizontalStrut(12));
            toolRow.add(chkInjectScanner);
            toolRow.add(Box.createHorizontalStrut(12));
            toolRow.add(chkInjectSequencer);
            body.add(stretchy(toolRow, 26));
            body.add(vGap(4));
            body.add(row("HTTP Version", cbHttpVersion, "HTTP version used when fetching tokens. Use HTTP/1.1 for maximum compatibility."));

            pnlInjectionTools = new JPanel();
            pnlInjectionTools.setLayout(new BoxLayout(pnlInjectionTools, BoxLayout.Y_AXIS));
            pnlInjectionTools.setOpaque(false);
            pnlInjectionTools.add(row("Header Name", tfHeaderName,
                    "The HTTP request header the token is written into."));
            pnlInjectionTools.add(row("Token Prefix", tfTokenPrefix,
                    "Text prepended before the token value (e.g. Bearer). Leave blank to inject the raw token."));
            body.add(pnlInjectionTools);

            body.add(vGap(6));

            // Token Refresh Mode (no header — continuation of above settings)
            rowRefreshMode = row("Token Refresh Mode", cbRefresh,
                    "Manual: click Get Token when needed. Auto-Refresh: automatically gets a new token when the current one expires.");
            body.add(rowRefreshMode);

            body.add(vGap(6));

            // Session Monitoring (separate header since it's a different concern)
            body.add(sectionLabel("Session Monitoring"));
            pnlMonitorBody = new JPanel();
            pnlMonitorBody.setLayout(new BoxLayout(pnlMonitorBody, BoxLayout.Y_AXIS));
            pnlMonitorBody.setOpaque(false);
            pnlMonitorBody.add(row("Failure Status Codes", tfScanCodes,
                    "Comma-separated HTTP status codes that indicate a rejected token (e.g. 401, 403). Leave blank to disable session monitoring."));
            pnlMonitorBody.add(row("Failure Response Text", tfSessionPhrase,
                    "If this text appears in a response body, it will be treated as a session failure. Leave blank to disable."));
            pnlMonitorBody.add(row("Failures Before Refresh", spRegenThreshold,
                    "Number of consecutive failures before automatically requesting a new token."));
            body.add(pnlMonitorBody);

            return body;
        });
        form.add(advancedSection);

        // ── TOKEN MANAGEMENT ──────────────────────────────────────────────────
        form.add(vGap(8));

        // Row 1: [ Save Settings ]  [ Test Connection ]
        btnSave.addActionListener(e -> { if (doSave()) showMessage("Settings saved."); });
        btnTest.addActionListener(e -> { if (doSave()) runFetch(selected, true); });

        JPanel topBtnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        topBtnRow.setOpaque(false);
        topBtnRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        topBtnRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 32));
        topBtnRow.add(btnSave);
        topBtnRow.add(btnTest);
        form.add(topBtnRow);

        // Separator line
        JSeparator sep = new JSeparator();
        sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
        sep.setAlignmentX(Component.LEFT_ALIGNMENT);
        form.add(vGap(4));
        form.add(sep);
        form.add(vGap(4));

        // Status block: three tight labels
        JPanel statusBlock = new JPanel();
        statusBlock.setLayout(new BoxLayout(statusBlock, BoxLayout.Y_AXIS));
        statusBlock.setOpaque(false);
        statusBlock.setAlignmentX(Component.LEFT_ALIGNMENT);
        statusBlock.setBorder(new EmptyBorder(2, 0, 4, 0));
        for (JLabel l : new JLabel[]{lblStatus, lblTtl}) {
            l.setAlignmentX(Component.LEFT_ALIGNMENT);
            statusBlock.add(l);
        }
        statusBlock.setMaximumSize(new Dimension(Integer.MAX_VALUE, 56));
        form.add(statusBlock);

        // Token textarea
        taToken = new JTextArea(4, 50);
        taToken.setEditable(false);
        taToken.setLineWrap(true);
        taToken.setFont(burpMono());
        taToken.setVisible(false);
        JScrollPane tokenScroll = new JScrollPane(taToken);
        tokenScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 85));
        tokenScroll.setPreferredSize(new Dimension(400, 80));
        tokenScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        form.add(tokenScroll);

        // Row 2 (below token): [ Get Token ]  [ Copy Token ]  [ Disable Auto-Refresh ]
        btnFetch.addActionListener(e -> { if (doSave()) runFetch(selected, false); });
        btnCopy.addActionListener(e -> copyToken());

        JPanel bottomBtnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        bottomBtnRow.setOpaque(false);
        bottomBtnRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        bottomBtnRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 32));
        bottomBtnRow.add(btnFetch);
        bottomBtnRow.add(btnCopy);
        form.add(vGap(4));
        form.add(bottomBtnRow);

        return form;
    }

    // =========================================================================
    // Collapsible section builder
    // =========================================================================

    private JPanel collapsibleSection(String title, boolean startExpanded,
                                      java.util.function.Supplier<JPanel> bodyBuilder) {
        JPanel container = new JPanel();
        container.setLayout(new BoxLayout(container, BoxLayout.Y_AXIS));
        container.setOpaque(false);
        container.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel headerRow = new JPanel(new GridBagLayout());
        headerRow.setOpaque(false);
        headerRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        headerRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 26));
        headerRow.setBorder(new EmptyBorder(6, 0, 2, 0));

        JLabel arrow = new JLabel(startExpanded ? "▼" : "▶");
        arrow.setForeground(SECTION_FG);

        JLabel titleLbl = new JLabel(title);
        titleLbl.setFont(burpBold());
        titleLbl.setForeground(SECTION_FG);

        JSeparator sep = new JSeparator();

        GridBagConstraints gc = new GridBagConstraints();
        gc.gridy = 0; gc.anchor = GridBagConstraints.WEST; gc.fill = GridBagConstraints.NONE;
        gc.gridx = 0; gc.insets = new Insets(0, 0, 0, 5); headerRow.add(arrow, gc);
        gc.gridx = 1; gc.insets = new Insets(0, 0, 0, 8); headerRow.add(titleLbl, gc);
        gc.gridx = 2; gc.fill = GridBagConstraints.HORIZONTAL; gc.weightx = 1.0;
        gc.insets = new Insets(0, 0, 0, 0); headerRow.add(sep, gc);

        container.add(headerRow);

        JPanel body = bodyBuilder.get();
        body.setAlignmentX(Component.LEFT_ALIGNMENT);
        JPanel bodyWrapper = new JPanel();
        bodyWrapper.setLayout(new BoxLayout(bodyWrapper, BoxLayout.Y_AXIS));
        bodyWrapper.setOpaque(false);
        bodyWrapper.setBorder(new EmptyBorder(2, 10, 4, 0));
        bodyWrapper.add(body);
        bodyWrapper.setVisible(startExpanded);
        container.add(bodyWrapper);

        // Only the arrow and title are clickable — not the full-width separator area
        headerRow.setCursor(Cursor.getDefaultCursor());
        java.awt.event.MouseAdapter toggle = new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                boolean nowVisible = !bodyWrapper.isVisible();
                bodyWrapper.setVisible(nowVisible);
                arrow.setText(nowVisible ? "▼" : "▶");
                container.revalidate();
                container.repaint();
            }
        };
        arrow.addMouseListener(toggle);
        arrow.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        titleLbl.addMouseListener(toggle);
        titleLbl.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        return container;
    }

    // =========================================================================
    // Layout helpers
    // =========================================================================

    private JPanel sectionLabel(String text) {
        JLabel lbl = new JLabel(text);
        lbl.setFont(burpBold());
        lbl.setForeground(SECTION_FG);
        lbl.setBorder(new EmptyBorder(8, 0, 2, 0));
        JPanel p = new JPanel(new BorderLayout());
        p.add(lbl, BorderLayout.CENTER);
        p.add(new JSeparator(), BorderLayout.SOUTH);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, 26));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.setOpaque(false);
        return p;
    }

    private JPanel row(String label, JComponent input) { return row(label, input, null); }

    private JPanel row(String label, JComponent input, String tooltip) {
        JPanel p = new JPanel(new GridBagLayout());
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, 26));
        p.setBorder(new EmptyBorder(1, 0, 1, 0));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.setOpaque(false);

        GridBagConstraints lc = new GridBagConstraints();
        lc.gridx = 0; lc.gridy = 0; lc.anchor = GridBagConstraints.WEST;
        lc.fill = GridBagConstraints.NONE; lc.insets = new Insets(0, 0, 0, 8);
        JLabel lbl = new JLabel(label);
        lbl.setPreferredSize(new Dimension(210, 22));
        p.add(lbl, lc);

        GridBagConstraints fc = new GridBagConstraints();
        fc.gridx = 1; fc.gridy = 0; fc.anchor = GridBagConstraints.WEST;
        fc.fill = GridBagConstraints.HORIZONTAL; fc.weightx = 1.0;
        p.add(input, fc);

        // Always add the icon column so all input fields end at the same x position.
        // When there is no tooltip, add an invisible placeholder of the same width.
        GridBagConstraints ic = new GridBagConstraints();
        ic.gridx = 2; ic.gridy = 0; ic.anchor = GridBagConstraints.WEST;
        ic.fill = GridBagConstraints.NONE; ic.insets = new Insets(0, 5, 0, 0);
        if (tooltip != null) {
            JLabel icon = new JLabel("\u24d8");
            icon.setForeground(new Color(100, 140, 200));
            icon.setToolTipText(tooltip);
            icon.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            p.add(icon, ic);
        } else {
            JLabel spacer = new JLabel("\u24d8");
            spacer.setForeground(new Color(0, 0, 0, 0)); // fully transparent
            p.add(spacer, ic);
        }
        return p;
    }

    private JPanel rowWithLabel(JLabel lbl, JComponent input, String tooltip) {
        lbl.setPreferredSize(new Dimension(210, 22));
        return row_raw(lbl, input, tooltip);
    }

    private JPanel row_raw(JComponent label, JComponent input, String tooltip) {
        JPanel p = new JPanel(new GridBagLayout());
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, 26));
        p.setBorder(new EmptyBorder(1, 0, 1, 0));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.setOpaque(false);

        GridBagConstraints lc = new GridBagConstraints();
        lc.gridx = 0; lc.gridy = 0; lc.anchor = GridBagConstraints.WEST;
        lc.fill = GridBagConstraints.NONE; lc.insets = new Insets(0, 0, 0, 8);
        p.add(label, lc);

        GridBagConstraints fc = new GridBagConstraints();
        fc.gridx = 1; fc.gridy = 0; fc.anchor = GridBagConstraints.WEST;
        fc.fill = GridBagConstraints.HORIZONTAL; fc.weightx = 1.0;
        p.add(input, fc);

        GridBagConstraints ic = new GridBagConstraints();
        ic.gridx = 2; ic.gridy = 0; ic.anchor = GridBagConstraints.WEST;
        ic.insets = new Insets(0, 5, 0, 0);
        if (tooltip != null) {
            JLabel icon = new JLabel("\u24d8");
            icon.setForeground(new Color(100, 140, 200));
            icon.setToolTipText(tooltip);
            icon.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            p.add(icon, ic);
        } else {
            JLabel spacer = new JLabel("\u24d8");
            spacer.setForeground(new Color(0, 0, 0, 0));
            p.add(spacer, ic);
        }
        return p;
    }

    private JPanel inlineRow(JComponent c) {
        JPanel p = new JPanel(new GridBagLayout());
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, 26));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.setOpaque(false);
        GridBagConstraints gc = new GridBagConstraints();
        gc.gridx = 0; gc.gridy = 0; gc.anchor = GridBagConstraints.WEST;
        gc.fill = GridBagConstraints.NONE; gc.weightx = 0;
        p.add(c, gc);
        GridBagConstraints fill = new GridBagConstraints();
        fill.gridx = 1; fill.fill = GridBagConstraints.HORIZONTAL; fill.weightx = 1.0;
        p.add(Box.createHorizontalGlue(), fill);
        return p;
    }

    private JPanel stretchy(JComponent c, int height) {
        JPanel p = new JPanel(new GridBagLayout());
        p.setOpaque(false);
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, height));
        GridBagConstraints gc = new GridBagConstraints();
        gc.gridx = 0; gc.gridy = 0; gc.anchor = GridBagConstraints.WEST;
        gc.fill = GridBagConstraints.HORIZONTAL; gc.weightx = 1.0;
        p.add(c, gc);
        return p;
    }

    private Component vGap(int h) { return Box.createRigidArea(new Dimension(0, h)); }

    private JTextField   field()           { return new JTextField(); }
    private JPasswordField pwField() {
        JPasswordField f = new JPasswordField();
        f.setMaximumSize(new Dimension(Integer.MAX_VALUE, 24));
        return f;
    }
    private JLabel lbl(String text)        { return new JLabel(text); }
    private JButton btn(String text)       { return new JButton(text); }
    private JButton smallBtn(String text)  {
        JButton b = new JButton(text);
        b.setMargin(new Insets(2, 6, 2, 6));
        return b;
    }
    private JCheckBox chk(String text) {
        JCheckBox c = new JCheckBox(text); c.setOpaque(false); return c;
    }

    @SuppressWarnings("unchecked")
    private <T> JComboBox<T> combo(T[] items,
            java.util.function.Function<Object, String> labelFn) {
        JComboBox<T> cb = new JComboBox<>(items);
        cb.setRenderer((list, value, index, sel, focus) -> {
            JLabel l = new JLabel(value == null ? "" : labelFn.apply(value));
            l.setOpaque(true);
            l.setBackground(sel ? list.getSelectionBackground() : list.getBackground());
            l.setForeground(sel ? list.getSelectionForeground() : list.getForeground());
            return l;
        });
        return cb;
    }

    private static void setPlaceholder(JTextField field, String placeholder) {
        field.setForeground(Color.GRAY);
        field.setText(placeholder);
        field.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override public void focusGained(java.awt.event.FocusEvent e) {
                if (field.getText().equals(placeholder)) {
                    field.setText("");
                    field.setForeground(UIManager.getColor("TextField.foreground"));
                }
            }
            @Override public void focusLost(java.awt.event.FocusEvent e) {
                if (field.getText().isBlank()) {
                    field.setForeground(Color.GRAY);
                    field.setText(placeholder);
                }
            }
        });
    }

    // =========================================================================
    // Dynamic visibility
    // =========================================================================

    private void updateVisibility() {
        if (formPanel == null || cbGrant == null) return;

        OAuthProfile.GrantType grant = (OAuthProfile.GrantType) cbGrant.getSelectedItem();
        OAuthProfile.ClientAuthMethod auth = (OAuthProfile.ClientAuthMethod) cbAuth.getSelectedItem();
        boolean isJwt           = auth == OAuthProfile.ClientAuthMethod.PRIVATE_KEY_JWT;
        boolean isClientSecretJwt = auth == OAuthProfile.ClientAuthMethod.CLIENT_SECRET_JWT;
        boolean isAnyJwt          = isJwt || isClientSecretJwt;
        boolean anyInject = chkInjectProxy.isSelected() || chkInjectRepeater.isSelected()
                         || chkInjectIntruder.isSelected() || chkInjectScanner.isSelected();

        if (rowJwtAudience  != null) rowJwtAudience.setVisible(isAnyJwt);
        if (rowJwtAlgorithm != null) rowJwtAlgorithm.setVisible(isAnyJwt);
        if (rowJwtLifetime  != null) rowJwtLifetime.setVisible(isAnyJwt);
        // Filter algorithm dropdown to only show relevant algorithms
        if (cbJwtAlgorithm != null) updateAlgorithmChoices(isJwt, isClientSecretJwt);
        boolean isRopc = grant == OAuthProfile.GrantType.RESOURCE_OWNER_PASSWORD;
        if (rowRopcWarning  != null) rowRopcWarning.setVisible(isRopc);
        if (rowRopcUsername != null) rowRopcUsername.setVisible(isRopc);
        if (rowRopcPassword != null) rowRopcPassword.setVisible(isRopc);
        // Hide auth method fields for ROPC — username/password are the credentials
        if (rowAuthMethod != null) rowAuthMethod.setVisible(!isRopc);
        if (rowSecret     != null) rowSecret.setVisible(!isRopc && !isJwt);
        if (rowPrivateKey != null) rowPrivateKey.setVisible(!isRopc && isJwt);
        if (rowRefreshMode != null) rowRefreshMode.setVisible(true);
        if (pnlInjectionTools != null) pnlInjectionTools.setVisible(anyInject);
        if (lblScopesLabel != null) lblScopesLabel.setText("Scopes (optional)");

        formPanel.revalidate();
        formPanel.repaint();
    }

    // =========================================================================
    // Profile CRUD
    // =========================================================================

    private void onAdd() {
        String name = JOptionPane.showInputDialog(suiteFrame, "Profile name:");
        if (name == null || name.isBlank()) return;
        OAuthProfile p = new OAuthProfile(name.trim());
        profileModel.addElement(p);
        trafficHandler.addProfile(p);
        profileList.setSelectedValue(p, true);
    }

    private void onDelete() {
        OAuthProfile p = profileList.getSelectedValue();
        if (p == null) return;
        if (JOptionPane.showConfirmDialog(suiteFrame,
                "Delete '" + p.getName() + "'?", "Confirm",
                JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) return;
        profileModel.removeElement(p);
        trafficHandler.removeProfile(p.getName());
        tokenManager.clearToken(p.getName());
        if (profileStore != null) profileStore.saveAll(allProfiles());
        selected = null;
        showCard("empty");
    }

    private void onSelect(OAuthProfile p) {
        selected = p;
        if (p == null) { showCard("empty"); return; }
        populate(p);
        showCard("form");
        updateVisibility();
        TokenEntry t = tokenManager.getToken(p.getName());
        if (t != null) showToken(t);
        else {
            lblStatus.setText("No token.");
            lblStatus.setForeground(Color.GRAY);
            taToken.setVisible(false);
            btnCopy.setVisible(false);
            lblTtl.setText("");
            }
    }

    private void populate(OAuthProfile p) {
        tfName.setText(p.getName());
        tfTokenUrl.setText(p.getTokenUrl());
        tfClientId.setText(p.getClientId());
        pfSecret.setText(p.getClientSecret());
        taPrivateKey.setText(p.getPrivateKeyPem());
        tfJwtAudience.setText(p.getJwtAudience());
        cbJwtAlgorithm.setSelectedItem(p.getJwtAlgorithm());
        spJwtLifetime.setValue(p.getJwtLifetimeSeconds());
        tfScopes.setText(p.getScopes());
        tfHeaderName.setText(p.getHeaderName().isBlank() ? "Authorization" : p.getHeaderName());
        tfTokenPrefix.setText(p.getTokenPrefix().isBlank() ? "Bearer" : p.getTokenPrefix());
        chkInjectProxy.setSelected(p.isInjectProxy());
        chkInjectRepeater.setSelected(p.isInjectRepeater());
        chkInjectIntruder.setSelected(p.isInjectIntruder());
        chkInjectScanner.setSelected(p.isInjectScanner());
        chkInjectSequencer.setSelected(p.isInjectSequencer());
        chkInjectTarget.setSelected(p.isInjectTarget());
        chkInjectionEnabled.setSelected(p.isInjectionEnabled());
        cbHttpVersion.setSelectedItem(p.getHttpVersion() != null ? p.getHttpVersion() : "HTTP/1.1");
        // debug mode is global, not per-profile — no populate needed
        cbGrant.setSelectedItem(p.getGrantType());
        tfRopcUsername.setText(p.getRopcUsername());
        pfRopcPassword.setText(p.getRopcPassword());
        cbAuth.setSelectedItem(p.getClientAuthMethod());
        cbRefresh.setSelectedIndex(modeToIndex(p.getRefreshMode()));
        spRegenThreshold.setValue(p.getRegenThreshold());

        String codes = p.getScanCodes();
        if (codes == null || codes.isBlank()) setPlaceholder(tfScanCodes, "e.g. 401, 403");
        else { tfScanCodes.setForeground(UIManager.getColor("TextField.foreground")); tfScanCodes.setText(codes); }

        String phrase = p.getSessionPhrase();
        if (phrase == null || phrase.isBlank()) setPlaceholder(tfSessionPhrase, "e.g. invalid_token, session expired");
        else { tfSessionPhrase.setForeground(UIManager.getColor("TextField.foreground")); tfSessionPhrase.setText(phrase); }
    }

    private boolean doSave() {
        if (selected == null) return false;
        String err = validate();
        if (err != null) { showMessage(err); return false; }

        OAuthProfile p = selected;
        p.setName(tfName.getText().trim());
        p.setGrantType((OAuthProfile.GrantType) cbGrant.getSelectedItem());
        p.setRopcUsername(tfRopcUsername.getText().trim());
        p.setRopcPassword(new String(pfRopcPassword.getPassword()));
        p.setTokenUrl(tfTokenUrl.getText().trim());
        p.setClientId(tfClientId.getText().trim());
        p.setClientSecret(new String(pfSecret.getPassword()));
        p.setPrivateKeyPem(taPrivateKey.getText().trim());
        p.setJwtAudience(tfJwtAudience.getText().trim());
        p.setJwtAlgorithm((OAuthProfile.JwtAlgorithm) cbJwtAlgorithm.getSelectedItem());
        p.setJwtLifetimeSeconds((Integer) spJwtLifetime.getValue());
        p.setClientAuthMethod((OAuthProfile.ClientAuthMethod) cbAuth.getSelectedItem());
        p.setScopes(tfScopes.getText().trim());
        p.setHeaderName(tfHeaderName.getText().trim());
        p.setTokenPrefix(tfTokenPrefix.getText().trim());
        p.setInjectProxy(chkInjectProxy.isSelected());
        p.setInjectRepeater(chkInjectRepeater.isSelected());
        p.setInjectIntruder(chkInjectIntruder.isSelected());
        p.setInjectScanner(chkInjectScanner.isSelected());
        p.setInjectSequencer(chkInjectSequencer.isSelected());
        p.setInjectTarget(chkInjectTarget.isSelected());
        p.setInjectionEnabled(chkInjectionEnabled.isSelected());
        p.setHttpVersion((String) cbHttpVersion.getSelectedItem());
        p.setRefreshMode(indexToMode(cbRefresh.getSelectedIndex()));
        p.setScanEnabled(!tfScanCodes.getForeground().equals(Color.GRAY) || !tfSessionPhrase.getForeground().equals(Color.GRAY));
        String rawCodes = tfScanCodes.getText().trim();
        p.setScanCodes(tfScanCodes.getForeground().equals(Color.GRAY) ? "" : rawCodes);
        String rawPhrase = tfSessionPhrase.getText().trim();
        p.setSessionPhrase(tfSessionPhrase.getForeground().equals(Color.GRAY) ? "" : rawPhrase);
        p.setRegenEnabled(true);
        p.setRegenThreshold((Integer) spRegenThreshold.getValue());

        int idx = profileModel.indexOf(p);
        if (idx >= 0) profileModel.set(idx, p);
        trafficHandler.setProfiles(allProfiles());
        if (profileStore != null) profileStore.saveAll(allProfiles());
        return true;
    }

    private String validate() {
        if (tfName.getText().trim().isBlank())    return "Profile name is required.";
        if (tfTokenUrl.getText().trim().isBlank()) return "Token URL is required.";
        if (!isUrl(tfTokenUrl.getText().trim()))   return "Token URL must be a valid URL.";
        if (tfClientId.getText().trim().isBlank()) return "Client ID is required.";
        boolean anyInject = chkInjectProxy.isSelected() || chkInjectRepeater.isSelected()
                || chkInjectIntruder.isSelected() || chkInjectScanner.isSelected();
        if (anyInject && tfHeaderName.getText().trim().isBlank())
            return "Header name cannot be blank when injection is enabled.";
        return null;
    }

    // =========================================================================
    // Token fetch / display
    // =========================================================================

    private void runFetch(OAuthProfile profile, boolean isTest) {
        if (fetchInProgress) return;
        fetchInProgress = true;
        btnFetch.setEnabled(false);
        btnTest.setEnabled(false);
        String msg = "Fetching...";
        setStatus(msg, Color.GRAY);
        taToken.setVisible(false);
        btnCopy.setVisible(false);

        Thread w = new Thread(() -> {
            try {
                TokenEntry entry = oAuthClient.fetchToken(profile);
                if (isTest) {
                    SwingUtilities.invokeLater(() -> {
                        showToken(entry);
                        JOptionPane.showMessageDialog(suiteFrame,
                                "Success — token received.", "Test passed",
                                JOptionPane.INFORMATION_MESSAGE);
                    });
                } else {
                    tokenManager.storeToken(profile, entry);
                    SwingUtilities.invokeLater(() -> showToken(entry));
                }
            } catch (Exception ex) {
                String errMsg = friendlyError(ex.getMessage());
                api.logging().logToError("OAuth fetch failed: " + ex.getMessage());
                SwingUtilities.invokeLater(() -> {
                    setStatus("Error: " + errMsg, Color.RED);
                    if (isTest) JOptionPane.showMessageDialog(suiteFrame, errMsg,
                            "Test failed", JOptionPane.ERROR_MESSAGE);
                });
            } finally {
                fetchInProgress = false;
                SwingUtilities.invokeLater(() -> {
                    btnFetch.setEnabled(true);
                    btnTest.setEnabled(true);
                });
            }
        }, "oauth-fetch") {
            @Override public void run() {
                try { super.run(); }
                catch (Throwable t) {
                    java.io.StringWriter sw = new java.io.StringWriter();
                    t.printStackTrace(new java.io.PrintWriter(sw));
                    api.logging().logToError("[OAuth Helper] Unexpected error in fetch thread: " + sw);
                }
            }
        };
        w.setDaemon(true);
        w.start();
    }

    private void showToken(TokenEntry e) {
        taToken.setText(e.getAccessToken());
        taToken.setVisible(true);
        btnCopy.setVisible(true);
        btnFetch.setEnabled(true);
        btnTest.setEnabled(true);
        setStatus("Success!", new Color(0, 130, 0));
        updateTtl();
    }


    private void updateTtl() {
        if (selected == null) return;
        TokenEntry e = tokenManager.getToken(selected.getName());
        if (e == null || e.getExpiresAt() == null) { lblTtl.setText(""); return; }
        long r = e.secondsRemaining();
        String ttl = r >= 60 ? (r / 60) + "m " + (r % 60) + "s" : r + "s";
        lblTtl.setText("Expires in: " + ttl);
        lblTtl.setForeground(r < 60 ? Color.RED : r < 300 ? new Color(180, 100, 0) : Color.GRAY);
    }

    private void copyToken() {
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(taToken.getText()), null);
    }


    /**
     * Repopulate the algorithm dropdown with only the algorithms relevant to the
     * currently selected auth method. Preserves the current selection if compatible.
     */
    private void updateAlgorithmChoices(boolean isPrivateKey, boolean isClientSecret) {
        OAuthProfile.JwtAlgorithm current =
                (OAuthProfile.JwtAlgorithm) cbJwtAlgorithm.getSelectedItem();
        cbJwtAlgorithm.removeAllItems();
        if (isPrivateKey) {
            // Asymmetric algorithms only
            for (OAuthProfile.JwtAlgorithm a : new OAuthProfile.JwtAlgorithm[]{
                    OAuthProfile.JwtAlgorithm.RS256, OAuthProfile.JwtAlgorithm.RS384,
                    OAuthProfile.JwtAlgorithm.RS512, OAuthProfile.JwtAlgorithm.ES256,
                    OAuthProfile.JwtAlgorithm.ES384}) {
                cbJwtAlgorithm.addItem(a);
            }
            // Default to RS256 if current was HMAC
            if (current != null && !current.name().startsWith("H"))
                cbJwtAlgorithm.setSelectedItem(current);
            else
                cbJwtAlgorithm.setSelectedItem(OAuthProfile.JwtAlgorithm.RS256);
        } else if (isClientSecret) {
            // Symmetric algorithms only
            for (OAuthProfile.JwtAlgorithm a : new OAuthProfile.JwtAlgorithm[]{
                    OAuthProfile.JwtAlgorithm.HS256, OAuthProfile.JwtAlgorithm.HS384,
                    OAuthProfile.JwtAlgorithm.HS512}) {
                cbJwtAlgorithm.addItem(a);
            }
            // Default to HS256 if current was asymmetric
            if (current != null && current.name().startsWith("H"))
                cbJwtAlgorithm.setSelectedItem(current);
            else
                cbJwtAlgorithm.setSelectedItem(OAuthProfile.JwtAlgorithm.HS256);
        }
    }


    private void setStatus(String text, Color color) {
        lblStatus.setText(text);
        lblStatus.setForeground(color);
    }

    // =========================================================================
    // TokenChangeListener
    // =========================================================================

    @Override
    public void onTokenChanged(String profileName, TokenEntry entry) {
        SwingUtilities.invokeLater(() -> {
            if (selected != null && selected.getName().equals(profileName) && entry != null)
                showToken(entry);
        });
    }

    @Override
    public void onRefreshNeeded(OAuthProfile profile) {
        // Client Credentials cannot use refresh tokens (RFC 6749 §4.4).
        // Always re-fetch a fresh token using the stored credentials.
        if (profile.getRefreshMode() == OAuthProfile.RefreshMode.AUTO_SILENT) {
            runFetch(profile, false);
        }
    }


    // =========================================================================
    // Load profile from JSON
    // =========================================================================


    private void onExportProfile() {
        if (selected == null) { showMessage("Select a profile to export."); return; }
        if (!doSave()) return;

        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Export profile to JSON");
        String safeName = selected.getName().replaceAll("[^a-zA-Z0-9_-]", "_");
        fc.setSelectedFile(new java.io.File(safeName + ".json"));
        fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("JSON files", "json"));
        if (fc.showSaveDialog(suiteFrame) != JFileChooser.APPROVE_OPTION) return;

        try {
            String json = profileToJson(selected);
            java.io.File file = fc.getSelectedFile();
            if (!file.getName().endsWith(".json"))
                file = new java.io.File(file.getParentFile(), file.getName() + ".json");
            java.nio.file.Files.writeString(file.toPath(), json, java.nio.charset.StandardCharsets.UTF_8);
            api.logging().logToOutput("[OAuth Helper] Profile exported: " + file.getAbsolutePath());
        } catch (Exception ex) {
            showMessage("Export failed: " + ex.getMessage());
        }
    }

    private static String profileToJson(OAuthProfile p) {
        String q  = String.valueOf((char)34);
        String nl = String.valueOf((char)10);
        String co = ",";
        StringBuilder j = new StringBuilder("{" + nl);
        j.append(jfield(q, "name",             q + esc(p.getName())                      + q, true,  nl));
        j.append(jfield(q, "grantType",        q + esc(p.getGrantType().name())          + q, true,  nl));
        j.append(jfield(q, "clientAuthMethod", q + esc(p.getClientAuthMethod().name())   + q, true,  nl));
        j.append(jfield(q, "tokenUrl",         q + esc(p.getTokenUrl())                  + q, true,  nl));
        j.append(jfield(q, "clientId",         q + esc(p.getClientId())                  + q, true,  nl));
        j.append(jfield(q, "clientSecret",     q + esc(p.getClientSecret())              + q, true,  nl));
        j.append(jfield(q, "jwtAudience",    q + esc(p.getJwtAudience())              + q, true,  nl));
        j.append(jfield(q, "jwtAlgorithm",   q + esc(p.getJwtAlgorithm().name())         + q, true,  nl));
        j.append(jfield(q, "jwtLifetime",     String.valueOf(p.getJwtLifetimeSeconds()),       true,  nl));
        j.append(jfield(q, "ropcUsername",    q + esc(p.getRopcUsername())             + q, true,  nl));
        j.append(jfield(q, "ropcPassword",    q + esc(p.getRopcPassword())             + q, true,  nl));
        j.append(jfield(q, "scopes",           q + esc(p.getScopes())                    + q, true,  nl));
        j.append(jfield(q, "headerName",       q + esc(p.getHeaderName())                + q, true,  nl));
        j.append(jfield(q, "tokenPrefix",      q + esc(p.getTokenPrefix())               + q, true,  nl));
        j.append(jfield(q, "injectionEnabled", String.valueOf(p.isInjectionEnabled()),          true,  nl));
        j.append(jfield(q, "httpVersion",      q + esc(p.getHttpVersion())              + q, true,  nl));
        j.append(jfield(q, "injectProxy",      String.valueOf(p.isInjectProxy()),            true,  nl));
        j.append(jfield(q, "injectRepeater",   String.valueOf(p.isInjectRepeater()),          true,  nl));
        j.append(jfield(q, "injectIntruder",   String.valueOf(p.isInjectIntruder()),          true,  nl));
        j.append(jfield(q, "injectScanner",    String.valueOf(p.isInjectScanner()),           true,  nl));
        j.append(jfield(q, "injectSequencer",  String.valueOf(p.isInjectSequencer()),         true,  nl));
        j.append(jfield(q, "injectTarget",     String.valueOf(p.isInjectTarget()),            true,  nl));
        j.append(jfield(q, "refreshMode",      q + esc(p.getRefreshMode().name())        + q, true,  nl));
        j.append(jfield(q, "scanEnabled",      String.valueOf(p.isScanEnabled()),             true,  nl));
        j.append(jfield(q, "scanCodes",        q + esc(p.getScanCodes())                 + q, true,  nl));
        j.append(jfield(q, "sessionPhrase",    q + esc(p.getSessionPhrase())             + q, true,  nl));
        j.append(jfield(q, "regenEnabled",     String.valueOf(p.isRegenEnabled()),            true,  nl));
        j.append(jfield(q, "regenThreshold",   String.valueOf(p.getRegenThreshold()),         false, nl));
        j.append("}");
        return j.toString();
    }

    private static String jfield(String q, String key, String val, boolean comma, String nl) {
        return "  " + q + key + q + ": " + val + (comma ? "," : "") + nl;
    }

    private static String esc(String s) {
        if (s == null) return "";
        char bs = 92; char dq = 34;
        return s.replace(String.valueOf(bs), String.valueOf(bs) + bs)
                .replace(String.valueOf(dq), String.valueOf(bs) + dq);
    }

    private void onLoadProfile() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Load profile from JSON file");
        fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("JSON files", "json"));
        if (fc.showOpenDialog(suiteFrame) != JFileChooser.APPROVE_OPTION) return;
        try {
            String json = new String(java.nio.file.Files.readAllBytes(
                    fc.getSelectedFile().toPath()), java.nio.charset.StandardCharsets.UTF_8);
            String nameFromJson = jsonStr(json, "name");
            String profileName = (nameFromJson != null && !nameFromJson.isBlank())
                    ? nameFromJson
                    : fc.getSelectedFile().getName().replaceAll("\\.json$", "");
            OAuthProfile p = new OAuthProfile(profileName);
            applyJsonToProfile(json, p);
            profileModel.addElement(p);
            trafficHandler.addProfile(p);
            profileList.setSelectedValue(p, true);
            if (profileStore != null) profileStore.saveAll(allProfiles());
        } catch (Exception ex) {
            showMessage("Failed to load profile: " + ex.getMessage());
        }
    }

    private void applyJsonToProfile(String json, OAuthProfile p) {
        String s;
        String name = jsonStr(json, "name"); if (name != null) p.setName(name);
        String gt = jsonStr(json, "grantType");
        if (gt != null) try { p.setGrantType(OAuthProfile.GrantType.valueOf(gt)); } catch (IllegalArgumentException ignored) {}
        String am = jsonStr(json, "clientAuthMethod");
        if (am != null) try { p.setClientAuthMethod(OAuthProfile.ClientAuthMethod.valueOf(am)); } catch (IllegalArgumentException ignored) {}
        if ((s = jsonStr(json, "tokenUrl"))         != null) p.setTokenUrl(s);
        if ((s = jsonStr(json, "clientId"))          != null) p.setClientId(s);
        if ((s = jsonStr(json, "clientSecret"))      != null) p.setClientSecret(s);
        if ((s = jsonStr(json, "jwtAudience"))       != null) p.setJwtAudience(s);
        String ja = jsonStr(json, "jwtAlgorithm");
        if (ja != null) try { p.setJwtAlgorithm(OAuthProfile.JwtAlgorithm.valueOf(ja)); } catch (IllegalArgumentException ignored) {}
        String jl = jsonStr(json, "jwtLifetime");
        if (jl != null) try { p.setJwtLifetimeSeconds(Integer.parseInt(jl)); } catch (NumberFormatException ignored) {}
        if ((s = jsonStr(json, "ropcUsername"))  != null) p.setRopcUsername(s);
        if ((s = jsonStr(json, "ropcPassword"))  != null) p.setRopcPassword(s);
        if ((s = jsonStr(json, "scopes"))            != null) p.setScopes(s);
        if ((s = jsonStr(json, "headerName"))        != null) p.setHeaderName(s);
        if ((s = jsonStr(json, "tokenPrefix"))       != null) p.setTokenPrefix(s);
        if ((s = jsonStr(json, "scanCodes"))          != null) p.setScanCodes(s);
        if ((s = jsonStr(json, "sessionPhrase"))      != null) p.setSessionPhrase(s);
        String injectLegacy = jsonStr(json, "injectionEnabled");
        if (injectLegacy != null) { boolean v = Boolean.parseBoolean(injectLegacy);
            p.setInjectProxy(v); p.setInjectRepeater(v); p.setInjectIntruder(v); p.setInjectScanner(v); }
        String ienabled = jsonStr(json, "injectionEnabled"); if (ienabled != null) p.setInjectionEnabled(Boolean.parseBoolean(ienabled));
        String hv = jsonStr(json, "httpVersion"); if (hv != null) p.setHttpVersion(hv);
        String ip = jsonStr(json, "injectProxy");    if (ip != null) p.setInjectProxy(Boolean.parseBoolean(ip));
        String ir = jsonStr(json, "injectRepeater"); if (ir != null) p.setInjectRepeater(Boolean.parseBoolean(ir));
        String ii = jsonStr(json, "injectIntruder"); if (ii != null) p.setInjectIntruder(Boolean.parseBoolean(ii));
        String is = jsonStr(json, "injectScanner");  if (is != null) p.setInjectScanner(Boolean.parseBoolean(is));
        String ise = jsonStr(json, "injectSequencer"); if (ise != null) p.setInjectSequencer(Boolean.parseBoolean(ise));
        String it = jsonStr(json, "injectTarget");   if (it != null) p.setInjectTarget(Boolean.parseBoolean(it));
        String rf = jsonStr(json, "refreshMode");
        if (rf != null) try { p.setRefreshMode(OAuthProfile.RefreshMode.valueOf(rf)); } catch (IllegalArgumentException ignored) {}
    }

    // =========================================================================
    // Misc helpers
    // =========================================================================

    private void showCard(String name)     { ((CardLayout) rightPane.getLayout()).show(rightPane, name); }
    private void showMessage(String msg)   { JOptionPane.showMessageDialog(suiteFrame, msg); }

    private void logDebug(String msg) {
        if (chkDebugMode != null && chkDebugMode.isSelected())
            api.logging().logToOutput("[OAuth Helper] " + msg);
    }

    private List<OAuthProfile> allProfiles() {
        List<OAuthProfile> list = new java.util.ArrayList<>();
        for (int i = 0; i < profileModel.size(); i++) list.add(profileModel.get(i));
        return list;
    }

    private static int modeToIndex(OAuthProfile.RefreshMode m) {
        return switch (m) { case MANUAL -> 0; case AUTO_SILENT -> 1; };
    }
    private static OAuthProfile.RefreshMode indexToMode(int i) {
        return switch (i) { case 1 -> OAuthProfile.RefreshMode.AUTO_SILENT; default -> OAuthProfile.RefreshMode.MANUAL; };
    }
    private static String grantLabel(OAuthProfile.GrantType g) {
        return switch (g) {
            case CLIENT_CREDENTIALS    -> "Client Credentials";
            case RESOURCE_OWNER_PASSWORD -> "Resource Owner Password";
        };
    }
    private static String authLabel(OAuthProfile.ClientAuthMethod m) {
        return switch (m) {
            case HTTP_BASIC        -> "HTTP Basic";
            case POST_BODY         -> "POST Body (form fields)";
            case PRIVATE_KEY_JWT   -> "Private Key JWT";
            case CLIENT_SECRET_JWT -> "Client Secret JWT";
        };
    }
    private static String friendlyError(String raw) {
        if (raw == null) return "Unknown error.";
        String lo = raw.toLowerCase();
        if (lo.contains("401") || lo.contains("invalid_client") || lo.contains("unauthorized"))
            return "Invalid credentials (401). Check Client ID and secret.";
        if (lo.contains("invalid_grant")) return "Invalid grant — the code may have expired. Try again.";
        if (lo.contains("unsupported_grant")) return "Grant type not supported by the server.";
        if (lo.contains("invalid_scope") || lo.contains("scope")) return "Scope rejected by server.";
        if (lo.contains("403")) return "Forbidden (403). Check scopes and client permissions.";
        if (lo.contains("connection refused") || lo.contains("unknownhost"))
            return "Could not reach the token endpoint. Check the URL and network.";
        if (lo.contains("timeout")) return "Request timed out.";
        return raw.length() > 300 ? raw.substring(0, 300) + "..." : raw;
    }
    private static boolean isUrl(String s) {
        try { URI u = URI.create(s); return u.isAbsolute() && u.getScheme().startsWith("http"); }
        catch (Exception e) { return false; }
    }
    private static String jsonStr(String json, String key) {
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search); if (idx < 0) return null;
        int colon = json.indexOf(':', idx + search.length()); if (colon < 0) return null;
        int s = json.indexOf('"', colon + 1);
        if (s >= 0 && s < colon + 8) { int e = json.indexOf('"', s + 1); return e >= 0 ? json.substring(s + 1, e) : null; }
        int ns = colon + 1;
        while (ns < json.length() && Character.isWhitespace(json.charAt(ns))) ns++;
        int ne = ns;
        while (ne < json.length() && !",}\n".contains(String.valueOf(json.charAt(ne)))) ne++;
        String raw = json.substring(ns, ne).trim();
        return raw.isEmpty() ? null : raw;
    }
}
