package com.iwayvietnam.zmsso.pac4j;

import com.iwayvietnam.zmsso.pac4j.ZmCasLogoutActionBuilder;
import com.iwayvietnam.zmsso.pac4j.ZmLogoutHandler;
import com.iwayvietnam.zmsso.pac4j.ZmLogoutLogic;
import com.iwayvietnam.zmsso.pac4j.ZmOidcLogoutActionBuilder;
import com.iwayvietnam.zmsso.util.Log;
import com.zimbra.common.localconfig.LC;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.StringUtil;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import org.pac4j.cas.client.CasClient;
import org.pac4j.cas.config.CasConfiguration;
import org.pac4j.config.client.PropertiesConfigFactory;
import org.pac4j.core.client.Client;
import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.pac4j.core.config.ConfigFactory;
import org.pac4j.core.context.WebContextFactory;
import org.pac4j.core.context.session.SessionStoreFactory;
import org.pac4j.core.engine.CallbackLogic;
import org.pac4j.core.engine.DefaultCallbackLogic;
import org.pac4j.core.engine.LogoutLogic;
import org.pac4j.core.logout.LogoutActionBuilder;
import org.pac4j.core.logout.handler.LogoutHandler;
import org.pac4j.jee.context.JEEContextFactory;
import org.pac4j.jee.context.session.JEESessionStoreFactory;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.config.SAML2Configuration;

public class ConfigBuilder {
    private static ConfigBuilder instance;
    private static final Map<String, String> properties;
    private final ConfigFactory configFactory;
    private final Config config;
    private final ZmLogoutHandler logoutHandler;
    private final Boolean saveInSession;
    private final Boolean multiProfile;
    private final Boolean renewSession;
    private final Boolean localLogout;
    private final Boolean destroySession;
    private final Boolean centralLogout;
    private final String postLogoutURL;

    // --- Session sync fields (Phase 2) ---
    private final Boolean sessionSyncEnabled;
    private final Boolean backchannelEnabled;
    private final Integer heartbeatIntervalSeconds;
    private final Integer minimumServerIntervalSeconds;
    private final Integer activityGraceSeconds;
    private final Integer hiddenTabGraceSeconds;
    private final Integer refreshBeforeExpirySeconds;
    private final Integer transientFailureGraceSeconds;
    private final Integer maxTransientFailures;
    private final Boolean failClosed;
    private final Integer absoluteMaxSeconds;
    private final String allowedOrigin;
    private final Boolean watchdogEnabled;
    private final Integer watchdogIntervalSeconds;
    private final Integer watchdogBatchSize;

    private ConfigBuilder() {
        ConfigBuilder.loadSettingsFromProperties();
        this.configFactory = new PropertiesConfigFactory(ConfigBuilder.loadStringProperty(SettingsConstants.ZM_SSO_CALLBACK_URL), properties);
        this.logoutHandler = new ZmLogoutHandler();
        this.config = this.buildConfig();
        this.saveInSession = ConfigBuilder.loadBooleanProperty(SettingsConstants.ZM_SSO_SAVE_IN_SESSION);
        this.multiProfile = ConfigBuilder.loadBooleanProperty(SettingsConstants.ZM_SSO_MULTI_PROFILE);
        this.renewSession = ConfigBuilder.loadBooleanProperty(SettingsConstants.ZM_SSO_RENEW_SESSION);
        this.localLogout = ConfigBuilder.loadBooleanProperty(SettingsConstants.ZM_SSO_LOCAL_LOGOUT);
        this.destroySession = ConfigBuilder.loadBooleanProperty(SettingsConstants.ZM_SSO_DESTROY_SESSION);
        this.centralLogout = ConfigBuilder.loadBooleanProperty(SettingsConstants.ZM_SSO_CENTRAL_LOGOUT);
        this.postLogoutURL = ConfigBuilder.loadStringProperty(SettingsConstants.ZM_SSO_POST_LOGOUT_URL);

        // --- Session sync properties (Phase 2) ---
        this.sessionSyncEnabled = ConfigBuilder.loadBooleanProperty(SettingsConstants.ZM_SSO_SESSION_SYNC_ENABLED);
        this.backchannelEnabled = ConfigBuilder.loadBooleanProperty(SettingsConstants.ZM_SSO_SESSION_SYNC_BACKCHANNEL_ENABLED);
        this.heartbeatIntervalSeconds = ConfigBuilder.loadIntegerProperty(SettingsConstants.ZM_SSO_SESSION_SYNC_HEARTBEAT_INTERVAL_SECONDS, 60);
        this.minimumServerIntervalSeconds = ConfigBuilder.loadIntegerProperty(SettingsConstants.ZM_SSO_SESSION_SYNC_MINIMUM_SERVER_INTERVAL_SECONDS, 30);
        this.activityGraceSeconds = ConfigBuilder.loadIntegerProperty(SettingsConstants.ZM_SSO_SESSION_SYNC_ACTIVITY_GRACE_SECONDS, 1500);
        this.hiddenTabGraceSeconds = ConfigBuilder.loadIntegerProperty(SettingsConstants.ZM_SSO_SESSION_SYNC_HIDDEN_TAB_GRACE_SECONDS, 120);
        this.refreshBeforeExpirySeconds = ConfigBuilder.loadIntegerProperty(SettingsConstants.ZM_SSO_SESSION_SYNC_REFRESH_BEFORE_EXPIRY_SECONDS, 60);
        this.transientFailureGraceSeconds = ConfigBuilder.loadIntegerProperty(SettingsConstants.ZM_SSO_SESSION_SYNC_TRANSIENT_FAILURE_GRACE_SECONDS, 180);
        this.maxTransientFailures = ConfigBuilder.loadIntegerProperty(SettingsConstants.ZM_SSO_SESSION_SYNC_MAX_TRANSIENT_FAILURES, 3);
        this.failClosed = ConfigBuilder.loadBooleanProperty(SettingsConstants.ZM_SSO_SESSION_SYNC_FAIL_CLOSED);
        this.absoluteMaxSeconds = ConfigBuilder.loadIntegerProperty(SettingsConstants.ZM_SSO_SESSION_SYNC_ABSOLUTE_MAX_SECONDS, 0);
        this.allowedOrigin = ConfigBuilder.loadStringProperty(SettingsConstants.ZM_SSO_SESSION_SYNC_ALLOWED_ORIGIN);
        this.watchdogEnabled = ConfigBuilder.loadBooleanProperty(SettingsConstants.ZM_SSO_SESSION_SYNC_WATCHDOG_ENABLED);
        this.watchdogIntervalSeconds = ConfigBuilder.loadIntegerProperty(SettingsConstants.ZM_SSO_SESSION_SYNC_WATCHDOG_INTERVAL_SECONDS, 60);
        this.watchdogBatchSize = ConfigBuilder.loadIntegerProperty(SettingsConstants.ZM_SSO_SESSION_SYNC_WATCHDOG_BATCH_SIZE, 100);

        // --- Validation (Phase 2.2) ---
        this.validateSessionSync();
    }

    public static ConfigBuilder getInstance() {
        if (instance != null) return instance;
        synchronized (ConfigBuilder.class) {
            if (instance != null) return instance;
            instance = new ConfigBuilder();
            return instance;
        }
    }

    public Config getConfig() {
        return this.config;
    }

    public Clients getClients() {
        return this.config.getClients();
    }

    public Client defaultClient() throws ServiceException {
        return (Client) this.config.getClients()
                .findClient(ConfigBuilder.loadStringProperty(SettingsConstants.ZM_SSO_DEFAULT_CLIENT))
                .orElseThrow(() -> ServiceException.NOT_FOUND("No default client found"));
    }

    public ZmLogoutHandler getLogoutHandler() {
        return this.logoutHandler;
    }

    public Boolean getRenewSession() {
        return this.renewSession;
    }

    public Boolean getLocalLogout() {
        return this.localLogout;
    }

    public Boolean getDestroySession() {
        return this.destroySession;
    }

    public Boolean getCentralLogout() {
        return this.centralLogout;
    }

    public String getPostLogoutURL() {
        return this.postLogoutURL;
    }

    // --- Session sync getters (Phase 2) ---
    public Boolean getSessionSyncEnabled() {
        return this.sessionSyncEnabled;
    }

    public Boolean getBackchannelEnabled() {
        return this.backchannelEnabled;
    }

    public Integer getHeartbeatIntervalSeconds() {
        return this.heartbeatIntervalSeconds;
    }

    public Integer getMinimumServerIntervalSeconds() {
        return this.minimumServerIntervalSeconds;
    }

    public Integer getActivityGraceSeconds() {
        return this.activityGraceSeconds;
    }

    public Integer getHiddenTabGraceSeconds() {
        return this.hiddenTabGraceSeconds;
    }

    public Integer getRefreshBeforeExpirySeconds() {
        return this.refreshBeforeExpirySeconds;
    }

    public Integer getTransientFailureGraceSeconds() {
        return this.transientFailureGraceSeconds;
    }

    public Integer getMaxTransientFailures() {
        return this.maxTransientFailures;
    }

    public Boolean getFailClosed() {
        return this.failClosed;
    }

    public Integer getAbsoluteMaxSeconds() {
        return this.absoluteMaxSeconds;
    }

    public String getAllowedOrigin() {
        return this.allowedOrigin;
    }

    public Boolean getWatchdogEnabled() {
        return this.watchdogEnabled;
    }

    public Integer getWatchdogIntervalSeconds() {
        return this.watchdogIntervalSeconds;
    }

    public Integer getWatchdogBatchSize() {
        return this.watchdogBatchSize;
    }

    private Config buildConfig() {
        Log.sso.info((Object) "Build Pac4J config");
        Config config = this.configFactory.build(new Object[0]);
        config.getClients().findClient(CasClient.class).ifPresent(casClient -> {
            Log.sso.info((Object) "Config cas client");
            CasConfiguration casConfiguration = casClient.getConfiguration();
            casConfiguration.setLogoutHandler((LogoutHandler) this.logoutHandler);
            Optional.ofNullable(ConfigBuilder.loadStringProperty(SettingsConstants.ZM_CAS_CALLBACK_URL))
                    .ifPresent(url -> ((CasClient) casClient).setCallbackUrl(url));
            String string = casConfiguration.computeFinalPrefixUrl(null) + "logout";
            casClient.setLogoutActionBuilder((LogoutActionBuilder) new ZmCasLogoutActionBuilder(string, casConfiguration.getPostLogoutUrlParameter(), this.getPostLogoutURL()));
            casClient.setMultiProfile(Boolean.TRUE.equals(this.multiProfile));
            casClient.setSaveProfileInSession(Boolean.TRUE.equals(this.saveInSession));
        });
        config.getClients().findClient(OidcClient.class).ifPresent(oidcClient -> {
            Log.sso.info((Object) "Config oidc client");
            OidcConfiguration oidcConfiguration = oidcClient.getConfiguration();
            oidcConfiguration.setLogoutHandler((LogoutHandler) this.logoutHandler);
            Optional.ofNullable(ConfigBuilder.loadStringProperty(SettingsConstants.ZM_OIDC_CALLBACK_URL))
                    .ifPresent(url -> ((OidcClient) oidcClient).setCallbackUrl(url));
            oidcClient.setLogoutActionBuilder((LogoutActionBuilder) new ZmOidcLogoutActionBuilder(oidcClient.getConfiguration(), this.getPostLogoutURL()));
            oidcClient.setMultiProfile(Boolean.TRUE.equals(this.multiProfile));
            oidcClient.setSaveProfileInSession(Boolean.TRUE.equals(this.saveInSession));
        });
        config.getClients().findClient(SAML2Client.class).ifPresent(sAML2Client -> {
            Log.sso.info((Object) "Config saml client");
            SAML2Configuration sAML2Configuration = sAML2Client.getConfiguration();
            sAML2Configuration.setLogoutHandler((LogoutHandler) this.logoutHandler);
            sAML2Configuration.setForceServiceProviderMetadataGeneration(true);
            sAML2Configuration.setSignMetadata(true);
            sAML2Configuration.setForceKeystoreGeneration(false);
            sAML2Configuration.setSpLogoutRequestSigned(ConfigBuilder.loadBooleanProperty(SettingsConstants.ZM_SAML_LOGOUT_REQUEST_SIGNED).booleanValue());
            sAML2Configuration.setAllSignatureValidationDisabled(ConfigBuilder.loadBooleanProperty(SettingsConstants.ZM_SAML_ALL_SIGNATURE_VALIDATION_DISABLED).booleanValue());
            Optional.ofNullable(ConfigBuilder.loadStringProperty(SettingsConstants.ZM_SAML_LOGOUT_REQUEST_BINDING))
                    .ifPresent(url -> sAML2Configuration.setSpLogoutRequestBindingType(url));
            Optional.ofNullable(ConfigBuilder.loadStringProperty(SettingsConstants.ZM_SAML_LOGOUT_RESPONSE_BINDING))
                    .ifPresent(url -> sAML2Configuration.setSpLogoutResponseBindingType(url));
            String string = Optional.ofNullable(this.getPostLogoutURL()).orElse("/");
            sAML2Configuration.setPostLogoutURL(string);
            Optional.ofNullable(ConfigBuilder.loadStringProperty(SettingsConstants.ZM_SAML_CALLBACK_URL))
                    .ifPresent(url -> ((SAML2Client) sAML2Client).setCallbackUrl(url));
            sAML2Client.setMultiProfile(Boolean.TRUE.equals(this.multiProfile));
            sAML2Client.setSaveProfileInSession(Boolean.TRUE.equals(this.saveInSession));
        });
        config.setSessionStoreFactory((SessionStoreFactory) JEESessionStoreFactory.INSTANCE);
        config.setWebContextFactory((WebContextFactory) JEEContextFactory.INSTANCE);
        config.setCallbackLogic((CallbackLogic) DefaultCallbackLogic.INSTANCE);
        config.setLogoutLogic((LogoutLogic) ZmLogoutLogic.INSTANCE);
        return config;
    }

    public static String loadStringProperty(String string) {
        return properties.get(string);
    }

    public static Boolean loadBooleanProperty(String string) {
        String string2 = properties.get(string);
        if (!StringUtil.isNullOrEmpty((String) string2)) {
            return Boolean.parseBoolean(string2.trim());
        }
        return false;
    }

    private static Integer loadIntegerProperty(String key, int defaultValue) {
        String value = properties.get(key);
        if (!StringUtil.isNullOrEmpty((String) value)) {
            try {
                return Integer.parseInt(value.trim());
            } catch (NumberFormatException e) {
                Log.sso.error((Object) ("Invalid integer for property '" + key + "': " + value + ", using default: " + defaultValue));
                return defaultValue;
            }
        }
        return defaultValue;
    }

    private static void loadSettingsFromProperties() {
        Log.sso.info((Object) "Load config properties");
        try {
            String string2 = Paths.get(LC.zimbra_home.value(), "conf").toString();
            Properties properties = new Properties();
            properties.load(new FileInputStream(string2 + "/zm.sso.properties"));
            properties.stringPropertyNames().forEach(string -> ConfigBuilder.properties.put((String) string, properties.getProperty((String) string)));
        } catch (IOException iOException) {
            Log.sso.error((Object) iOException);
        }
    }

    // --- Validation (Phase 2.2) ---

    private void validateSessionSync() {
        // Always: reject negative values
        if (this.heartbeatIntervalSeconds < 0) {
            throw new RuntimeException("oidc.sessionSync.heartbeatIntervalSeconds cannot be negative");
        }
        if (this.minimumServerIntervalSeconds < 0) {
            throw new RuntimeException("oidc.sessionSync.minimumServerIntervalSeconds cannot be negative");
        }
        if (this.activityGraceSeconds < 0) {
            throw new RuntimeException("oidc.sessionSync.activityGraceSeconds cannot be negative");
        }
        if (this.hiddenTabGraceSeconds < 0) {
            throw new RuntimeException("oidc.sessionSync.hiddenTabGraceSeconds cannot be negative");
        }
        if (this.refreshBeforeExpirySeconds < 0) {
            throw new RuntimeException("oidc.sessionSync.refreshBeforeExpirySeconds cannot be negative");
        }
        if (this.transientFailureGraceSeconds < 0) {
            throw new RuntimeException("oidc.sessionSync.transientFailureGraceSeconds cannot be negative");
        }
        if (this.maxTransientFailures < 0) {
            throw new RuntimeException("oidc.sessionSync.maxTransientFailures cannot be negative");
        }
        if (this.absoluteMaxSeconds < 0) {
            throw new RuntimeException("oidc.sessionSync.absoluteMaxSeconds cannot be negative");
        }
        if (this.watchdogIntervalSeconds < 0) {
            throw new RuntimeException("oidc.sessionSync.watchdogIntervalSeconds cannot be negative");
        }
        if (this.watchdogBatchSize <= 0) {
            throw new RuntimeException("oidc.sessionSync.watchdogBatchSize must be greater than zero");
        }

        // Always: reject heartbeat below minimum safe
        if (this.heartbeatIntervalSeconds < this.minimumServerIntervalSeconds) {
            throw new RuntimeException(
                    "oidc.sessionSync.heartbeatIntervalSeconds (" + this.heartbeatIntervalSeconds
                            + ") must be >= minimumServerIntervalSeconds (" + this.minimumServerIntervalSeconds + ")");
        }

        // When enabled: additional checks
        if (Boolean.TRUE.equals(this.sessionSyncEnabled)) {
            String defaultClient = ConfigBuilder.loadStringProperty(SettingsConstants.ZM_SSO_DEFAULT_CLIENT);
            if (!"OidcClient".equals(defaultClient)) {
                throw new RuntimeException(
                        "oidc.sessionSync.enabled=true requires sso.defaultClient=OidcClient, but found: " + defaultClient);
            }
            if (StringUtil.isNullOrEmpty((String) this.allowedOrigin)) {
                throw new RuntimeException(
                        "oidc.sessionSync.allowedOrigin must be set when oidc.sessionSync.enabled=true");
            }
            Log.sso.info((Object) "Session sync is ENABLED");
        }
    }

    static {
        properties = new HashMap<String, String>();
    }
}
