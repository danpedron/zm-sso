package com.iwayvietnam.zmsso.pac4j;

public final class SettingsConstants {
    public static final String ZM_SSO_SETTINGS_FILE = "zm.sso.properties";
    public static final String ZM_SSO_DEFAULT_CLIENT = "sso.defaultClient";
    public static final String ZM_SSO_CALLBACK_URL = "sso.callbackUrl";
    public static final String ZM_CAS_CALLBACK_URL = "cas.callbackUrl";
    public static final String ZM_SAML_CALLBACK_URL = "saml.callbackUrl";
    public static final String ZM_OIDC_CALLBACK_URL = "oidc.callbackUrl";
    public static final String ZM_SSO_SAVE_IN_SESSION = "sso.saveInSession";
    public static final String ZM_SSO_MULTI_PROFILE = "sso.multiProfile";
    public static final String ZM_SSO_RENEW_SESSION = "sso.renewSession";
    public static final String ZM_SSO_LOCAL_LOGOUT = "sso.localLogout";
    public static final String ZM_SSO_DESTROY_SESSION = "sso.destroySession";
    public static final String ZM_SSO_CENTRAL_LOGOUT = "sso.centralLogout";
    public static final String ZM_SSO_POST_LOGOUT_URL = "sso.postLogoutURL";
    public static final String ZM_SAML_LOGOUT_REQUEST_BINDING = "saml.spLogoutRequestBindingType";
    public static final String ZM_SAML_LOGOUT_RESPONSE_BINDING = "saml.spLogoutResponseBindingType";
    public static final String ZM_SAML_LOGOUT_REQUEST_SIGNED = "saml.logoutRequestSigned";
    public static final String ZM_SAML_ALL_SIGNATURE_VALIDATION_DISABLED = "saml.allSignatureValidationDisabled";
    public static final String SSO_CLIENT_NAME_SESSION_ATTR = "sso.ClientName";
    public static final String SSO_PROFILE_SESSION_ATTR = "sso.Profile";

    // --- Session sync feature flags (Phase 2) ---
    public static final String ZM_SSO_SESSION_SYNC_ENABLED = "oidc.sessionSync.enabled";
    public static final String ZM_SSO_SESSION_SYNC_BACKCHANNEL_ENABLED = "oidc.sessionSync.backchannelEnabled";

    // --- Heartbeat timing ---
    public static final String ZM_SSO_SESSION_SYNC_HEARTBEAT_INTERVAL_SECONDS = "oidc.sessionSync.heartbeatIntervalSeconds";
    public static final String ZM_SSO_SESSION_SYNC_MINIMUM_SERVER_INTERVAL_SECONDS = "oidc.sessionSync.minimumServerIntervalSeconds";
    public static final String ZM_SSO_SESSION_SYNC_ACTIVITY_GRACE_SECONDS = "oidc.sessionSync.activityGraceSeconds";
    public static final String ZM_SSO_SESSION_SYNC_HIDDEN_TAB_GRACE_SECONDS = "oidc.sessionSync.hiddenTabGraceSeconds";
    public static final String ZM_SSO_SESSION_SYNC_REFRESH_BEFORE_EXPIRY_SECONDS = "oidc.sessionSync.refreshBeforeExpirySeconds";

    // --- Transient failure handling ---
    public static final String ZM_SSO_SESSION_SYNC_TRANSIENT_FAILURE_GRACE_SECONDS = "oidc.sessionSync.transientFailureGraceSeconds";
    public static final String ZM_SSO_SESSION_SYNC_MAX_TRANSIENT_FAILURES = "oidc.sessionSync.maxTransientFailures";
    public static final String ZM_SSO_SESSION_SYNC_FAIL_CLOSED = "oidc.sessionSync.failClosed";

    // --- Absolute limits ---
    public static final String ZM_SSO_SESSION_SYNC_ABSOLUTE_MAX_SECONDS = "oidc.sessionSync.absoluteMaxSeconds";
    public static final String ZM_SSO_SESSION_SYNC_ALLOWED_ORIGIN = "oidc.sessionSync.allowedOrigin";

    // --- Watchdog ---
    public static final String ZM_SSO_SESSION_SYNC_WATCHDOG_ENABLED = "oidc.sessionSync.watchdogEnabled";
    public static final String ZM_SSO_SESSION_SYNC_WATCHDOG_INTERVAL_SECONDS = "oidc.sessionSync.watchdogIntervalSeconds";
    public static final String ZM_SSO_SESSION_SYNC_WATCHDOG_BATCH_SIZE = "oidc.sessionSync.watchdogBatchSize";

    // --- Back-channel logout token validation (Phase 3) ---
    public static final String ZM_OIDC_LOGOUT_TOKEN_ISSUER = "oidc.logoutToken.issuer";
    public static final String ZM_OIDC_LOGOUT_TOKEN_CLIENT_ID = "oidc.logoutToken.clientId";
    public static final String ZM_OIDC_LOGOUT_TOKEN_JWS_ALGORITHM = "oidc.logoutToken.jwsAlgorithm";
    public static final String ZM_OIDC_LOGOUT_TOKEN_JWKS_URL = "oidc.logoutToken.jwksUrl";
}
