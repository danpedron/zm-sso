package com.iwayvietnam.zmsso;

import com.iwayvietnam.zmsso.CallbackHandler;
import com.iwayvietnam.zmsso.KeepAliveHandler;
import com.iwayvietnam.zmsso.KeepAliveJsHandler;
import com.iwayvietnam.zmsso.LoginHandler;
import com.iwayvietnam.zmsso.LogoutHandler;
import com.iwayvietnam.zmsso.cas.CasCallbackHandler;
import com.iwayvietnam.zmsso.cas.CasLoginHandler;
import com.iwayvietnam.zmsso.db.DbSsoSession;
import com.iwayvietnam.zmsso.oidc.OidcBackchannelLogoutHandler;
import com.iwayvietnam.zmsso.oidc.OidcCallbackHandler;
import com.iwayvietnam.zmsso.oidc.OidcLoginHandler;
import com.iwayvietnam.zmsso.pac4j.ConfigBuilder;
import com.iwayvietnam.zmsso.saml.SamlCallbackHandler;
import com.iwayvietnam.zmsso.saml.SamlLoginHandler;
import com.iwayvietnam.zmsso.saml.SamlMetadataHandler;
import com.iwayvietnam.zmsso.saml.SamlSloHandler;
import com.iwayvietnam.zmsso.service.GetAllSsoSessions;
import com.iwayvietnam.zmsso.util.Log;
import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.extension.ExtensionDispatcherServlet;
import com.zimbra.cs.extension.ExtensionException;
import com.zimbra.cs.extension.ExtensionHttpHandler;
import com.zimbra.cs.extension.ZimbraExtension;
import com.zimbra.soap.DocumentHandler;
import com.zimbra.soap.SoapServlet;

    public class ZmSsoExtension
    implements ZimbraExtension {
        public static final String E_GET_ALL_SSO_SESSIONS_REQUEST = "GetAllSsoSessionsRequest";
        public static final String E_GET_ALL_SSO_SESSIONS_RESPONSE = "GetAllSsoSessionsResponse";
        private static final String EXTENSION_NAME = "com_iwayvietnam_zmsso";

        // Phase 4: Watchdog reference for clean shutdown
        private SessionSyncWatchdog watchdog;

    public String getName() {
        return EXTENSION_NAME;
    }

    public void init() throws ExtensionException, ServiceException {
        DbSsoSession.createSsoSessionTable();
        Log.sso.info((Object) "Register sso handlers");
        ExtensionDispatcherServlet.register((ZimbraExtension) this, (ExtensionHttpHandler) new LoginHandler());
        ExtensionDispatcherServlet.register((ZimbraExtension) this, (ExtensionHttpHandler) new CallbackHandler());
        ExtensionDispatcherServlet.register((ZimbraExtension) this, (ExtensionHttpHandler) new LogoutHandler());
        ExtensionDispatcherServlet.register((ZimbraExtension) this, (ExtensionHttpHandler) new KeepAliveHandler());
        try {
            Log.sso.info((Object) "Register saml sso handlers");
            ExtensionDispatcherServlet.register((ZimbraExtension) this, (ExtensionHttpHandler) new SamlMetadataHandler());
            ExtensionDispatcherServlet.register((ZimbraExtension) this, (ExtensionHttpHandler) new SamlLoginHandler());
            ExtensionDispatcherServlet.register((ZimbraExtension) this, (ExtensionHttpHandler) new SamlCallbackHandler());
            ExtensionDispatcherServlet.register((ZimbraExtension) this, (ExtensionHttpHandler) new SamlSloHandler());
        } catch (ExtensionException extensionException) {
            Log.sso.error((Object) extensionException);
        }
        try {
            Log.sso.info((Object) "Register cas sso handlers");
            ExtensionDispatcherServlet.register((ZimbraExtension) this, (ExtensionHttpHandler) new CasLoginHandler());
            ExtensionDispatcherServlet.register((ZimbraExtension) this, (ExtensionHttpHandler) new CasCallbackHandler());
        } catch (ExtensionException extensionException) {
            Log.sso.error((Object) extensionException);
        }
        try {
            Log.sso.info((Object) "Register oidc sso handlers");
            ExtensionDispatcherServlet.register((ZimbraExtension) this, (ExtensionHttpHandler) new OidcLoginHandler());
            ExtensionDispatcherServlet.register((ZimbraExtension) this, (ExtensionHttpHandler) new OidcCallbackHandler());

            // Phase 3: Register dedicated back-channel logout handler (only when enabled)
            ConfigBuilder configBuilder = ConfigBuilder.getInstance();
            if (configBuilder.getBackchannelEnabled()) {
                Log.sso.info((Object) "Register back-channel logout handler");
                ExtensionDispatcherServlet.register((ZimbraExtension) this, (ExtensionHttpHandler) new OidcBackchannelLogoutHandler());
            } else {
                Log.sso.info((Object) "Back-channel logout disabled, skipping handler registration");
            }
        } catch (ExtensionException extensionException) {
            Log.sso.error((Object) extensionException);
        }

        // Phase 4: Register keepalive JS handler (only when sessionSync enabled)
        ConfigBuilder configBuilder = ConfigBuilder.getInstance();
        if (configBuilder.getSessionSyncEnabled()) {
            Log.sso.info((Object) "Register keepalive JS handler");
            try {
                ExtensionDispatcherServlet.register((ZimbraExtension) this, (ExtensionHttpHandler) new KeepAliveJsHandler());
            } catch (ServiceException e) {
                Log.sso.error((Object) e);
            }
        } else {
            Log.sso.info((Object) "Session sync disabled, skipping keepalive JS handler registration");
        }

        // Phase 4: Start watchdog thread (only when watchdogEnabled)
        if (configBuilder.getWatchdogEnabled()) {
            Log.sso.info((Object) "Starting session sync watchdog");
            this.watchdog = new SessionSyncWatchdog();
            this.watchdog.start();
        } else {
            Log.sso.info((Object) "Watchdog disabled, not starting");
        }

        SoapServlet.addService((String) "AdminServlet", documentDispatcher -> {
            Log.sso.info((Object) "Register admin soap services");
            documentDispatcher.registerHandler(GetAllSsoSessions.GET_ALL_SSO_SESSIONS_REQUEST, (DocumentHandler) new GetAllSsoSessions());
        });
    }

    public void destroy() {
        Log.sso.info((Object) "Unregister sso extension");
        // Phase 4: Stop watchdog thread
        if (this.watchdog != null) {
            this.watchdog.stop();
        }
        ExtensionDispatcherServlet.unregister((ZimbraExtension) this);
    }
}
