package com.iwayvietnam.zmsso;

import com.iwayvietnam.zmsso.pac4j.ConfigBuilder;
import com.iwayvietnam.zmsso.pac4j.ZmLogoutHandler;
import com.iwayvietnam.zmsso.util.Log;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ByteUtil;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.Server;
import com.zimbra.cs.extension.ExtensionHttpHandler;
import com.zimbra.cs.servlet.util.AuthUtil;
import java.io.IOException;
import java.text.ParseException;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.pac4j.core.client.Client;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.exception.http.HttpAction;
import org.pac4j.core.http.adapter.HttpActionAdapter;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.jee.context.JEEContext;
import org.pac4j.jee.http.adapter.JEEHttpActionAdapter;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.profile.OidcProfile;

public abstract class BaseSsoHandler
extends ExtensionHttpHandler {
    protected final ConfigBuilder configBuilder = ConfigBuilder.getInstance();
    private static final int SESSION_TIMEOUT_SECONDS = 1800;

    protected void doLogin(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Client client) throws IOException, ServiceException {
        block11: {
            BaseSsoHandler.extendSessionTimeout(httpServletRequest);
            if (!this.isLoggedIn(httpServletRequest)) {
                Log.sso.info("SSO login with: %s", new Object[]{client.getName()});
                httpServletRequest.getSession().setAttribute("sso.ClientName", (Object) client.getName());
                Config config = this.configBuilder.getConfig();
                WebContext webContext = config.getWebContextFactory().newContext(new Object[]{httpServletRequest, httpServletResponse});
                SessionStore sessionStore = config.getSessionStoreFactory().newSessionStore(new Object[0]);
                client.getRedirectionAction(webContext, sessionStore).ifPresent(redirectionAction -> JEEHttpActionAdapter.INSTANCE.adapt((HttpAction) redirectionAction, webContext));
            } else if (client instanceof OidcClient) {
                OidcClient oidcClient = (OidcClient) client;
                HttpSession httpSession = httpServletRequest.getSession(false);
                if (httpSession != null) {
                    OidcProfile oidcProfile;
                    CommonProfile commonProfile = (CommonProfile) httpSession.getAttribute("sso.Profile");
                    if (commonProfile instanceof OidcProfile && (oidcProfile = (OidcProfile) commonProfile).isExpired()) {
                        Log.sso.info("SSO login: OIDC profile expired for client: %s, attempting token refresh", new Object[]{client.getName()});
                        Config config = this.configBuilder.getConfig();
                        WebContext webContext = config.getWebContextFactory().newContext(new Object[]{httpServletRequest, httpServletResponse});
                        SessionStore sessionStore = config.getSessionStoreFactory().newSessionStore(new Object[0]);
                        try {
                            Optional<UserProfile> optional = oidcClient.renewUserProfile((UserProfile) oidcProfile, webContext, sessionStore);
                            if (optional.isPresent()) {
                                Log.sso.info((Object) "SSO login: OIDC token refreshed successfully, redirecting to mail");
                                httpSession.setAttribute("sso.Profile", optional.get());
                                this.redirectToMail(httpServletRequest, httpServletResponse);
                                break block11;
                            }
                            Log.sso.info((Object) "SSO login: OIDC token refresh failed, forcing re-authentication");
                            httpSession.removeAttribute("sso.Profile");
                            this.doOidcLoginRedirect(httpServletRequest, httpServletResponse, client, httpSession);
                        } catch (Exception exception) {
                            Log.sso.warn("SSO login: OIDC token refresh threw exception: %s", new Object[]{exception.getMessage()});
                            httpSession.removeAttribute("sso.Profile");
                            this.doOidcLoginRedirect(httpServletRequest, httpServletResponse, client, httpSession);
                        }
                    } else {
                        this.redirectToMail(httpServletRequest, httpServletResponse);
                    }
                } else {
                    this.redirectToMail(httpServletRequest, httpServletResponse);
                }
            } else {
                this.redirectToMail(httpServletRequest, httpServletResponse);
            }
        }
    }

    private void doOidcLoginRedirect(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Client client, HttpSession httpSession) throws IOException {
        httpSession.setAttribute("sso.ClientName", (Object) client.getName());
        Config config = this.configBuilder.getConfig();
        WebContext webContext = config.getWebContextFactory().newContext(new Object[]{httpServletRequest, httpServletResponse});
        SessionStore sessionStore = config.getSessionStoreFactory().newSessionStore(new Object[0]);
        client.getRedirectionAction(webContext, sessionStore).ifPresent(redirectionAction -> JEEHttpActionAdapter.INSTANCE.adapt((HttpAction) redirectionAction, webContext));
    }

    protected void doCallback(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Client client) {
        Log.sso.info("SSO callback with: %s", new Object[]{client.getName()});
        Boolean bl = this.configBuilder.getRenewSession();
        Config config = this.configBuilder.getConfig();
        WebContext webContext = config.getWebContextFactory().newContext(new Object[]{httpServletRequest, httpServletResponse});
        SessionStore sessionStore = config.getSessionStoreFactory().newSessionStore(new Object[0]);
        config.getCallbackLogic().perform(webContext, sessionStore, config, (HttpActionAdapter) JEEHttpActionAdapter.INSTANCE, "/", bl, client.getName());
        Log.sso.info("SSO callback is performed with: %s", new Object[]{client.getName()});
        ProfileManager profileManager = new ProfileManager(webContext, sessionStore);
        profileManager.setConfig(config);
        profileManager.getProfile(CommonProfile.class).ifPresent(commonProfile -> {
            httpServletRequest.getSession().setAttribute("sso.Profile", commonProfile);
            ZmLogoutHandler zmLogoutHandler = this.configBuilder.getLogoutHandler();
            String accountName = Optional.ofNullable(commonProfile.getEmail()).orElse(commonProfile.getId());
            String pac4jSessionId = sessionStore.getSessionId(webContext, true).orElse("");
            String sessionKey = (String) zmLogoutHandler.getStore().get(pac4jSessionId).orElse(pac4jSessionId);

            // Phase 3: Extract sid from OIDC profile for back-channel logout session mapping
            String sidHash = null;
            if (commonProfile instanceof OidcProfile) {
                try {
                    String sid = ((OidcProfile) commonProfile).getIdToken().getJWTClaimsSet().getStringClaim("sid");
                    if (sid != null && !sid.isEmpty()) {
                        sidHash = ByteUtil.getSHA256Digest(sid.getBytes(), false);
                    }
                } catch (ParseException e) {
                    Log.sso.warn("Failed to extract sid from OIDC profile: " + e.getMessage());
                }
            }

            try {
                if (sidHash != null) {
                    zmLogoutHandler.singleLogin(webContext, accountName, sessionKey, commonProfile.getClientName(), sidHash);
                } else {
                    zmLogoutHandler.singleLogin(webContext, accountName, sessionKey, commonProfile.getClientName());
                }
            } catch (ServiceException serviceException) {
                Log.sso.error((Object) serviceException);
            }
        });
    }

    private boolean isLoggedIn(HttpServletRequest httpServletRequest) {
        AuthToken authToken = AuthUtil.getAuthTokenFromHttpReq((HttpServletRequest) httpServletRequest, (boolean) false);
        return Optional.ofNullable(authToken).isPresent() && !authToken.isExpired() && authToken.isRegistered();
    }

    private void redirectToMail(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException, ServiceException {
        String string = AuthUtil.getRedirectURL((HttpServletRequest) httpServletRequest, (Server) Provisioning.getInstance().getLocalServer(), (boolean) false, (boolean) true) + "?ignoreLoginURL=1";
        httpServletResponse.sendRedirect(string);
    }

    private static void extendSessionTimeout(HttpServletRequest httpServletRequest) {
        HttpSession httpSession = httpServletRequest.getSession(false);
        if (httpSession != null) {
            httpSession.setMaxInactiveInterval(1800);
        }
    }
}
