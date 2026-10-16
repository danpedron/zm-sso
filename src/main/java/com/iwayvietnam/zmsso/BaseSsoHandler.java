/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zm SSO is the Zimbra Collaboration Open Source Edition extension for single sign-on authentication to the Zimbra Web Client.
 * Copyright (C) 2020-present iWay Vietnam and/or its affiliates. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>
 * ***** END LICENSE BLOCK *****
 *
 * Zimbra Single Sign On
 *
 * Written by Nguyen Van Nguyen <nguyennv1981@gmail.com>
 * Modified by danpedron for OIDC session synchronization
 */
package com.iwayvietnam.zmsso;

import com.iwayvietnam.zmsso.pac4j.ConfigBuilder;
import com.iwayvietnam.zmsso.util.Log;
import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.account.*;
import com.zimbra.cs.extension.ExtensionHttpHandler;

import com.zimbra.cs.servlet.util.AuthUtil;
import org.pac4j.core.client.Client;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.util.Pac4jConstants;
import org.pac4j.jee.http.adapter.JEEHttpActionAdapter;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.profile.OidcProfile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.*;

import static com.iwayvietnam.zmsso.pac4j.SettingsConstants.SSO_CLIENT_NAME_SESSION_ATTR;
import static com.iwayvietnam.zmsso.pac4j.SettingsConstants.SSO_PROFILE_SESSION_ATTR;

/**
 * Base Sso Handler
 * @author Nguyen Van Nguyen <nguyennv1981@gmail.com>
 */
public abstract class BaseSsoHandler extends ExtensionHttpHandler {
    protected final ConfigBuilder configBuilder;

    public BaseSsoHandler() {
        configBuilder = ConfigBuilder.getInstance();
    }

    protected void doLogin(final HttpServletRequest request, final HttpServletResponse response, final Client client) throws IOException, ServiceException {
        // Extend the Jetty session timeout so the OIDC profile survives the
        // Keycloak access token (5 min) and Keycloak idle timeout (30 min).
        // Without this, the JSESSION expires at the webdefault.xml setting.
        extendSessionTimeout(request);

        if (!isLoggedIn(request)) {
            Log.sso.info("SSO login with: %s", client.getName());
            request.getSession().setAttribute(SSO_CLIENT_NAME_SESSION_ATTR, client.getName());
            final var config = configBuilder.getConfig();
            final var context = config.getWebContextFactory().newContext(request, response);
            final var sessionStore = config.getSessionStoreFactory().newSessionStore();
            client.getRedirectionAction(context, sessionStore).ifPresent(action -> {
                JEEHttpActionAdapter.INSTANCE.adapt(action, context);
            });
        } else if (client instanceof OidcClient oidcClient) {
            // The Zimbra auth token is valid, but check if the OIDC profile
            // has expired (access token lifetime is shorter than the Zimbra token).
            // If expired, attempt to renew via refresh token.
            // If renewal fails (Keycloak session expired by idle timeout),
            // force re-authentication through Keycloak.
            final var session = request.getSession(false);
            if (session != null) {
                final var profile = (CommonProfile) session.getAttribute(SSO_PROFILE_SESSION_ATTR);
                if (profile instanceof OidcProfile oidcProfile && oidcProfile.isExpired()) {
                    Log.sso.info("SSO login: OIDC profile expired for client: %s, attempting token refresh", client.getName());
                    final var config = configBuilder.getConfig();
                    final var context = config.getWebContextFactory().newContext(request, response);
                    final var sessionStore = config.getSessionStoreFactory().newSessionStore();
                    try {
                        final var renewedProfile = oidcClient.renewUserProfile(oidcProfile, context, sessionStore);
                        if (renewedProfile.isPresent()) {
                            Log.sso.info("SSO login: OIDC token refreshed successfully, redirecting to mail");
                            session.setAttribute(SSO_PROFILE_SESSION_ATTR, renewedProfile.get());
                            redirectToMail(request, response);
                        } else {
                            Log.sso.info("SSO login: OIDC token refresh failed, forcing re-authentication");
                            session.removeAttribute(SSO_PROFILE_SESSION_ATTR);
                            doOidcLoginRedirect(request, response, client, session);
                        }
                    } catch (final Exception e) {
                        Log.sso.warn("SSO login: OIDC token refresh threw exception: %s", e.getMessage());
                        session.removeAttribute(SSO_PROFILE_SESSION_ATTR);
                        doOidcLoginRedirect(request, response, client, session);
                    }
                } else {
                    redirectToMail(request, response);
                }
            } else {
                redirectToMail(request, response);
            }
        }
        else {
            redirectToMail(request, response);
        }
    }

    /**
     * Redirects the user to the OIDC login flow, preserving the client name in session.
     */
    private void doOidcLoginRedirect(final HttpServletRequest request, final HttpServletResponse response,
                                     final Client client, final HttpSession session) throws IOException {
        session.setAttribute(SSO_CLIENT_NAME_SESSION_ATTR, client.getName());
        final var config = configBuilder.getConfig();
        final var context = config.getWebContextFactory().newContext(request, response);
        final var sessionStore = config.getSessionStoreFactory().newSessionStore();
        client.getRedirectionAction(context, sessionStore).ifPresent(action -> {
            JEEHttpActionAdapter.INSTANCE.adapt(action, context);
        });
    }

    protected void doCallback(final HttpServletRequest request, final HttpServletResponse response, final Client client) {
        Log.sso.info("SSO callback with: %s", client.getName());

        final var defaultUrl = Pac4jConstants.DEFAULT_URL_VALUE;
        final var renewSession = configBuilder.getRenewSession();

        final var config = configBuilder.getConfig();
        final var context = config.getWebContextFactory().newContext(request, response);
        final var sessionStore = config.getSessionStoreFactory().newSessionStore();
        config.getCallbackLogic().perform(
            context,
            sessionStore,
            config,
            JEEHttpActionAdapter.INSTANCE,
            defaultUrl,
            renewSession,
            client.getName()
        );
        Log.sso.info("SSO callback is performed with: %s", client.getName());

        final var manager = new ProfileManager(context, sessionStore);
        manager.setConfig(config);
        manager.getProfile(CommonProfile.class).ifPresent(profile -> {
            // Store the full OidcProfile (with refresh token) in the HTTP session
            // so that the keepalive handler and doLogin can access it for token renewal.
            request.getSession().setAttribute(SSO_PROFILE_SESSION_ATTR, profile);
            final var logoutHandler = configBuilder.getLogoutHandler();
            final var accountName = Optional.ofNullable(profile.getEmail()).orElse(profile.getId());
            final var sessionId = sessionStore.getSessionId(context, true).orElse("");
            final var sessionKey = (String) logoutHandler.getStore().get(sessionId).orElse(sessionId);
            try {
                logoutHandler.singleLogin(context, accountName, sessionKey, profile.getClientName());
            } catch (final ServiceException e) {
                Log.sso.error(e);
            }
        });
    }

    private boolean isLoggedIn(final HttpServletRequest request) {
        final var authToken = AuthUtil.getAuthTokenFromHttpReq(request, false);
        return Optional.ofNullable(authToken).isPresent() && !authToken.isExpired() && authToken.isRegistered();
    }

    private void redirectToMail(final HttpServletRequest request, final HttpServletResponse response) throws IOException, ServiceException {
        final var redirectUrl = AuthUtil.getRedirectURL(request, Provisioning.getInstance().getLocalServer(), false, true) + AuthUtil.IGNORE_LOGIN_URL;
        response.sendRedirect(redirectUrl);
    }

    /**
     * Extends the HTTP session timeout to 30 minutes so that the OIDC profile
     * (containing the refresh token) survives between keepalive calls.
     * The default Jetty webdefault.xml may set a shorter timeout (e.g., 5 min).
     */
    private static final int SESSION_TIMEOUT_SECONDS = 30 * 60;

    private static void extendSessionTimeout(final HttpServletRequest request) {
        final var session = request.getSession(false);
        if (session != null) {
            session.setMaxInactiveInterval(SESSION_TIMEOUT_SECONDS);
        }
    }
}
