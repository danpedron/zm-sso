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
import com.zimbra.cs.extension.ExtensionHttpHandler;

import org.pac4j.core.client.Client;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.profile.OidcProfile;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Optional;

import static com.iwayvietnam.zmsso.pac4j.SettingsConstants.SSO_PROFILE_SESSION_ATTR;

/**
 * Keep Alive Handler for OIDC session synchronization.
 *
 * This handler is called periodically by the Zimbra Web Client (via JavaScript)
 * to renew the OIDC access token and keep the Keycloak session alive while the
 * user is actively using the Webmail.
 *
 * URL: /service/extension/sso/keepalive
 *
 * The handler:
 * 1. Retrieves the OIDC profile from the HTTP session
 * 2. Checks if the profile (access token) is expired via OidcProfile.isExpired()
 * 3. If expired, calls OidcClient.renewUserProfile() to perform a refresh token grant
 * 4. Updates the profile in the session
 * 5. Returns HTTP 200 on success, HTTP 401 if the session cannot be renewed
 *
 * To enable the keepalive mechanism, add the following JavaScript to the Zimbra
 * Web Client (see static/sso-keepalive.js):
 *
 *   <script src="/service/extension/sso/keepalive.js"></script>
 *
 * @author danpedron
 */
public class KeepAliveHandler extends BaseSsoHandler {
    public static final String HANDLER_PATH = "/sso/keepalive";

    /**
     * The session timeout (in minutes) to set when the keepalive is configured.
     * Defaults to 30 minutes so the OIDC profile survives longer in the JSESSION.
     * This should be >= the Keycloak idle timeout and >= the keepalive interval.
     */
    private static final int KEEPALIVE_SESSION_TIMEOUT_MINUTES = 30;

    @Override
    public String getPath() {
        return HANDLER_PATH;
    }

    @Override
    public void doPost(final HttpServletRequest request, final HttpServletResponse response) throws IOException, ServletException {
        handleKeepAlive(request, response);
    }

    @Override
    public void doGet(final HttpServletRequest request, final HttpServletResponse response) throws IOException, ServletException {
        handleKeepAlive(request, response);
    }

    private void handleKeepAlive(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        final var session = request.getSession(false);
        if (session == null) {
            Log.sso.debug("KeepAlive: no session found");
            sendResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "No active session");
            return;
        }

        // Extend the session lifetime on each keepalive call
        session.setMaxInactiveInterval(KEEPALIVE_SESSION_TIMEOUT_MINUTES * 60);

        final var profile = (CommonProfile) session.getAttribute(SSO_PROFILE_SESSION_ATTR);
        if (profile == null) {
            Log.sso.debug("KeepAlive: no OIDC profile in session");
            sendResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "No profile in session");
            return;
        }

        if (!(profile instanceof OidcProfile oidcProfile)) {
            Log.sso.debug("KeepAlive: profile is not an OidcProfile");
            sendResponse(response, HttpServletResponse.SC_OK, "Non-OIDC profile, no refresh needed");
            return;
        }

        // Check if the OIDC access token is expired (default: 5 minutes from Keycloak)
        if (!oidcProfile.isExpired()) {
            Log.sso.debug("KeepAlive: OIDC profile still valid, no refresh needed");
            sendResponse(response, HttpServletResponse.SC_OK, "OK");
            return;
        }

        // Profile is expired — attempt token refresh via refresh_token grant
        Log.sso.info("KeepAlive: OIDC profile expired, attempting token refresh");

        final var config = configBuilder.getConfig();
        final Optional<Client> optClient = config.getClients().findClient(OidcClient.class);
        if (optClient.isEmpty()) {
            Log.sso.warn("KeepAlive: no OidcClient found, cannot refresh");
            sendResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "No OIDC client configured");
            return;
        }

        final var oidcClient = (OidcClient) optClient.get();
        final var context = config.getWebContextFactory().newContext(request, response);
        final var sessionStore = config.getSessionStoreFactory().newSessionStore();

        try {
            final var renewedProfile = oidcClient.renewUserProfile(oidcProfile, context, sessionStore);
            if (renewedProfile.isPresent()) {
                Log.sso.info("KeepAlive: OIDC token refreshed successfully");
                session.setAttribute(SSO_PROFILE_SESSION_ATTR, renewedProfile.get());
                sendResponse(response, HttpServletResponse.SC_OK, "Token refreshed");
            } else {
                Log.sso.warn("KeepAlive: token refresh returned empty profile (Keycloak session may have expired)");
                session.removeAttribute(SSO_PROFILE_SESSION_ATTR);
                sendResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "Session expired on IdP");
            }
        } catch (final Exception e) {
            Log.sso.warn("KeepAlive: token refresh failed: %s", e.getMessage());
            session.removeAttribute(SSO_PROFILE_SESSION_ATTR);
            sendResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "Refresh failed: session expired on IdP");
        }
    }

    private void sendResponse(final HttpServletResponse response, final int status, final String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        final PrintWriter writer = response.getWriter();
        writer.write("{\"status\":\"" + message + "\",\"code\":" + status + "}");
        writer.flush();
    }
}
