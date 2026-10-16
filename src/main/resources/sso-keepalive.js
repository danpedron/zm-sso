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
 * Zimbra Single Sign On - Keep Alive JavaScript
 *
 * This JavaScript is loaded into the Zimbra Web Client to periodically call
 * the /sso/keepalive endpoint, which renews the OIDC access token (every 5 min
 * by default) and keeps the Keycloak SSO session alive while the user is
 * actively using the Webmail.
 *
 * Installation (optional):
 *   Copy this file to /opt/zimbra/jetty_base/webapps/zimbra/js/
 *   Add the following line to the Zimbra Web Client (e.g., via
 *   /opt/zimbra/jetty_base/webapps/zimbra/hiddenTagline.jsp or
 *   a custom zimlet):
 *
 *     <script src="/service/extension/sso/keepalive.js"></script>
 *
 * Configuration:
 *   The KEEPALIVE_INTERVAL_MS controls how often the keepalive is called.
 *   Set to 120000 (2 minutes) by default — should be less than the
 *   Jetty session timeout (30 min) and Keycloak access token lifespan (5 min).
 *
 * Written by danpedron
 */

(function() {
    'use strict';

    // Interval in milliseconds between keepalive calls.
    // Default: 2 minutes (120000 ms). Should be less than the access token
    // lifespan (5 min in this deployment) to ensure the token is refreshed
    // before it expires.
    var KEEPALIVE_INTERVAL_MS = window.SO_KEEPALIVE_INTERVAL_MS || 120000;

    // The keepalive endpoint URL
    var KEEPALIVE_URL = '/service/extension/sso/keepalive';

    var initialized = false;

    function startKeepAlive() {
        if (initialized) {
            return;
        }
        initialized = true;

        console.log('[SSO KeepAlive] Starting periodic keepalive to ' + KEEPALIVE_URL +
            ' every ' + (KEEPALIVE_INTERVAL_MS / 1000) + 's');

        // Initial call after a short delay (let the page load first)
        setTimeout(sendKeepAlive, 5000);
    }

    function sendKeepAlive() {
        fetch(KEEPALIVE_URL, {
            method: 'GET',
            credentials: 'same-origin',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Cache-Control': 'no-cache, no-store'
            }
        }).then(function(response) {
            if (response.status === 200) {
                // Token refreshed or still valid — schedule next call
                setTimeout(sendKeepAlive, KEEPALIVE_INTERVAL_MS);
            } else if (response.status === 401) {
                // Session expired on Keycloak — force re-authentication
                console.log('[SSO KeepAlive] Session expired on IdP, redirecting to login');
                window.location.href = '/service/extension/oidc/login';
            } else {
                // Unexpected error — retry after a shorter interval
                console.warn('[SSO KeepAlive] Unexpected response: ' + response.status +
                    ' — retrying in 30s');
                setTimeout(sendKeepAlive, 30000);
            }
        }).catch(function(error) {
            console.error('[SSO KeepAlive] Network error: ' + error.message +
                ' — retrying in 30s');
            setTimeout(sendKeepAlive, 30000);
        });
    }

    // Start the keepalive loop once the page has loaded
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', startKeepAlive);
    } else {
        startKeepAlive();
    }

    // Also start when the Web Client becomes visible again (e.g., user
    // returns to the tab after a period of inactivity)
    document.addEventListener('visibilitychange', function() {
        if (!document.hidden && initialized) {
            // User returned to the tab — fire an immediate keepalive
            sendKeepAlive();
        }
    });
})();
