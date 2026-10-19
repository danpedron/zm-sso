/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zm SSO — Zimlet Webmail Hook (Phase 5)
 * Injects sso-keepalive.js into the Webmail page.
 * The actual heartbeat logic lives in the server-served keepalive.js.
 * ***** END LICENSE BLOCK *****
 */
(function() {
    'use strict';

    // Guard against double injection
    if (document.getElementById('zm-sso-keepalive-js')) return;

    var script = document.createElement('script');
    script.id = 'zm-sso-keepalive-js';
    script.src = '/service/extension/sso/keepalive.js';
    script.async = true;
    script.onload = function() {
        console.log('[SSO KeepAlive Zimlet] Heartbeat JS loaded — session sync active');
    };
    script.onerror = function() {
        console.warn('[SSO KeepAlive Zimlet] Failed to load heartbeat JS');
    };
    document.head.appendChild(script);
})();
