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
 * Zimbra Single Sign On — Keep Alive JavaScript (Phase 5)
 *
 * Full-featured browser-side heartbeat with:
 *   - Activity monitoring (pointerdown, keydown, touchstart, visibility)
 *   - Visibility gate: heartbeat only when tab is visible & active within grace
 *   - Hidden tab grace: short allowence when tab hidden, then stop
 *   - Multi-tab leader election via BroadcastChannel (localStorage fallback)
 *   - Recursive setTimeout with jitter (never setInterval)
 *   - POST with CSRF header (X-Zm-Sso-Heartbeat)
 *   - Response handling: 200/204/401/403/429/503 with Retry-After
 *
 * Configuration via window.SO_SSO_CONFIG or server response fields.
 *
 * Written by danpedron
 */

(function() {
    'use strict';

    // ─── Configuration ────────────────────────────────────────────────
    var config = window.SO_SSO_CONFIG || {
        heartbeatIntervalSeconds: 60,
        activityGraceSeconds: 1500,
        hiddenTabGraceSeconds: 120,
        transientFailureGraceSeconds: 180,
        maxTransientFailures: 3,
        jitterPercent: 0.10,
        leaderKey: 'default'
    };

    var LEADER_CHANNEL = 'zm-sso-leader-election';
    var LEADER_KEY = 'zm-sso-leader-' + config.leaderKey;

    // Runtime state
    var state = {
        intervalMs: (config.heartbeatIntervalSeconds * 1000) || 60000,
        lastActivity: Date.now(),
        lastHeartbeat: 0,
        initialized: false,
        isLeader: false,
        leaderExpiry: 0,
        transientFailureCount: 0,
        LEADER_LEASE_MS: 30000,
        LEADER_RENEW_MS: 15000,
    };

    var KEEPALIVE_URL = '/service/extension/sso/keepalive';
    var bc = null;  // BroadcastChannel

    // ─── Activity Monitoring ────────────────────────────────────────────

    function trackActivity() {
        state.lastActivity = Date.now();
    }

    function shouldHeartbeat() {
        var now = Date.now();
        var sinceActivity = now - state.lastActivity;

        if (document.visibilityState !== 'visible') {
            if (sinceActivity > config.hiddenTabGraceSeconds * 1000) {
                return false;
            }
        }

        if (sinceActivity > config.activityGraceSeconds * 1000) {
            return false;
        }

        return true;
    }

    // ─── Multi-Tab Leader Election ──────────────────────────────────────

    function generateTabId() {
        return 'tab_' + Date.now() + '_' + Math.floor(Math.random() * 100000);
    }

    var myTabId = generateTabId();

    function tryAcquireLeadership() {
        var now = Date.now();
        if (state.isLeader && now < state.leaderExpiry) {
            return true;
        }

        // Try to claim leadership via localStorage (last-writer-wins with TTL)
        var existing = localStorage.getItem(LEADER_KEY);
        if (existing) {
            try {
                var parsed = JSON.parse(existing);
                if (parsed.expiry > now && parsed.tabId !== myTabId) {
                    state.isLeader = false;
                    return false;
                }
            } catch (e) { /* stale entry */ }
        }

        // Claim leadership
        var candidate = { tabId: myTabId, expiry: now + state.LEADER_LEASE_MS };
        localStorage.setItem(LEADER_KEY, JSON.stringify(candidate));

        // Verify we still hold it (race condition check)
        var verify = localStorage.getItem(LEADER_KEY);
        try {
            var v = JSON.parse(verify);
            if (v.tabId === myTabId) {
                state.isLeader = true;
                state.leaderExpiry = now + state.LEADER_LEASE_MS;
                announceLeadership(true);
                scheduleLeadershipRefresh();
                return true;
            }
        } catch (e) { /* won the race */ }

        state.isLeader = false;
        return false;
    }

    function announceLeadership(leader) {
        if (bc) {
            try {
                bc.postMessage({ type: 'leader', value: leader });
            } catch (e) {}
        }
    }

    function scheduleLeadershipRefresh() {
        if (!state.isLeader) return;
        var remaining = state.leaderExpiry - Date.now();
        if (remaining < state.LEADER_RENEW_MS) return;

        setTimeout(function() {
            if (state.isLeader) {
                tryAcquireLeadership();
            }
        }, Math.min(remaining - state.LEADER_RENEW_MS, 5000));
    }

    function initBroadcastChannel() {
        if (typeof BroadcastChannel !== 'undefined') {
            try {
                bc = new BroadcastChannel(LEADER_CHANNEL);
                bc.onmessage = function(event) {
                    if (event.data && event.data.type === 'leader' && event.data.value === true) {
                        state.isLeader = false;
                    }
                };
            } catch (e) {
                bc = null;
            }
        }

        // Fallback: localStorage 'storage' event
        if (!bc) {
            window.addEventListener('storage', function(event) {
                if (event.key === LEADER_KEY) {
                    if (event.newValue) {
                        state.isLeader = false;
                    }
                }
            });
        }
    }

    // ─── Heartbeat ──────────────────────────────────────────────────────

    function jitter(interval) {
        var delta = interval * config.jitterPercent;
        return interval + (Math.random() * 2 - 1) * delta;
    }

    function getIntervalMs() {
        return jitter(state.intervalMs);
    }

    function sendKeepAlive() {
        // Only leader tab sends heartbeats
        if (!state.isLeader) {
            tryAcquireLeadership();
        }
        if (!state.isLeader) {
            setTimeout(sendKeepAlive, jitter(5000));
            return;
        }

        if (!shouldHeartbeat()) {
            setTimeout(sendKeepAlive, jitter(10000));
            return;
        }

        trackActivity();

        fetch(KEEPALIVE_URL, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'X-Zm-Sso-Heartbeat': '1',
                'X-Requested-With': 'XMLHttpRequest',
                'Cache-Control': 'no-cache, no-store'
            },
            body: JSON.stringify({})
        }).then(function(response) {
            state.lastHeartbeat = Date.now();

            // Read interval from header (works for 200/204)
            var serverInterval = response.headers.get('X-Heartbeat-Interval');
            if (serverInterval) {
                state.intervalMs = parseInt(serverInterval, 10) * 1000;
                config.heartbeatIntervalSeconds = parseInt(serverInterval, 10);
            }

            if (response.status === 200 || response.status === 204) {
                // Try to read JSON for additional config (non-204 responses)
                if (response.status === 200) {
                    response.json().then(function(data) {
                        if (data && data.heartbeatInterval) {
                            state.intervalMs = data.heartbeatInterval * 1000;
                            config.heartbeatIntervalSeconds = data.heartbeatInterval;
                        }
                        state.transientFailureCount = 0;
                        setTimeout(sendKeepAlive, getIntervalMs());
                    }).catch(function() {
                        state.transientFailureCount = 0;
                        setTimeout(sendKeepAlive, getIntervalMs());
                    });
                } else {
                    state.transientFailureCount = 0;
                    setTimeout(sendKeepAlive, getIntervalMs());
                }
            } else if (response.status === 401) {
                state.transientFailureCount = 0;
                console.warn('[SSO KeepAlive] Session expired/revoked (401), redirecting to login');
                window.location.href = '/service/extension/oidc/login';
            } else if (response.status === 403) {
                state.transientFailureCount = 0;
                console.error('[SSO KeepAlive] Security violation (403), blocking');
            } else if (response.status === 429) {
                var retryAfter = (response.headers.get('Retry-After') || '30');
                var retrySec = parseInt(retryAfter, 10);
                if (isNaN(retrySec)) retrySec = 30;
                setTimeout(sendKeepAlive, retrySec * 1000);
            } else if (response.status === 503) {
                state.transientFailureCount++;
                if (state.transientFailureCount < config.maxTransientFailures) {
                    var retryAfter503 = response.headers.get('Retry-After');
                    var retryDelay = retryAfter503 ? parseInt(retryAfter503, 10) * 1000 : 30000;
                    console.warn('[SSO KeepAlive] Transient failure ' + state.transientFailureCount + '/' +
                        config.maxTransientFailures + ', retrying in ' + (retryDelay / 1000) + 's');
                    setTimeout(sendKeepAlive, retryDelay);
                } else {
                    console.error('[SSO KeepAlive] Max transient failures exceeded, redirecting to login');
                    window.location.href = '/service/extension/oidc/login';
                }
            } else {
                console.warn('[SSO KeepAlive] Unexpected response: ' + response.status + ', retrying in 30s');
                setTimeout(sendKeepAlive, 30000);
            }
        }).catch(function(error) {
            state.transientFailureCount++;
            if (state.transientFailureCount < config.maxTransientFailures) {
                console.warn('[SSO KeepAlive] Network error: ' + error.message +
                    ', retrying in 30s (attempt ' + state.transientFailureCount + ')');
                setTimeout(sendKeepAlive, 30000);
            } else {
                console.warn('[SSO KeepAlive] Max retries exceeded after network errors');
                state.transientFailureCount = 0;
                setTimeout(sendKeepAlive, 60000);
            }
        });
    }

    // ─── Initialization ─────────────────────────────────────────────────

    function start() {
        if (state.initialized) return;
        state.initialized = true;

        initBroadcastChannel();
        trackActivity();

        // Activity event listeners (throttled)
        var activityEvents = ['pointerdown', 'keydown', 'touchstart', 'mousedown', 'scroll', 'visibilitychange'];
        activityEvents.forEach(function(evt) {
            document.addEventListener(evt, trackActivity, { passive: true, capture: true });
        });

        window.addEventListener('focus', trackActivity, { passive: true, capture: true });

        // On visibility change: if becoming visible, send heartbeat immediately
        document.addEventListener('visibilitychange', function() {
            if (document.visibilityState === 'visible') {
                trackActivity();
                if (state.isLeader) {
                    sendKeepAlive();
                }
            }
        });

        console.log('[SSO KeepAlive] Phase 5 heartbeat initialized (leader election: BroadcastChannel=' + (!!bc) + ')');
        setTimeout(function() {
            if (tryAcquireLeadership()) {
                sendKeepAlive();
            } else {
                setTimeout(sendKeepAlive, jitter(10000));
            }
        }, 2000);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
