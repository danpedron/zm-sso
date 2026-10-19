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
 */
package com.iwayvietnam.zmsso.util;

import com.iwayvietnam.zmsso.util.Log;

/**
 * Structured audit logger for SSO session lifecycle events.
 * <p>
 * All fields are key=value pairs separated by '|'. No raw tokens, cookies,
 * secrets, or JWT payloads are ever logged. Only hashes, account IDs, IPs,
 * and status codes are recorded.
 * </p>
 */
public final class AuditLog {

    /** Event type constants. */
    public static final String SESSION_CREATED         = "SESSION_CREATED";
    public static final String HEARTBEAT_ACCEPTED      = "HEARTBEAT_ACCEPTED";
    public static final String TOKEN_REFRESHED         = "TOKEN_REFRESHED";
    public static final String TRANSIENT_PROVIDER_FAILURE = "TRANSIENT_PROVIDER_FAILURE";
    public static final String SESSION_REVOKED         = "SESSION_REVOKED";
    public static final String BACKCHANNEL_LOGOUT      = "BACKCHANNEL_LOGOUT";
    public static final String HEARTBEAT_TIMEOUT       = "HEARTBEAT_TIMEOUT";
    public static final String LOCAL_TOKEN_INVALIDATED = "LOCAL_TOKEN_INVALIDATED";
    public static final String ABSOLUTE_MAX_REACHED    = "ABSOLUTE_MAX_REACHED";
    public static final String LOGOUT_REPLAY           = "LOGOUT_REPLAY";
    public static final String LOGOUT_COMPLETED        = "LOGOUT_COMPLETED";

    private AuditLog() {}

    /**
     * Record a structured audit event. All arguments are treated as already-sanitized
     * (i.e., token hashes, not raw tokens).
     */
    public static void audit(String event, String accountId, String sidHashPrefix,
                             String reason, String result) {
        StringBuilder sb = new StringBuilder();
        sb.append("AUDIT|").append(event);
        if (accountId != null && !accountId.isEmpty()) sb.append("|account=").append(accountId);
        if (sidHashPrefix != null && !sidHashPrefix.isEmpty()) sb.append("|sid_hash=").append(sidHashPrefix);
        if (reason != null && !reason.isEmpty()) sb.append("|reason=").append(reason);
        if (result != null && !result.isEmpty()) sb.append("|result=").append(result);
        Log.sso.info(sb);
    }

    /** Convenience method for heartbeat events with latency. */
    public static void heartbeat(String accountId, String sidHashPrefix, String reason,
                                 String result, long latencyMs) {
        StringBuilder sb = new StringBuilder();
        sb.append("AUDIT|").append(HEARTBEAT_ACCEPTED);
        if (accountId != null && !accountId.isEmpty()) sb.append("|account=").append(accountId);
        if (sidHashPrefix != null && !sidHashPrefix.isEmpty()) sb.append("|sid_hash=").append(sidHashPrefix);
        if (reason != null && !reason.isEmpty()) sb.append("|reason=").append(reason);
        sb.append("|result=").append(result);
        sb.append("|latency_ms=").append(latencyMs);
        Log.sso.info(sb);
    }

    /** Convenience method for transient failure events. */
    public static void transientFailure(String accountId, String sidHashPrefix,
                                         String reason, int attempt, int maxAttempts) {
        StringBuilder sb = new StringBuilder();
        sb.append("AUDIT|").append(TRANSIENT_PROVIDER_FAILURE);
        if (accountId != null && !accountId.isEmpty()) sb.append("|account=").append(accountId);
        if (sidHashPrefix != null && !sidHashPrefix.isEmpty()) sb.append("|sid_hash=").append(sidHashPrefix);
        if (reason != null && !reason.isEmpty()) sb.append("|reason=").append(reason);
        sb.append("|attempt=").append(attempt);
        sb.append("|max=").append(maxAttempts);
        Log.sso.info(sb);
    }

    /**
     * Truncate a hash/prefix for logging. Never logs full tokens.
     */
    public static String hashPrefix(String hash) {
        if (hash == null || hash.isEmpty()) return "(none)";
        return hash.substring(0, Math.min(10, hash.length())) + "...";
    }
}
