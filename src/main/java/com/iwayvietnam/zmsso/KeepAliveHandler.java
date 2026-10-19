package com.iwayvietnam.zmsso;

import com.iwayvietnam.zmsso.db.DbSsoSession;
import com.iwayvietnam.zmsso.util.Log;
import com.iwayvietnam.zmsso.util.AuditLog;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ByteUtil;
import com.zimbra.common.util.StringUtil;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.text.ParseException;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.io.IOUtils;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.jee.context.JEEContext;
import org.pac4j.jee.http.adapter.JEEHttpActionAdapter;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.profile.OidcProfile;

public class KeepAliveHandler
extends BaseSsoHandler {
    public static final String HANDLER_PATH = "/sso/keepalive";
    private static final int KEEPALIVE_SESSION_TIMEOUT_MINUTES = 30;

    public String getPath() {
        return HANDLER_PATH;
    }

    public void doPost(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {
        this.handleKeepAlive(httpServletRequest, httpServletResponse);
    }

    public void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {
        this.handleKeepAlive(httpServletRequest, httpServletResponse);
    }

    private void handleKeepAlive(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {
        HttpSession httpSession = httpServletRequest.getSession(false);
        if (httpSession == null) {
            Log.sso.debug((Object) "KeepAlive: no session found");
            this.sendResponse(httpServletResponse, 401, "No active session");
            return;
        }
        httpSession.setMaxInactiveInterval(1800);
        CommonProfile commonProfile = (CommonProfile) httpSession.getAttribute("sso.Profile");
        if (commonProfile == null) {
            Log.sso.debug((Object) "KeepAlive: no OIDC profile in session");
            this.sendResponse(httpServletResponse, 401, "No profile in session");
            return;
        }

        // Phase 4: Session sync — check database session status when enabled
        if (this.configBuilder.getSessionSyncEnabled()) {
            if (commonProfile instanceof OidcProfile) {
                this.checkDbSessionStatus(httpServletRequest, httpServletResponse, (OidcProfile) commonProfile, httpSession);
                // checkDbSessionStatus sends response and returns if session revoked
                // If session is active, it falls through to token refresh
                if (httpServletResponse.getStatus() == 401) {
                    return;
                }
            }
        }

        if (!(commonProfile instanceof OidcProfile)) {
            Log.sso.debug((Object) "KeepAlive: profile is not an OidcProfile");
            this.sendResponse(httpServletResponse, 200, "Non-OIDC profile, no refresh needed");
            return;
        }
        OidcProfile oidcProfile = (OidcProfile) commonProfile;
        if (!oidcProfile.isExpired()) {
            Log.sso.debug((Object) "KeepAlive: OIDC profile still valid, no refresh needed");
            // Phase 7: Audit log — HEARTBEAT_ACCEPTED
            try {
                String sid = oidcProfile.getIdToken().getJWTClaimsSet().getStringClaim("sid");
                AuditLog.heartbeat(oidcProfile.getId(), AuditLog.hashPrefix(sid),
                        "profile_valid", "ok", 0);
            } catch (Exception e) { /* sid extraction failed */ }
            this.sendResponse(httpServletResponse, 200, "OK");
            return;
        }
            Log.sso.info((Object) "KeepAlive: OIDC profile expired, attempting token refresh");
        long startTime = System.currentTimeMillis();
        Config config = this.configBuilder.getConfig();
        Optional<OidcClient> optional = config.getClients().findClient(OidcClient.class);
        if (optional.isEmpty()) {
            Log.sso.warn((Object) "KeepAlive: no OidcClient found, cannot refresh");
            this.sendResponse(httpServletResponse, 500, "No OIDC client configured");
            return;
        }
        OidcClient oidcClient = optional.get();
        WebContext webContext = config.getWebContextFactory().newContext(new Object[]{httpServletRequest, httpServletResponse});
        SessionStore sessionStore = config.getSessionStoreFactory().newSessionStore(new Object[0]);
        try {
            Optional<UserProfile> optional2 = oidcClient.renewUserProfile((UserProfile) oidcProfile, webContext, sessionStore);
            if (optional2.isPresent()) {
                Log.sso.info((Object) "KeepAlive: OIDC token refreshed successfully");
                httpSession.setAttribute("sso.Profile", optional2.get());
                // Phase 4: Update last_heartbeat_at after successful refresh
                this.updateHeartbeatInDb(httpSession, oidcProfile);
                // Phase 7: Audit log — TOKEN_REFRESHED
                try {
                    String sid = oidcProfile.getIdToken().getJWTClaimsSet().getStringClaim("sid");
                    String accountId = oidcProfile.getId();
                    AuditLog.audit(AuditLog.TOKEN_REFRESHED, accountId, AuditLog.hashPrefix(sid),
                            "refresh_success", "ok");
                    AuditLog.heartbeat(accountId, AuditLog.hashPrefix(sid), "token_refreshed", "ok",
                            System.currentTimeMillis() - startTime);
                } catch (Exception e) { /* sid extraction failed, skip audit */ }
                this.sendResponse(httpServletResponse, 200, "Token refreshed");
            } else {
                // Phase 5: Track transient failure instead of immediately invalidating
                this.handleRefreshFailure(httpServletResponse, httpSession, oidcProfile, "empty profile from IdP");
            }
        } catch (Exception exception) {
            // Phase 5: Track transient failure instead of immediately invalidating
            this.handleRefreshFailure(httpServletResponse, httpSession, oidcProfile, exception.getMessage());
        }
    }

    /**
     * Phase 5: Handle token refresh failure with transient error state.
     * Instead of immediately returning 401, tracks the failure count.
     * After maxTransientFailures, escalates to 401 (session expired).
     */
    private void handleRefreshFailure(HttpServletResponse response, HttpSession httpSession,
            OidcProfile oidcProfile, String failureReason) throws IOException {
        try {
            String sid = oidcProfile.getIdToken().getJWTClaimsSet().getStringClaim("sid");
            if (sid != null && !sid.isEmpty()) {
                String sidHash = ByteUtil.getSHA256Digest(sid.getBytes(), false);
                DbSsoSession dbSession = DbSsoSession.getSessionBySidHash(sidHash);
                if (dbSession != null && DbSsoSession.STATUS_ACTIVE.equals(dbSession.getStatus())) {
                    int failCount = DbSsoSession.incrementTransientFailureBySidHash(sidHash);
                    int maxFailures = configBuilder.getMaxTransientFailures();

                    if (failCount < maxFailures) {
                        Log.sso.warn("KeepAlive: transient failure " + failCount + "/" + maxFailures +
                                ", keeping session alive — retry. Reason: " + failureReason);
                        // Phase 5: Return 503 with Retry-After per plan spec
                        // Phase 7: Audit log — TRANSIENT_PROVIDER_FAILURE
                        AuditLog.transientFailure(oidcProfile.getId(), AuditLog.hashPrefix(sid),
                                failureReason, failCount, maxFailures);
                        response.setStatus(503);
                        response.setContentType("application/json");
                        response.setHeader("Retry-After", String.valueOf(configBuilder.getTransientFailureGraceSeconds()));
                        PrintWriter pw = response.getWriter();
                        pw.print("{\"status\":\"Transient error, retrying\",\"code\":503,\"retryAfter\":"
                                + configBuilder.getTransientFailureGraceSeconds() + ",\"sessionSync\":true}");
                        pw.flush();
                        return;
                    } else {
                        Log.sso.warn("KeepAlive: max transient failures (" + maxFailures +
                                ") exceeded, marking session as EXPIRED");
                        DbSsoSession.setTransientErrorBySidHash(sidHash);
                        // Phase 7: Audit log — ABSOLUTE_MAX_REACHED
                        AuditLog.audit(AuditLog.ABSOLUTE_MAX_REACHED, oidcProfile.getId(),
                                AuditLog.hashPrefix(sid), "max_failures_exceeded", "escalated_to_transient_error");
                        httpSession.removeAttribute("sso.Profile");
                        this.sendResponse(response, 401, "Session expired after transient failures");
                        return;
                    }
                }
            }
        } catch (Exception e) {
            Log.sso.warn("KeepAlive: failed to track transient failure: " + e.getMessage());
        }
        // Fallback: if sid tracking fails, fall back to immediate 401
        Log.sso.warn("KeepAlive: token refresh failed: " + failureReason);
        httpSession.removeAttribute("sso.Profile");
        this.sendResponse(response, 401, "Refresh failed: session expired on IdP");
    }

    /**
     * Phase 4: Check database session status for session sync.
     * If the session was revoked by back-channel logout, returns 401.
     * If the session is active, updates last_heartbeat_at.
     */
    private void checkDbSessionStatus(HttpServletRequest request, HttpServletResponse response,
            OidcProfile oidcProfile, HttpSession httpSession) throws IOException {
        try {
            String sid = oidcProfile.getIdToken().getJWTClaimsSet().getStringClaim("sid");
            if (sid == null || sid.isEmpty()) {
                Log.sso.debug("KeepAlive: no sid in OIDC profile, skipping DB session check");
                return;
            }
            String sidHash = ByteUtil.getSHA256Digest(sid.getBytes(), false);
            DbSsoSession dbSession = DbSsoSession.getSessionBySidHash(sidHash);

            if (dbSession == null) {
                Log.sso.debug("KeepAlive: no DB session found for sid_hash, skipping DB check");
                return;
            }

            String status = dbSession.getStatus();
            if (DbSsoSession.STATUS_REVOKED.equals(status)) {
                Log.sso.info("KeepAlive: session is REVOKED (back-channel logout), forcing re-authentication");
                // Phase 7: Audit log — SESSION_REVOKED detected at heartbeat
                AuditLog.audit(AuditLog.SESSION_REVOKED, dbSession.getAccountId(),
                        AuditLog.hashPrefix(sidHash), "revoked_at_heartbeat", "forcing_logout");
                httpSession.removeAttribute("sso.Profile");
                this.sendResponse(response, 401, "Session revoked by back-channel logout");
                return;
            }

            if (DbSsoSession.STATUS_EXPIRED.equals(status)) {
                Log.sso.info("KeepAlive: session is EXPIRED, forcing re-authentication");
                httpSession.removeAttribute("sso.Profile");
                this.sendResponse(response, 401, "Session expired");
                return;
            }

            // Active session — update heartbeat timestamp
            DbSsoSession.updateHeartbeatBySidHash(sidHash);

        } catch (ParseException e) {
            Log.sso.warn("KeepAlive: failed to extract sid from OIDC profile: " + e.getMessage());
        } catch (ServiceException e) {
            Log.sso.warn("KeepAlive: failed to check session status: " + e.getMessage());
        }
    }

    /**
     * Phase 4: Update last_heartbeat_at in the database after successful token refresh.
     */
    private void updateHeartbeatInDb(HttpSession httpSession, CommonProfile commonProfile) {
        if (commonProfile instanceof OidcProfile) {
            try {
                String sid = ((OidcProfile) commonProfile).getIdToken().getJWTClaimsSet().getStringClaim("sid");
                if (sid != null && !sid.isEmpty()) {
                    String sidHash = ByteUtil.getSHA256Digest(sid.getBytes(), false);
                    DbSsoSession dbSession = DbSsoSession.getSessionBySidHash(sidHash);
                    if (dbSession != null && DbSsoSession.STATUS_ACTIVE.equals(dbSession.getStatus())) {
                        DbSsoSession.updateHeartbeatBySidHash(sidHash);
                        // Phase 5: Reset transient failure count on success
                        DbSsoSession.resetTransientFailureBySidHash(sidHash);
                    }
                }
            } catch (Exception e) {
                Log.sso.warn("KeepAlive: failed to update heartbeat: " + e.getMessage());
            }
        }
    }

    private void sendResponse(HttpServletResponse httpServletResponse, int n, String string) throws IOException {
        httpServletResponse.setStatus(n);
        httpServletResponse.setContentType("application/json");
        // Phase 5: Also include heartbeat interval as header for clients that read headers
        httpServletResponse.setHeader("X-Heartbeat-Interval", String.valueOf(this.configBuilder.getHeartbeatIntervalSeconds()));
        PrintWriter printWriter = httpServletResponse.getWriter();
        StringBuilder json = new StringBuilder();
        json.append("{\"status\":\"").append(string).append("\"");
        json.append(",\"code\":").append(n);
        // Phase 4: Include heartbeat interval for client-side configuration
        if (this.configBuilder.getSessionSyncEnabled()) {
            json.append(",\"heartbeatInterval\":").append(this.configBuilder.getHeartbeatIntervalSeconds());
            json.append(",\"sessionSync\":true");
        } else {
            json.append(",\"heartbeatInterval\":").append(120);
            json.append(",\"sessionSync\":false");
        }
        json.append("}");
        printWriter.write(json.toString());
        printWriter.flush();
    }
}
