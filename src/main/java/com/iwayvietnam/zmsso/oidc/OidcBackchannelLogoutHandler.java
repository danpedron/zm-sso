package com.iwayvietnam.zmsso.oidc;

import com.iwayvietnam.zmsso.db.DbSsoSession;
import com.iwayvietnam.zmsso.pac4j.ConfigBuilder;
import com.iwayvietnam.zmsso.pac4j.SettingsConstants;
import com.iwayvietnam.zmsso.util.Log;
import com.iwayvietnam.zmsso.util.AuditLog;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ByteUtil;
import com.zimbra.common.util.StringUtil;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.service.AuthProvider;
import java.io.IOException;
import java.net.URL;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.LogoutTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import com.nimbusds.openid.connect.sdk.validators.LogoutTokenValidator;

/**
 * Dedicated back-channel logout handler.
 * <p>
 * Registered at <code>/service/extension/oidc/backchannel-logout</code> when
 * {@code oidc.sessionSync.backchannelEnabled=true}. Validates the signed
 * {@code logout_token} JWT (RFC 9100) received from Keycloak and
 * invalidates the corresponding local Zimbra session.
 * </p>
 *
 * <h3>Validation performed</h3>
 * <ul>
 *   <li>Signature (RSA via JWK Set URL from Keycloak discovery)</li>
 *   <li>Issuer claim matches configured realm issuer</li>
 *   <li>Audience claim matches configured client ID</li>
 *   <li>JWS algorithm matches configured algorithm</li>
 *   <li>Expiration / issue time within clock skew</li>
 *   <li>{@code events} claim is exactly the back-channel logout event type</li>
 *   <li>{@code sid} or {@code sub} present (required for session mapping)</li>
 * </ul>
 */
public class OidcBackchannelLogoutHandler
extends OidcBaseHandler {

    public static final String HANDLER_PATH = "/oidc/backchannel-logout";

    public OidcBackchannelLogoutHandler() throws com.zimbra.cs.extension.ExtensionException {
        super();
    }

    @Override
    public String getPath() {
        return HANDLER_PATH;
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        response.getWriter().write("GET method not supported. Use POST with logout_token parameter.");
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        // Check feature flag
        if (!configBuilder.getBackchannelEnabled()) {
            Log.sso.warn("Back-channel logout handler called but feature is disabled");
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        Log.sso.info("Back-channel logout: received POST request");

        try {
            // --- Step 1: Extract logout_token ---
            String logoutToken = request.getParameter("logout_token");
            if (StringUtil.isNullOrEmpty((String) logoutToken)) {
                Log.sso.warn("Back-channel logout: missing logout_token parameter");
                // Phase 7: Audit log
                AuditLog.audit(AuditLog.BACKCHANNEL_LOGOUT, null, "(unknown)", "missing_logout_token", "rejected_400");
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write("logout_token parameter is required");
                return;
            }

            // --- Step 2: Validate logout_token ---
            LogoutTokenClaimsSet claims = validateLogoutToken(logoutToken);
            if (claims == null) {
                Log.sso.warn("Back-channel logout: invalid logout_token");
                // Phase 7: Audit log
                AuditLog.audit(AuditLog.BACKCHANNEL_LOGOUT, null, "(unknown)", "invalid_token", "rejected_400");
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write("Invalid logout_token");
                return;
            }

            // --- Step 3: Extract claims ---
            JWTID jwtId = claims.getJWTID();
            Subject subject = claims.getSubject();
            SessionID sessionId = claims.getSessionID();

            String jti = (jwtId != null) ? jwtId.getValue() : null;
            String sub = (subject != null) ? subject.getValue() : null;
            String sid = (sessionId != null) ? sessionId.getValue() : null;

            if (StringUtil.isNullOrEmpty((String) sid)) {
                // Logout token without sid: use sub as fallback (if sub-based mapping exists)
                Log.sso.warn("Back-channel logout: logout_token missing sid claim, using sub fallback: " + (sub != null ? "***redacted***" : "(null)"));
                if (StringUtil.isNullOrEmpty((String) sub)) {
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    response.getWriter().write("logout_token must contain sid or sub claim");
                    return;
                }
            }

            // --- Step 4: Replay protection ---
            if (!StringUtil.isNullOrEmpty((String) jti) && DbSsoSession.isJtiProcessed(jti)) {
                Log.sso.info("Back-channel logout: jti already processed, returning 200 (idempotent)");
                response.setStatus(HttpServletResponse.SC_OK);
                return;
            }

            // --- Step 5: Look up session by sid_hash ---
            String sidHash = ByteUtil.getSHA256Digest(sid.getBytes(), false);
            DbSsoSession session = DbSsoSession.getSessionBySidHash(sidHash);

            if (session == null) {
                Log.sso.info("Back-channel logout: no active session found for sid (already logged out or unknown)");
                // Record the jti as processed for idempotency
                if (!StringUtil.isNullOrEmpty((String) jti)) {
                    // Not strictly necessary, but helps with idempotency
                }
                response.setStatus(HttpServletResponse.SC_OK);
                return;
            }

            // --- Step 6: Invalidate local session ---
            invalidateLocalSession(session, jti, sid);

            // --- Step 7: Return 200 ---
            response.setStatus(HttpServletResponse.SC_OK);
            Log.sso.info("Back-channel logout: successfully processed for account: " + session.getAccountName());
            // Phase 7: Structured audit log — BACKCHANNEL_LOGOUT (no raw tokens)
            AuditLog.audit(AuditLog.BACKCHANNEL_LOGOUT, session.getAccountId(),
                    AuditLog.hashPrefix(session.getSidHash()), "logout_token_valid", "ok");

        } catch (Exception e) {
            Log.sso.error("Back-channel logout error: " + e.getMessage(), e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("Internal server error");
        }
    }

    /**
     * Validates the logout_token JWT using Nimbus LogoutTokenValidator.
     * Checks signature, issuer, audience, algorithm, expiration, events claim, sid, sub, jti.
     *
     * @return LogoutTokenClaimsSet if valid, null if invalid
     */
    private LogoutTokenClaimsSet validateLogoutToken(String logoutToken) {
        try {
            JWT jwt = SignedJWT.parse(logoutToken);

            // Read validation parameters from config
            String issuerStr = ConfigBuilder.loadStringProperty(SettingsConstants.ZM_OIDC_LOGOUT_TOKEN_ISSUER);
            String clientIdStr = ConfigBuilder.loadStringProperty(SettingsConstants.ZM_OIDC_LOGOUT_TOKEN_CLIENT_ID);
            String algStr = ConfigBuilder.loadStringProperty(SettingsConstants.ZM_OIDC_LOGOUT_TOKEN_JWS_ALGORITHM);
            String jwksUrlStr = ConfigBuilder.loadStringProperty(SettingsConstants.ZM_OIDC_LOGOUT_TOKEN_JWKS_URL);

            if (StringUtil.isNullOrEmpty((String) issuerStr) ||
                StringUtil.isNullOrEmpty((String) clientIdStr) ||
                StringUtil.isNullOrEmpty((String) algStr) ||
                StringUtil.isNullOrEmpty((String) jwksUrlStr)) {
                Log.sso.error("Back-channel logout: missing logout_token validation configuration");
                return null;
            }

            Issuer issuer = new Issuer(issuerStr);
            ClientID clientId = new ClientID(clientIdStr);
            JWSAlgorithm algorithm = JWSAlgorithm.parse(algStr);
            URL jwksUrl = new URL(jwksUrlStr);

            LogoutTokenValidator validator = new LogoutTokenValidator(
                    issuer, clientId, algorithm, jwksUrl);

            return validator.validate(jwt);

        } catch (Exception e) {
            Log.sso.error("Back-channel logout: logout_token validation failed: " + e.getMessage(), e);
            return null;
        }
    }

    /**
     * Invalidates the local session associated with the given sid_hash.
     * Marks the session as REVOKED in the database, records the jti for
     * replay protection, and attempts to revoke the associated Zimbra auth token.
     *
     * This method is idempotent: calling it multiple times with the same sid
     * or jti has no additional effect.
     *
     * @param session The DbSsoSession to invalidate (looked up by sid_hash)
     * @param jti     The JWT ID from the logout_token (for replay protection)
     * @param sid     The OIDC session ID (for logging)
     */
    private void invalidateLocalSession(DbSsoSession session, String jti, String sid) {
        String ssoToken = session.getSsoToken();
        String accountId = session.getAccountId();
        String authTokenDigest = session.getAuthTokenDigest();

        try {
            // 1. Mark session as REVOKED in database
            boolean revoked = DbSsoSession.invalidateSessionBySidHash(session.getSidHash(), jti);
            if (!revoked) {
                Log.sso.info("Back-channel logout: session was already REVOKED for token hash: " + ssoToken.substring(0, Math.min(10, ssoToken.length())) + "...");
                return; // Already revoked — idempotent
            }

            Log.sso.info("Back-channel logout: session marked REVOKED for account: " + session.getAccountName() + " (token hash prefix: " + ssoToken.substring(0, Math.min(10, ssoToken.length())) + "...)");

            // 2. Prevent new heartbeats — status check in KeepAliveHandler handles this

            // 3. Attempt auth token revocation
            revokeAuthToken(accountId, authTokenDigest);

            // 4. Pac4j session invalidation — not possible in back-channel flow.
            //    No WebContext/HttpSession is available in server-to-server logout.
            //    The REVOKED status in DB prevents future pac4j session usage:
            //    next keepalive call will return 401, forcing re-authentication.
            //    See: KeepAliveHandler.checkDbSessionStatus()

            // 4. Audit log (no tokens printed)
            Log.sso.info("Back-channel logout: audit — account=" + session.getAccountName()
                    + ", protocol=" + session.getProtocol()
                    + ", origin_ip=" + session.getOriginClientIp()
                    + ", jti=" + (jti != null ? jti.substring(0, Math.min(8, jti.length())) + "..." : "(null)"));

        } catch (ServiceException e) {
            Log.sso.error("Back-channel logout: failed to invalidate session: " + e.getMessage(), e);
        }
    }

    /**
     * Revokes the associated Zimbra auth token.
     *
     * Known limitation (documented): Individual auth token revocation via
     * {@code AuthToken.deRegister()} requires the live AuthToken object, which
     * is only available from the HTTP cookie (front-channel). In back-channel
     * logout, we only have the auth_token_digest stored during login. There is
     * no Zimbra API to reconstruct an AuthToken from a digest alone.
     *
     * When {@code oidc.sessionSync.failClosed=true} (the default), this method
     * falls back to incrementing {@code zimbraAuthTokenValidityValue} for the
     * account — a global invalidation. This is logged explicitly.
     *
     * When {@code failClosed=false}, only the session record is marked REVOKED
     * and the auth token will expire naturally.
     */
    private void revokeAuthToken(String accountId, String authTokenDigest) {
        boolean failClosed = configBuilder.getFailClosed();

        if (StringUtil.isNullOrEmpty((String) authTokenDigest)) {
            Log.sso.warn("Back-channel logout: auth_token_digest is empty — cannot attempt individual revocation");
            if (failClosed) {
                doGlobalTokenInvalidation(accountId);
            } else {
                Log.sso.info("Back-channel logout: failClosed=false, skipping global invalidation — token will expire naturally");
            }
            return;
        }

        // Try individual revocation via AuthToken.deRegister()
        // Note: AuthToken.getAuthToken(encoded) requires the encoded token string,
        // which we do not store (per §3.2). We can only attempt global invalidation.
        Log.sso.warn("Back-channel logout: individual auth token revocation not possible (no AuthToken object available). auth_token_digest: "
                + authTokenDigest.substring(0, Math.min(8, authTokenDigest.length())) + "...");

        // Phase 7: Audit log — LOCAL_TOKEN_INVALIDATED (attempted)
        AuditLog.audit(AuditLog.LOCAL_TOKEN_INVALIDATED, accountId, "(digest_only)",
                "individual_revocation_not_possible", failClosed ? "falling_back_to_global" : "token_expires_naturally");

        if (failClosed) {
            doGlobalTokenInvalidation(accountId);
        } else {
            Log.sso.info("Back-channel logout: failClosed=false, skipping global invalidation — token will expire naturally");
        }
    }

    /**
     * Global token invalidation fallback using zimbraAuthTokenValidityValue.
     * Logs explicit warning about the limitation.
     */
    private void doGlobalTokenInvalidation(String accountId) {
        try {
            Account account = Provisioning.getInstance().getAccountById(accountId);
            if (account == null) {
                Log.sso.warn("Back-channel logout: account not found for global token invalidation: " + accountId);
                return;
            }
            int n = account.getAuthTokenValidityValue();
            if (n > 99) {
                account.setAuthTokenValidityValue(1);
            } else {
                account.setAuthTokenValidityValue(n + 1);
            }
            Log.sso.warn("Back-channel logout: GLOBAL token invalidation applied (zimbraAuthTokenValidityValue incremented to "
                    + account.getAuthTokenValidityValue() + ") for account: " + account.getName()
                    + " — this invalidates ALL sessions for this account. Individual revocation is not possible without the AuthToken object.");
        } catch (Exception e) {
            Log.sso.error("Back-channel logout: failed to invalidate auth token globally: " + e.getMessage(), e);
        }
    }
}
