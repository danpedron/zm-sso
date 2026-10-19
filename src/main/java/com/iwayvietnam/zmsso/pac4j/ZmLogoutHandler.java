package com.iwayvietnam.zmsso.pac4j;

import com.iwayvietnam.zmsso.db.DbSsoSession;
import com.iwayvietnam.zmsso.util.Log;
import com.zimbra.common.localconfig.LC;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.StringUtil;
import com.zimbra.common.util.ZimbraCookie;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.cs.account.AuthTokenException;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.auth.AuthContext;
import com.zimbra.cs.service.AuthProvider;
import com.zimbra.cs.servlet.util.AuthUtil;
import java.util.HashMap;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.logout.handler.DefaultLogoutHandler;
import org.pac4j.core.logout.handler.LogoutHandler;
import org.pac4j.jee.context.JEEContext;

public final class ZmLogoutHandler
extends DefaultLogoutHandler
implements LogoutHandler {
    private static final Provisioning prov = Provisioning.getInstance();
    private static final String X_ORIGINATING_IP_HEADER = LC.zimbra_http_originating_ip_header.value();
    private static final String USER_AGENT_HEADER = "User-Agent";

    public void destroySessionFront(WebContext webContext, SessionStore sessionStore, String string) {
        Log.sso.info((Object) "Destroy front channel sso session");
        try {
            super.destroySessionFront(webContext, sessionStore, string);
            this.clearAuthToken(webContext, string);
        }
        catch (ServiceException serviceException) {
            Log.sso.error((Object) serviceException);
        }
        catch (RuntimeException runtimeException) {
            Log.sso.error((Object) ("destroySessionFront: threw RuntimeException: " + runtimeException));
        }
    }

    public void destroySessionBack(WebContext webContext, SessionStore sessionStore, String string) {
        Log.sso.info((Object) "Destroy back channel sso session");
        try {
            super.destroySessionBack(webContext, sessionStore, string);
            this.singleLogout(string);
        }
        catch (ServiceException serviceException) {
            Log.sso.error((Object) serviceException);
        }
        catch (RuntimeException runtimeException) {
            Log.sso.error((Object) ("destroySessionBack: threw RuntimeException: " + runtimeException));
        }
    }

    public void singleLogin(WebContext webContext, String string, String string2, String string3) throws ServiceException {
        this.singleLogin(webContext, string, string2, string3, null);
    }

    // Phase 3 overload: stores sid_hash and auth_token_digest for back-channel logout
    public void singleLogin(WebContext webContext, String accountName, String ssoToken, String clientName, String sidHash) throws ServiceException {
        Log.sso.info("Perform single login for account: %s", new Object[]{accountName});
        HashMap<String, Object> hashMap = new HashMap<String, Object>(8);
        String originClientIp = webContext.getRemoteAddr();
        String forwardedFor = webContext.getRequestHeader(X_ORIGINATING_IP_HEADER).orElse(originClientIp);
        String userAgent = webContext.getRequestHeader(USER_AGENT_HEADER).orElse(null);
        hashMap.put("ocip", forwardedFor);
        hashMap.put("remoteip", originClientIp);
        hashMap.put("anp", accountName);
        hashMap.put("ua", userAgent);
        Account account = prov.getAccountByName(accountName);
        prov.ssoAuthAccount(account, AuthContext.Protocol.soap, hashMap);
        AuthToken authToken = AuthProvider.getAuthToken((Account) account, (boolean) false);
        this.setAuthTokenCookie(webContext, authToken);
        String authTokenDigest = authToken.getDigest();
        if (sidHash != null) {
            Log.sso.debug("Single login with sid_hash for account: %s", new Object[]{accountName});
        }
        if (!StringUtil.isNullOrEmpty((String) ssoToken)) {
            DbSsoSession.ssoSessionLogin(
                    (Account) account, (String) ssoToken, (String) clientName,
                    (String) forwardedFor, (String) originClientIp, (String) userAgent,
                    sidHash, authTokenDigest);
        }
    }

    private void setAuthTokenCookie(WebContext webContext, AuthToken authToken) throws ServiceException {
        if (webContext instanceof JEEContext) {
            JEEContext jEEContext = (JEEContext) webContext;
            boolean bl = AuthToken.isAnyAdmin((AuthToken) authToken);
            authToken.encode(jEEContext.getNativeResponse(), bl, webContext.isSecure());
            Log.sso.debug("Set auth token cookie for account id: %s", new Object[]{authToken.getAccountId()});
        }
    }

    private void clearAuthToken(WebContext webContext, String string) throws ServiceException {
        if (string == null) {
            Log.sso.warn("SSO token is null, skipping auth token clear");
            return;
        }
        String string2 = DbSsoSession.ssoSessionLogout((String) string);
        Log.sso.debug("Update sso session logout for account id: %s", new Object[]{string2});
        if (webContext instanceof JEEContext) {
            JEEContext jEEContext = (JEEContext) webContext;
            AuthToken authToken = AuthUtil.getAuthTokenFromHttpReq((HttpServletRequest) jEEContext.getNativeRequest(), (boolean) false);
            Optional<AuthToken> optional = Optional.ofNullable(authToken);
            if (optional.isPresent()) {
                Log.sso.info("Clear auth token for account: %s", new Object[]{authToken.getAccount().getName()});
                authToken.encode(jEEContext.getNativeRequest(), jEEContext.getNativeResponse(), true);
                try {
                    authToken.deRegister();
                }
                catch (AuthTokenException authTokenException) {
                    throw ServiceException.FAILURE((String) authTokenException.getMessage(), (Throwable) authTokenException);
                }
            }
            ZimbraCookie.clearCookie((HttpServletResponse) jEEContext.getNativeResponse(), (String) "ZM_AUTH_TOKEN");
        }
    }

    private void singleLogout(String string) throws ServiceException {
        if (string == null) {
            Log.sso.warn("SSO token is null, skipping single logout");
            return;
        }
        String string2 = DbSsoSession.ssoSessionLogout((String) string);
        if (!StringUtil.isNullOrEmpty((String) string2)) {
            Account account = prov.getAccountById(string2);
            if (account == null) {
                Log.sso.warn("Account not found for back-channel logout: %s", new Object[]{string2});
                return;
            }
            int n = account.getAuthTokenValidityValue();
            if (n > 99) {
                account.setAuthTokenValidityValue(1);
            } else {
                account.setAuthTokenValidityValue(n + 1);
            }
            Log.sso.info("Change validity value for account: %s", new Object[]{account.getName()});
        }
    }
}
