package com.iwayvietnam.zmsso.db;

import com.iwayvietnam.zmsso.util.Log;
import com.iwayvietnam.zmsso.util.AuditLog;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ByteUtil;
import com.zimbra.common.util.StringUtil;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.db.Db;
import com.zimbra.cs.db.DbPool;
import com.zimbra.cs.db.DbResults;
import com.zimbra.cs.db.DbUtil;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.IOUtils;

public final class DbSsoSession {
    private static final String SCRIPT_FILE = "sso_session.sql";
    private static final String SELECT_TABLE = "sso_session";
    private static final String SELECT_COLUMNS = "sso_token, account_id, account_name, protocol, origin_client_ip, remote_ip, user_agent, login_at, logout_at";
    private static final String SELECT_COLUMNS_FULL = "sso_token, account_id, account_name, protocol, origin_client_ip, remote_ip, user_agent, login_at, logout_at, sid_hash, pac4j_session_id, auth_token_digest, status, last_heartbeat_at, logout_jti, transient_failure_count";
    private static final String INSERT_COLUMNS = "sso_token, account_id, account_name, protocol, origin_client_ip, remote_ip, user_agent, login_at";
    private static final String KEY_COLUMN = "sso_token";
    private static final String SID_HASH_COLUMN = "sid_hash";
    private static final String ORDER_COLUMN = "login_at";

    // Existing fields
    private final String ssoToken;
    private final String accountId;
    private final String accountName;
    private final String protocol;
    private final String originClientIp;
    private final String remoteIp;
    private final String userAgent;
    private final Timestamp loginAt;
    private final Timestamp logoutAt;

    // Phase 3: New fields
    private final String sidHash;
    private final String pac4jSessionId;
    private final String authTokenDigest;
    private final String status;
    private final Timestamp lastHeartbeatAt;
    private final String logoutJti;
    private final int transientFailureCount;

    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_REVOKED = "REVOKED";
    public static final String STATUS_LOGGED_OUT = "LOGGED_OUT";
    public static final String STATUS_EXPIRED = "EXPIRED";
    public static final String STATUS_TRANSIENT_ERROR = "TRANSIENT_ERROR";

    DbSsoSession(String ssoToken, String accountId, String accountName, String protocol, String originClientIp, String remoteIp, String userAgent, Timestamp loginAt, Timestamp logoutAt) {
        this(ssoToken, accountId, accountName, protocol, originClientIp, remoteIp, userAgent, loginAt, logoutAt, null, null, null, STATUS_ACTIVE, null, null, 0);
    }

    DbSsoSession(String ssoToken, String accountId, String accountName, String protocol, String originClientIp, String remoteIp, String userAgent, Timestamp loginAt, Timestamp logoutAt, String sidHash, String pac4jSessionId, String authTokenDigest, String status, Timestamp lastHeartbeatAt, String logoutJti) {
        this(ssoToken, accountId, accountName, protocol, originClientIp, remoteIp, userAgent, loginAt, logoutAt, sidHash, pac4jSessionId, authTokenDigest, status, lastHeartbeatAt, logoutJti, 0);
    }

    DbSsoSession(String ssoToken, String accountId, String accountName, String protocol, String originClientIp, String remoteIp, String userAgent, Timestamp loginAt, Timestamp logoutAt, String sidHash, String pac4jSessionId, String authTokenDigest, String status, Timestamp lastHeartbeatAt, String logoutJti, int transientFailureCount) {
        this.ssoToken = ssoToken;
        this.accountId = accountId;
        this.accountName = accountName;
        this.protocol = protocol;
        this.originClientIp = originClientIp;
        this.remoteIp = remoteIp;
        this.userAgent = userAgent;
        this.loginAt = loginAt;
        this.logoutAt = logoutAt;
        this.sidHash = sidHash;
        this.pac4jSessionId = pac4jSessionId;
        this.authTokenDigest = authTokenDigest;
        this.status = status;
        this.lastHeartbeatAt = lastHeartbeatAt;
        this.logoutJti = logoutJti;
        this.transientFailureCount = transientFailureCount;
    }

    static DbSsoSession constructSsoSession(DbResults dbResults) {
        return new DbSsoSession(
                dbResults.getString(KEY_COLUMN),
                dbResults.getString("account_id"),
                dbResults.getString("account_name"),
                dbResults.getString("protocol"),
                dbResults.getString("origin_client_ip"),
                dbResults.getString("remote_ip"),
                dbResults.getString("user_agent"),
                (Timestamp) dbResults.getObject(ORDER_COLUMN),
                (Timestamp) dbResults.getObject("logout_at"));
    }

    static DbSsoSession constructSsoSessionFull(DbResults dbResults) {
        return new DbSsoSession(
                dbResults.getString(KEY_COLUMN),
                dbResults.getString("account_id"),
                dbResults.getString("account_name"),
                dbResults.getString("protocol"),
                dbResults.getString("origin_client_ip"),
                dbResults.getString("remote_ip"),
                dbResults.getString("user_agent"),
                (Timestamp) dbResults.getObject(ORDER_COLUMN),
                (Timestamp) dbResults.getObject("logout_at"),
                dbResults.getString(SID_HASH_COLUMN),
                dbResults.getString("pac4j_session_id"),
                dbResults.getString("auth_token_digest"),
                dbResults.getString("status"),
                (Timestamp) dbResults.getObject("last_heartbeat_at"),
                dbResults.getString("logout_jti"),
                dbResults.getInt("transient_failure_count"));
    }

    public String getSsoToken() {
        return this.ssoToken;
    }

    public String getAccountId() {
        return this.accountId;
    }

    public String getAccountName() {
        return this.accountName;
    }

    public String getProtocol() {
        return this.protocol;
    }

    public String getOriginClientIp() {
        return this.originClientIp;
    }

    public String getRemoteIp() {
        return this.remoteIp;
    }

    public String getUserAgent() {
        return this.userAgent;
    }

    public Timestamp getLoginAt() {
        return this.loginAt;
    }

    public Timestamp getLogoutAt() {
        return this.logoutAt;
    }

    // Phase 3: Additional getters
    public String getSidHash() {
        return this.sidHash;
    }

    public String getPac4jSessionId() {
        return this.pac4jSessionId;
    }

    public String getAuthTokenDigest() {
        return this.authTokenDigest;
    }

    public String getStatus() {
        return this.status;
    }

    public Timestamp getLastHeartbeatAt() {
        return this.lastHeartbeatAt;
    }

    public String getLogoutJti() {
        return this.logoutJti;
    }

    public int getTransientFailureCount() {
        return this.transientFailureCount;
    }

    public static void createSsoSessionTable() throws ServiceException {
        ClassLoader classLoader = DbSsoSession.class.getClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream(SCRIPT_FILE);
        try {
            if (inputStream == null) {
                throw ServiceException.NOT_FOUND((String) String.format("Script file '%s' not found in the classpath", SCRIPT_FILE));
            }
            Log.sso.info((Object) "Create sso session table");
            String string = new String(IOUtils.toByteArray((InputStream) inputStream));
            DbUtil.executeScript((DbPool.DbConnection) DbPool.getConnection(), (Reader) new StringReader(string));
        } catch (IOException iOException) {
            throw ServiceException.FAILURE((String) String.format("Script file '%s' cannot be loaded.", SCRIPT_FILE), (Throwable) iOException);
        } catch (SQLException sQLException) {
            throw ServiceException.FAILURE((String) "Create sso session table", (Throwable) sQLException);
        }

        // Phase 3: Migrate schema (additive, idempotent)
        migrateSsoSessionSchema();
    }

    // Phase 3: Idempotent schema migration for existing tables
    private static void migrateSsoSessionSchema() {
        try {
            if (!columnExists("sid_hash")) {
                Log.sso.info((Object) "Adding column sid_hash to sso_session");
                DbUtil.executeUpdate("ALTER TABLE " + SELECT_TABLE + " ADD COLUMN " + SID_HASH_COLUMN + " VARCHAR(255)");
            }
            if (!columnExists("pac4j_session_id")) {
                Log.sso.info((Object) "Adding column pac4j_session_id to sso_session");
                DbUtil.executeUpdate("ALTER TABLE " + SELECT_TABLE + " ADD COLUMN pac4j_session_id VARCHAR(255)");
            }
            if (!columnExists("auth_token_digest")) {
                Log.sso.info((Object) "Adding column auth_token_digest to sso_session");
                DbUtil.executeUpdate("ALTER TABLE " + SELECT_TABLE + " ADD COLUMN auth_token_digest VARCHAR(255)");
            }
            if (!columnExists("status")) {
                Log.sso.info((Object) "Adding column status to sso_session");
                DbUtil.executeUpdate("ALTER TABLE " + SELECT_TABLE + " ADD COLUMN status VARCHAR(32) DEFAULT 'ACTIVE'");
            }
            if (!columnExists("last_heartbeat_at")) {
                Log.sso.info((Object) "Adding column last_heartbeat_at to sso_session");
                DbUtil.executeUpdate("ALTER TABLE " + SELECT_TABLE + " ADD COLUMN last_heartbeat_at TIMESTAMP");
            }
            if (!columnExists("logout_jti")) {
                Log.sso.info((Object) "Adding column logout_jti to sso_session");
                DbUtil.executeUpdate("ALTER TABLE " + SELECT_TABLE + " ADD COLUMN logout_jti VARCHAR(255)");
            }
            // Phase 5: Add transient_failure_count column
            if (!columnExists("transient_failure_count")) {
                Log.sso.info((Object) "Adding column transient_failure_count to sso_session");
                DbUtil.executeUpdate("ALTER TABLE " + SELECT_TABLE + " ADD COLUMN transient_failure_count INT DEFAULT 0");
            }
            if (!indexExists("i_sso_sid_hash")) {
                Log.sso.info((Object) "Adding index i_sso_sid_hash");
                DbUtil.executeUpdate("CREATE INDEX i_sso_sid_hash ON " + SELECT_TABLE + " (" + SID_HASH_COLUMN + ")");
            }
            if (!indexExists("i_sso_logout_jti")) {
                Log.sso.info((Object) "Adding index i_sso_logout_jti");
                DbUtil.executeUpdate("CREATE INDEX i_sso_logout_jti ON " + SELECT_TABLE + " (logout_jti)");
            }
        } catch (ServiceException e) {
            Log.sso.error((Object) ("Schema migration failed: " + e.getMessage()));
        }
    }

    private static boolean columnExists(String columnName) throws ServiceException {
        DbResults rs = DbUtil.executeQuery(
                "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?",
                SELECT_TABLE, columnName);
        return rs.next() && rs.getInt(1) > 0;
    }

    private static boolean indexExists(String indexName) throws ServiceException {
        DbResults rs = DbUtil.executeQuery(
                "SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ?",
                SELECT_TABLE, indexName);
        return rs.next() && rs.getInt(1) > 0;
    }

    public static void ssoSessionLogin(Account account, String ssoToken, String protocol, String originClientIp, String remoteIp, String userAgent) throws ServiceException {
        ssoSessionLogin(account, ssoToken, protocol, originClientIp, remoteIp, userAgent, null, null);
    }

    // Phase 3: Login with sid_hash and auth_token_digest for back-channel logout
    public static void ssoSessionLogin(Account account, String ssoToken, String protocol, String originClientIp, String remoteIp, String userAgent, String sidHash, String authTokenDigest) throws ServiceException {
        String hashedToken = ByteUtil.getSHA256Digest((byte[]) ssoToken.getBytes(), (boolean) false);
        DbResults dbResults = DbUtil.executeQuery(
                String.format("SELECT %s FROM %s WHERE %s = ?", KEY_COLUMN, SELECT_TABLE, KEY_COLUMN),
                (Object[]) new Object[]{hashedToken});
        if (!dbResults.next() && !StringUtil.isNullOrEmpty((String) hashedToken)) {
            Log.sso.debug("Insert sso session login for account %s with hashed token %s)", new Object[]{account.getId(), hashedToken});
            String sql = String.format("INSERT INTO %s (%s%s) VALUES (?, ?, ?, ?, ?, ?, ?, ?%s)",
                    SELECT_TABLE, INSERT_COLUMNS,
                    ", sid_hash, auth_token_digest, status",
                    ", ?, ?, ?");
            Timestamp timestamp = new Timestamp(System.currentTimeMillis());
            String status = STATUS_ACTIVE;
            DbUtil.executeUpdate(sql, new Object[]{
                    hashedToken, account.getId(), account.getName(), protocol, originClientIp, remoteIp, userAgent, timestamp,
                    sidHash, authTokenDigest, status
            });
            // Phase 7: Structured audit log — SESSION_CREATED (no raw tokens)
            AuditLog.audit(AuditLog.SESSION_CREATED, account.getId(), AuditLog.hashPrefix(sidHash),
                    "login_success", "session_stored");
        }
    }

    // Phase 3: Look up session by sid_hash for back-channel logout
    public static DbSsoSession getSessionBySidHash(String sidHash) throws ServiceException {
        if (StringUtil.isNullOrEmpty((String) sidHash)) {
            return null;
        }
        DbResults dbResults = DbUtil.executeQuery(
                String.format("SELECT %s FROM %s WHERE %s = ? AND status = ?", SELECT_COLUMNS_FULL, SELECT_TABLE, SID_HASH_COLUMN),
                (Object[]) new Object[]{sidHash, STATUS_ACTIVE});
        if (dbResults.next()) {
            return constructSsoSessionFull(dbResults);
        }
        return null;
    }

    // Phase 3: Mark session as REVOKED (idempotent, for back-channel logout)
    public static boolean invalidateSessionBySidHash(String sidHash, String jti) throws ServiceException {
        if (StringUtil.isNullOrEmpty((String) sidHash)) {
            return false;
        }
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        int updated = DbUtil.executeUpdate(
                String.format("UPDATE %s SET status = ?, logout_at = ?, logout_jti = ? WHERE %s = ? AND status = ?",
                        SELECT_TABLE, SID_HASH_COLUMN),
                new Object[]{STATUS_REVOKED, timestamp, jti, sidHash, STATUS_ACTIVE});
        // Phase 7: Structured audit log — SESSION_REVOKED (no raw tokens)
        if (updated > 0) {
            AuditLog.audit(AuditLog.SESSION_REVOKED, null, AuditLog.hashPrefix(sidHash),
                    "backchannel_logout", "revoked");
        } else {
            AuditLog.audit(AuditLog.LOGOUT_REPLAY, null, AuditLog.hashPrefix(sidHash),
                    "not_active_or_already_revoked", "noop");
        }
        return updated > 0;
    }

    // Phase 3: Check if jti was already processed (replay protection)
    public static boolean isJtiProcessed(String jti) throws ServiceException {
        if (StringUtil.isNullOrEmpty((String) jti)) {
            return false;
        }
        DbResults dbResults = DbUtil.executeQuery(
                String.format("SELECT COUNT(*) FROM %s WHERE logout_jti = ?", SELECT_TABLE),
                (Object[]) new Object[]{jti});
        return dbResults.next() && dbResults.getInt(1) > 0;
    }

    public static String ssoSessionLogout(String ssoToken) throws ServiceException {
        String hashedToken = ByteUtil.getSHA256Digest((byte[]) ssoToken.getBytes(), (boolean) false);
        DbResults dbResults = DbUtil.executeQuery(
                String.format("SELECT %s FROM %s WHERE %s = ?", SELECT_COLUMNS, SELECT_TABLE, KEY_COLUMN),
                (Object[]) new Object[]{hashedToken});
        // Phase 7: Fix logoutAt == null — use getObject which returns null for 0000-00-00 in MariaDB
        if (dbResults.next() && dbResults.getObject("logout_at") == null) {
            Log.sso.debug("Update sso session logout with hashed token %s", new Object[]{hashedToken});
            String sql = String.format("UPDATE %s SET logout_at = ?, status = ? WHERE %s = ?", SELECT_TABLE, KEY_COLUMN);
            Timestamp timestamp = new Timestamp(System.currentTimeMillis());
            DbUtil.executeUpdate(sql, new Object[]{timestamp, STATUS_LOGGED_OUT, hashedToken});
            // Phase 7: Structured audit log — LOGOUT_COMPLETED (no raw tokens)
            AuditLog.audit(AuditLog.LOGOUT_COMPLETED, dbResults.getString("account_id"),
                    AuditLog.hashPrefix(hashedToken), "local_logout", "session_updated");
            return dbResults.getString("account_id");
        }
        return null;
    }

    // Phase 3: Update heartbeat timestamp (by sid_hash — avoids double-hashing)
    public static void updateHeartbeat(String ssoToken) throws ServiceException {
        String hashedToken = ByteUtil.getSHA256Digest((byte[]) ssoToken.getBytes(), (boolean) false);
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        DbUtil.executeUpdate(
                String.format("UPDATE %s SET last_heartbeat_at = ? WHERE %s = ? AND status = ?", SELECT_TABLE, KEY_COLUMN),
                new Object[]{timestamp, hashedToken, STATUS_ACTIVE});
    }

    // Phase 5: Update heartbeat by sid_hash (used by KeepAliveHandler where only sid_hash is available)
    public static void updateHeartbeatBySidHash(String sidHash) throws ServiceException {
        if (StringUtil.isNullOrEmpty((String) sidHash)) {
            return;
        }
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        DbUtil.executeUpdate(
                String.format("UPDATE %s SET last_heartbeat_at = ? WHERE %s = ? AND status = ?", SELECT_TABLE, SID_HASH_COLUMN),
                new Object[]{timestamp, sidHash, STATUS_ACTIVE});
    }

    // Phase 5: Increment transient failure count by sid_hash
    public static int incrementTransientFailureBySidHash(String sidHash) throws ServiceException {
        if (StringUtil.isNullOrEmpty((String) sidHash)) {
            return 0;
        }
        int updated = DbUtil.executeUpdate(
                String.format("UPDATE %s SET transient_failure_count = transient_failure_count + 1 WHERE %s = ? AND status = ?",
                        SELECT_TABLE, SID_HASH_COLUMN),
                new Object[]{sidHash, STATUS_ACTIVE});
        if (updated > 0) {
            DbResults rs = DbUtil.executeQuery(
                    String.format("SELECT transient_failure_count FROM %s WHERE %s = ?", SELECT_TABLE, SID_HASH_COLUMN),
                    (Object[]) new Object[]{sidHash});
            if (rs.next()) {
                return rs.getInt(1);
            }
        }
        return 0;
    }

    // Phase 5: Reset transient failure count by sid_hash
    public static void resetTransientFailureBySidHash(String sidHash) throws ServiceException {
        if (StringUtil.isNullOrEmpty((String) sidHash)) {
            return;
        }
        DbUtil.executeUpdate(
                String.format("UPDATE %s SET transient_failure_count = 0 WHERE %s = ? AND status = ?",
                        SELECT_TABLE, SID_HASH_COLUMN),
                new Object[]{sidHash, STATUS_ACTIVE});
    }

    // Phase 5: Set session status to TRANSIENT_ERROR by sid_hash
    public static void setTransientErrorBySidHash(String sidHash) throws ServiceException {
        if (StringUtil.isNullOrEmpty((String) sidHash)) {
            return;
        }
        DbUtil.executeUpdate(
                String.format("UPDATE %s SET status = ? WHERE %s = ? AND status = ?",
                        SELECT_TABLE, SID_HASH_COLUMN),
                new Object[]{STATUS_TRANSIENT_ERROR, sidHash, STATUS_ACTIVE});
    }

    public static List<DbSsoSession> GetAllSsoSessions(Integer n, Integer n2) throws ServiceException {
        ArrayList<DbSsoSession> arrayList = new ArrayList<DbSsoSession>();
        // Phase 7: Use SELECT_COLUMNS_FULL to include status, sid_hash, etc. for audit
        // Also use constructSsoSessionFull instead of constructSsoSession so that
        // logoutAt null-safety is handled (logout_at default is 0000-00-00, treated as null by MariaDB driver)
        StringBuilder stringBuilder = new StringBuilder(String.format("SELECT %s AS ref_key FROM %s ORDER BY %s DESC",
                KEY_COLUMN, SELECT_TABLE, ORDER_COLUMN));
        if (Db.supports((Db.Capability) Db.Capability.LIMIT_CLAUSE) && n2 != null && n2 > 0) {
            if (n != null && n > 0) {
                stringBuilder.append(" ").append(Db.getInstance().limit(n.intValue(), n2.intValue()));
            } else {
                stringBuilder.append(" ").append(Db.getInstance().limit(n2.intValue()));
            }
        }
        String string = String.format("SELECT %s FROM %s INNER JOIN (%s) AS joinQuery ON joinQuery.ref_key = %s.%s",
                SELECT_COLUMNS_FULL, SELECT_TABLE, stringBuilder, SELECT_TABLE, KEY_COLUMN);
        DbResults dbResults = DbUtil.executeQuery((String) string, (Object[]) new Object[0]);
        while (dbResults.next()) {
            arrayList.add(DbSsoSession.constructSsoSessionFull(dbResults));
        }
        // Phase 7: Audit — admin queried all sessions
        AuditLog.audit(AuditLog.HEARTBEAT_ACCEPTED, null, "(count=" + arrayList.size() + ")",
                "admin_query", "returning_full_fields");
        return arrayList;
    }

    public static Integer CountAllSsoSessions() throws ServiceException {
        DbResults dbResults = DbUtil.executeQuery(String.format("SELECT COUNT(*) FROM %s", SELECT_TABLE), (Object[]) new Object[0]);
        if (dbResults.next()) {
            return dbResults.getInt(1);
        }
        return 0;
    }

    // Phase 4: Expire stale sessions (used by watchdog)
    public static int expireStaleSessions(Timestamp threshold, int batchSize) throws ServiceException {
        Timestamp now = new Timestamp(System.currentTimeMillis());
        int updated = DbUtil.executeUpdate(
                String.format("UPDATE %s SET status = ?, logout_at = ? WHERE last_heartbeat_at < ? AND status = ? AND logout_at IS NULL LIMIT %d",
                        SELECT_TABLE, batchSize),
                STATUS_EXPIRED, now, threshold, STATUS_ACTIVE);
        if (updated > 0) {
            Log.sso.info("Watchdog: expired %d stale sessions (threshold: %s)", new Object[]{updated, threshold});
            // Phase 7: Structured audit log
            AuditLog.audit(AuditLog.HEARTBEAT_TIMEOUT, null, "(batch=" + updated + ")",
                    "stale_threshold=" + threshold, "expired");
        }
        return updated;
    }

    // Phase 5: Clear stale TRANSIENT_ERROR sessions (escalate to EXPIRED)
    public static int clearStaleTransientErrors(Timestamp threshold, int batchSize) throws ServiceException {
        Timestamp now = new Timestamp(System.currentTimeMillis());
        int updated = DbUtil.executeUpdate(
                String.format("UPDATE %s SET status = ?, logout_at = ? WHERE last_heartbeat_at < ? AND status = ? AND logout_at IS NULL LIMIT %d",
                        SELECT_TABLE, batchSize),
                STATUS_EXPIRED, now, threshold, STATUS_TRANSIENT_ERROR);
        return updated;
    }
}
