package com.iwayvietnam.zmsso;

import com.iwayvietnam.zmsso.db.DbSsoSession;
import com.iwayvietnam.zmsso.pac4j.ConfigBuilder;
import com.iwayvietnam.zmsso.util.Log;
import com.iwayvietnam.zmsso.util.AuditLog;
import java.sql.Timestamp;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import com.zimbra.common.service.ServiceException;

/**
 * Phase 4: Watchdog thread for cleaning up expired sessions.
 * <p>
 * Runs periodically (every {@code watchdogIntervalSeconds}) and marks sessions
 * as {@code EXPIRED} when their {@code last_heartbeat_at} timestamp is older
 * than {@code heartbeatIntervalSeconds + transientFailureGraceSeconds}.
 * </p>
 * <p>
 * Only started when {@code oidc.sessionSync.watchdogEnabled=true}.
 * Uses a single-thread scheduled executor to avoid concurrency issues.
 * </p>
 */
public class SessionSyncWatchdog {
    private final ConfigBuilder configBuilder;
    private ScheduledExecutorService scheduler;

    public SessionSyncWatchdog() {
        this.configBuilder = ConfigBuilder.getInstance();
    }

    public void start() {
        Integer intervalSeconds = configBuilder.getWatchdogIntervalSeconds();
        Integer batchSize = configBuilder.getWatchdogBatchSize();
        Integer heartbeatInterval = configBuilder.getHeartbeatIntervalSeconds();
        Integer transientFailureGrace = configBuilder.getTransientFailureGraceSeconds();

        if (intervalSeconds <= 0) {
            Log.sso.warn("SessionSyncWatchdog: interval is <= 0, not starting");
            return;
        }

        long stalenessSeconds = (long) heartbeatInterval + (long) transientFailureGrace;

        Log.sso.info("Starting SessionSyncWatchdog: interval=" + intervalSeconds +
                "s, batchSize=" + batchSize + ", stalenessThreshold=" + stalenessSeconds + "s");

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "SessionSyncWatchdog");
            t.setDaemon(true);
            return t;
        });

        scheduler.scheduleAtFixedRate(() -> {
            try {
                runWatchdogCycle(stalenessSeconds, batchSize);
            } catch (Exception e) {
                Log.sso.error("SessionSyncWatchdog: error in watchdog cycle: " + e.getMessage(), e);
            }
        }, intervalSeconds, intervalSeconds, TimeUnit.SECONDS);
    }

    private void runWatchdogCycle(long stalenessSeconds, int batchSize) {
        try {
            Timestamp threshold = new Timestamp(System.currentTimeMillis() - stalenessSeconds * 1000L);
            // Phase 5: Also expire sessions stuck in TRANSIENT_ERROR state
            int expired = DbSsoSession.expireStaleSessions(threshold, batchSize);
            int transientCleared = DbSsoSession.clearStaleTransientErrors(threshold, batchSize);
            if (expired > 0 || transientCleared > 0) {
                Log.sso.info("SessionSyncWatchdog: expired " + expired + " stale sessions (threshold: " +
                        stalenessSeconds + "s, batch: " + batchSize + "), cleared " +
                        transientCleared + " transient-error sessions");
                // Phase 7: Audit log — HEARTBEAT_TIMEOUT
                if (expired > 0) {
                    AuditLog.audit(AuditLog.HEARTBEAT_TIMEOUT, null, "(batch=" + expired + ")",
                            "stale_threshold=" + stalenessSeconds + "s", "expired");
                }
                if (transientCleared > 0) {
                    AuditLog.audit(AuditLog.HEARTBEAT_TIMEOUT, null, "(batch=" + transientCleared + ")",
                            "transient_error_stale", "escalated_to_expired");
                }
            }
        } catch (ServiceException e) {
            Log.sso.error("SessionSyncWatchdog: failed to expire stale sessions: " + e.getMessage(), e);
        }
    }

    public void stop() {
        if (scheduler != null && !scheduler.isShutdown()) {
            Log.sso.info("Stopping SessionSyncWatchdog");
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(30, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                scheduler.shutdownNow();
            }
        }
    }
}
