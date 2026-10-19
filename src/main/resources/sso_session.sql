CREATE TABLE IF NOT EXISTS sso_session (
    sso_token           VARCHAR(255) NOT NULL,
    account_id          VARCHAR(127) NOT NULL,
    account_name        VARCHAR(255) NOT NULL,
    protocol            VARCHAR(64),
    origin_client_ip    VARCHAR(64),
    remote_ip           VARCHAR(64),
    user_agent          VARCHAR(255),
    login_at            TIMESTAMP,
    logout_at           TIMESTAMP,

    -- Phase 3: Back-channel logout support
    sid_hash            VARCHAR(255),
    pac4j_session_id    VARCHAR(255),
    auth_token_digest   VARCHAR(255),
    status              VARCHAR(32) DEFAULT 'ACTIVE',
    last_heartbeat_at   TIMESTAMP,
    logout_jti          VARCHAR(255),

    -- Phase 5: Transient failure tracking
    transient_failure_count INT DEFAULT 0,

    PRIMARY KEY (sso_token, account_id),
    UNIQUE INDEX i_sso_token (sso_token),
    INDEX i_account_id (account_id),
    INDEX i_sso_sid_hash (sid_hash),
    INDEX i_sso_logout_jti (logout_jti),
    CONSTRAINT fk_sso_session_mailbox_id FOREIGN KEY (account_id) REFERENCES mailbox(account_id) ON DELETE CASCADE
) ENGINE = InnoDB;
