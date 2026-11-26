// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.transport;

import com.certmanagement.service.audit.AgentTokenAuditRecorder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * Issues and checks the bearer tokens agents use to reach the HTTPS agent gateway.
 *
 * <p>Only a SHA-256 hash of each token is stored. The plain value is shown once, when it is
 * created, the same way most platforms handle API keys. A token belongs to one organization and
 * the gateway lets it read only that organization's inbound queue and stamps that organization
 * on everything it sends, so the token itself is the proof of who sent a message.
 */
@Slf4j
@Service
public class AgentTokenService {

    /** Every agent token starts with this, so secret scanners and people can recognise one. */
    public static final String TOKEN_PREFIX = "cpa_";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final JdbcTemplate jdbc;
    private final TransportProperties properties;
    private AgentTokenAuditRecorder auditRecorder;

    public AgentTokenService(JdbcTemplate jdbc, TransportProperties properties) {
        this.jdbc = jdbc;
        this.properties = properties;
    }

    /**
     * One agent token. {@code expiresAt} is null for a token that never expires (every token made
     * before expiry existed, and the bundled agent's bootstrap token).
     */
    public record AgentToken(long id, long organizationId, String name, String tokenPrefix, String createdBy,
                             OffsetDateTime createdAt, OffsetDateTime lastUsedAt, OffsetDateTime revokedAt,
                             OffsetDateTime expiresAt) {
        public AgentToken(long id, long organizationId, String name, String tokenPrefix, String createdBy,
                          OffsetDateTime createdAt, OffsetDateTime lastUsedAt, OffsetDateTime revokedAt) {
            this(id, organizationId, name, tokenPrefix, createdBy, createdAt, lastUsedAt, revokedAt, null);
        }
    }

    /** The plain token is only available here, at creation time. */
    public record CreatedToken(AgentToken token, String plainToken) {
    }

    /** Who a valid token is: its own id, and the organization it belongs to. */
    public record Identity(long tokenId, long organizationId) {
    }

    /**
     * Records token creation and revocation in the audit trail. Absent only where the service is built by
     * hand without Spring (some tests).
     */
    @Autowired(required = false)
    public void setAuditRecorder(AgentTokenAuditRecorder auditRecorder) {
        this.auditRecorder = auditRecorder;
    }

    /** A token that never expires. */
    @Transactional
    public CreatedToken create(long organizationId, String name, String createdBy) {
        return create(organizationId, name, createdBy, null);
    }

    /** A token that stops working at {@code expiresAt}; null for one that never expires. Audited. */
    @Transactional
    public CreatedToken create(long organizationId, String name, String createdBy, OffsetDateTime expiresAt) {
        byte[] raw = new byte[32];
        RANDOM.nextBytes(raw);
        String plain = TOKEN_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        AgentToken token = insert(organizationId, name, plain, createdBy, expiresAt);
        if (auditRecorder != null) {
            auditRecorder.tokenCreated(organizationId, token.id(), token.name(), token.expiresAt());
        }
        return new CreatedToken(token, plain);
    }

    public List<AgentToken> list(long organizationId) {
        return jdbc.query("""
                SELECT id, organization_id, name, token_prefix, created_by, created_at, last_used_at, revoked_at,
                       expires_at
                  FROM agent_tokens WHERE organization_id = ? ORDER BY created_at DESC
                """, (rs, i) -> map(rs), organizationId);
    }

    /** Revokes the organization's token; false when it is not the organization's or already revoked. Audited. */
    @Transactional
    public boolean revoke(long organizationId, long tokenId) {
        List<String> revoked = jdbc.queryForList("""
                UPDATE agent_tokens SET revoked_at = NOW()
                 WHERE id = ? AND organization_id = ? AND revoked_at IS NULL
                RETURNING name
                """, String.class, tokenId, organizationId);
        if (revoked.isEmpty()) {
            return false;
        }
        if (auditRecorder != null) {
            auditRecorder.tokenRevoked(organizationId, tokenId, revoked.get(0));
        }
        return true;
    }

    /**
     * Returns the organization a token belongs to, or empty when the token is unknown or revoked.
     * The lookup is by hash, so the comparison never touches the plain value stored anywhere.
     */
    public Optional<Long> authenticate(String plainToken) {
        return identify(plainToken).map(Identity::organizationId);
    }

    /**
     * The token's id and organization, or empty when the token is unknown, revoked or expired. Checked
     * on every gateway call, so a revoked or expired token gets 401 on its next poll.
     */
    public Optional<Identity> identify(String plainToken) {
        if (plainToken == null || !plainToken.startsWith(TOKEN_PREFIX) || plainToken.length() > 200) {
            return Optional.empty();
        }
        String hash = sha256(plainToken);
        List<long[]> rows = jdbc.query(
                "SELECT id, organization_id, token_hash FROM agent_tokens WHERE token_hash = ? AND " + VALID,
                (rs, i) -> MessageDigest.isEqual(
                        rs.getString("token_hash").getBytes(StandardCharsets.US_ASCII),
                        hash.getBytes(StandardCharsets.US_ASCII))
                        ? new long[]{rs.getLong("id"), rs.getLong("organization_id")}
                        : null,
                hash);
        Optional<Identity> found = rows.stream().filter(r -> r != null).findFirst().map(r -> {
            touch(r[0]);
            return new Identity(r[0], r[1]);
        });
        if (found.isEmpty() && isBootstrapToken(plainToken) && registerBootstrapToken()) {
            // The first organization was created after startup; the bundled agent can connect now.
            return identifyQuietly(plainToken);
        }
        return found;
    }

    /** Neither revoked nor past its expiry. */
    private static final String VALID = "revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())";

    /**
     * True for the configured bootstrap token while no organization exists to register it for. The
     * gateway answers 503 rather than 401 then, so the bundled agent keeps waiting instead of
     * treating its token as wrong.
     */
    public boolean isPendingBootstrap(String plainToken) {
        return isBootstrapToken(plainToken) && identifyQuietly(plainToken).isEmpty();
    }

    private Optional<Identity> identifyQuietly(String plainToken) {
        return jdbc.query("SELECT id, organization_id FROM agent_tokens WHERE token_hash = ? AND " + VALID,
                (rs, i) -> new Identity(rs.getLong("id"), rs.getLong("organization_id")),
                sha256(plainToken)).stream().findFirst();
    }

    private boolean isBootstrapToken(String plainToken) {
        String configured = properties.getBootstrapAgentToken();
        return configured != null && !configured.isBlank() && plainToken != null
                && MessageDigest.isEqual(configured.getBytes(StandardCharsets.UTF_8),
                        plainToken.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * On a single-server install the bundled agent needs a token before anyone has logged in.
     * When {@code certping.transport.bootstrap-agent-token} is set, it is registered for the
     * organization named by {@code bootstrap-agent-organization} (a slug), once.
     */
    @EventListener(ApplicationReadyEvent.class)
    public void onReady() {
        registerBootstrapToken();
    }

    /** Registers the bootstrap token if it is configured and not yet stored; true once it is stored. */
    public synchronized boolean registerBootstrapToken() {
        String plain = properties.getBootstrapAgentToken();
        String slug = properties.getBootstrapAgentOrganization();
        if (plain == null || plain.isBlank()) {
            return false;
        }
        if (!plain.startsWith(TOKEN_PREFIX) || plain.length() < TOKEN_PREFIX.length() + 32) {
            log.error("Ignoring certping.transport.bootstrap-agent-token: it must start with '{}' and carry at "
                    + "least 32 random characters after it", TOKEN_PREFIX);
            return false;
        }
        try {
            Integer existing = jdbc.queryForObject(
                    "SELECT COUNT(*) FROM agent_tokens WHERE token_hash = ?", Integer.class, sha256(plain));
            if (existing != null && existing > 0) {
                return true;
            }
            List<Long> orgIds = (slug == null || slug.isBlank())
                    ? jdbc.queryForList("SELECT id FROM organizations ORDER BY id LIMIT 1", Long.class)
                    : jdbc.queryForList("SELECT id FROM organizations WHERE slug = ?", Long.class, slug);
            if (orgIds.isEmpty()) {
                log.info("Bootstrap agent token waiting for its organization{}: it is registered when the "
                        + "bundled agent next connects after the organization is created.",
                        slug == null || slug.isBlank() ? "" : " (slug '" + slug + "')");
                return false;
            }
            // Never expires: the bundled agent has no way to receive a new token.
            insert(orgIds.get(0), "bundled-agent", plain, "bootstrap", null);
            log.info("Registered the bootstrap agent token for organization {}", orgIds.get(0));
            return true;
        } catch (DataAccessException e) {
            log.warn("Could not register the bootstrap agent token: {}", e.getMessage());
            return false;
        }
    }

    private AgentToken insert(long organizationId, String name, String plain, String createdBy,
                              OffsetDateTime expiresAt) {
        String display = plain.substring(0, Math.min(plain.length(), TOKEN_PREFIX.length() + 6));
        return jdbc.queryForObject("""
                INSERT INTO agent_tokens (organization_id, name, token_hash, token_prefix, created_by, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                RETURNING id, organization_id, name, token_prefix, created_by, created_at, last_used_at, revoked_at,
                          expires_at
                """, (rs, i) -> map(rs), organizationId, truncate(name, 100), sha256(plain), display,
                truncate(createdBy, 255), expiresAt);
    }

    private void touch(long id) {
        // Coarse on purpose: one write per token per minute is enough to show "last seen".
        jdbc.update("""
                UPDATE agent_tokens SET last_used_at = NOW()
                 WHERE id = ? AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '1 minute')
                """, id);
    }

    private static AgentToken map(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new AgentToken(rs.getLong("id"), rs.getLong("organization_id"), rs.getString("name"),
                rs.getString("token_prefix"), rs.getString("created_by"),
                rs.getObject("created_at", OffsetDateTime.class),
                rs.getObject("last_used_at", OffsetDateTime.class),
                rs.getObject("revoked_at", OffsetDateTime.class),
                rs.getObject("expires_at", OffsetDateTime.class));
    }

    static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }
}
