// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.messaging.model.AgentCaStatus;
import com.certmanagement.messaging.model.AgentInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import tools.jackson.databind.ObjectMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

/**
 * The Agents page data ({@code agent_info}): per agent token, the last {@link AgentInfo} it reported
 * and when its last heartbeat arrived, read together with the token and its CA status.
 */
@Slf4j
@Repository
public class AgentInfoStore {

    /** One agent token with what is known about the agent using it. */
    public record AgentRow(long tokenId, String name, String tokenPrefix, String createdBy,
                           OffsetDateTime tokenCreatedAt, OffsetDateTime tokenExpiresAt, OffsetDateTime revokedAt,
                           OffsetDateTime lastUsedAt, OffsetDateTime lastHeartbeatAt,
                           AgentInfo agentInfo, AgentCaStatus caStatus) {
    }

    private static final String SELECT = """
            SELECT t.id, t.name, t.token_prefix, t.created_by, t.created_at, t.expires_at, t.revoked_at,
                   t.last_used_at, i.last_heartbeat_at, i.agent_info::text AS agent_info,
                   c.ca_status::text AS ca_status
              FROM agent_tokens t
              LEFT JOIN agent_info i ON i.agent_token_id = t.id
              LEFT JOIN agent_ca_status c ON c.agent_token_id = t.id AND c.organization_id = t.organization_id
             WHERE t.organization_id = ?
            """;

    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public AgentInfoStore(JdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
    }

    /**
     * Records a heartbeat from the agent using {@code agentTokenId}, with its info when it sent one
     * (a heartbeat without info keeps the info last reported). Only for a token of that organization.
     */
    public void recordHeartbeat(long organizationId, long agentTokenId, AgentInfo agentInfo) {
        AgentInfo clean = AgentInfoSanitizer.sanitize(agentInfo);
        // Serialized from the sanitized typed object, so only its known fields are stored.
        String json = clean == null ? null : objectMapper.writeValueAsString(clean);
        jdbc.update("""
                INSERT INTO agent_info (agent_token_id, organization_id, agent_info, last_heartbeat_at, reported_at)
                SELECT t.id, t.organization_id, CAST(? AS jsonb), NOW(), CASE WHEN ? THEN NOW() END
                  FROM agent_tokens t WHERE t.id = ? AND t.organization_id = ?
                ON CONFLICT (agent_token_id) DO UPDATE
                   SET last_heartbeat_at = EXCLUDED.last_heartbeat_at,
                       agent_info = COALESCE(EXCLUDED.agent_info, agent_info.agent_info),
                       reported_at = COALESCE(EXCLUDED.reported_at, agent_info.reported_at)
                """, json, json != null, agentTokenId, organizationId);
    }

    /** Every agent token of the organization, revoked and expired ones included. */
    public List<AgentRow> list(long organizationId) {
        return jdbc.query(SELECT, (rs, i) -> map(rs), organizationId);
    }

    public Optional<AgentRow> find(long organizationId, long agentTokenId) {
        return jdbc.query(SELECT + " AND t.id = ?", (rs, i) -> map(rs), organizationId, agentTokenId)
                .stream().findFirst();
    }

    private AgentRow map(ResultSet rs) throws SQLException {
        return new AgentRow(rs.getLong("id"), rs.getString("name"), rs.getString("token_prefix"),
                rs.getString("created_by"),
                rs.getObject("created_at", OffsetDateTime.class),
                rs.getObject("expires_at", OffsetDateTime.class),
                rs.getObject("revoked_at", OffsetDateTime.class),
                rs.getObject("last_used_at", OffsetDateTime.class),
                rs.getObject("last_heartbeat_at", OffsetDateTime.class),
                parse(rs.getString("agent_info"), AgentInfo.class),
                parse(rs.getString("ca_status"), AgentCaStatus.class));
    }

    private <T> T parse(String json, Class<T> type) {
        if (json == null) {
            return null;
        }
        try {
            return objectMapper.readValue(json, type);
        } catch (RuntimeException e) {
            log.warn("Unreadable {} row: {}", type.getSimpleName(), e.getMessage());
            return null;
        }
    }
}
