// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.messaging.model.AgentCaStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import tools.jackson.databind.ObjectMapper;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * The latest {@link AgentCaStatus} per agent ({@code agent_ca_status}). An agent is the token that
 * delivered its heartbeat; agents of revoked tokens are left out of the list.
 */
@Slf4j
@Repository
public class AgentCaStatusStore {

    /** One agent's last report: {@code tokenId} and {@code agentName} are null for an unstamped heartbeat. */
    public record AgentReport(Long tokenId, String agentName, AgentCaStatus caStatus, OffsetDateTime reportedAt) {
    }

    private final JdbcTemplate jdbc;
    private final ObjectMapper objectMapper;

    public AgentCaStatusStore(JdbcTemplate jdbc, ObjectMapper objectMapper) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
    }

    public void save(long organizationId, Long agentTokenId, AgentCaStatus caStatus) {
        // Serialized from the typed object, so only its known fields are stored.
        String json = objectMapper.writeValueAsString(caStatus);
        jdbc.update("""
                INSERT INTO agent_ca_status (organization_id, agent_token_id, ca_status, reported_at)
                VALUES (?, ?, CAST(? AS jsonb), NOW())
                ON CONFLICT (organization_id, (COALESCE(agent_token_id, 0)))
                DO UPDATE SET ca_status = EXCLUDED.ca_status, reported_at = EXCLUDED.reported_at
                """, organizationId, agentTokenId, json);
    }

    public List<AgentReport> list(long organizationId) {
        return jdbc.query("""
                SELECT s.agent_token_id, t.name, s.ca_status::text AS ca_status, s.reported_at
                  FROM agent_ca_status s
                  LEFT JOIN agent_tokens t ON t.id = s.agent_token_id
                 WHERE s.organization_id = ?
                   AND (s.agent_token_id IS NULL OR t.revoked_at IS NULL)
                 ORDER BY t.name NULLS LAST, s.id
                """, (rs, i) -> new AgentReport(
                        (Long) rs.getObject("agent_token_id"),
                        rs.getString("name"),
                        parse(rs.getString("ca_status")),
                        rs.getObject("reported_at", OffsetDateTime.class)),
                organizationId);
    }

    private AgentCaStatus parse(String json) {
        try {
            return objectMapper.readValue(json, AgentCaStatus.class);
        } catch (RuntimeException e) {
            log.warn("Unreadable agent_ca_status row: {}", e.getMessage());
            return null;
        }
    }
}
