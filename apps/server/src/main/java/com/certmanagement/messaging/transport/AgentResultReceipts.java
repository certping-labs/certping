// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.transport;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Which agent token delivered each agent result the server applied: one row in
 * {@code agent_result_receipts} per completed result, with the token id the gateway stamped on the
 * message ({@link AgentGatewayHeaders#AGENT_TOKEN_PROPERTY}). A message queued before the stamp
 * existed records no token id.
 */
@Component
public class AgentResultReceipts {

    private final JdbcTemplate jdbc;

    public AgentResultReceipts(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public record Receipt(long organizationId, Long agentTokenId, String messageId, String messageType,
                          String requestId) {
    }

    public void record(Receipt receipt) {
        jdbc.update("""
                INSERT INTO agent_result_receipts (organization_id, agent_token_id, message_id, message_type, request_id)
                VALUES (?, ?, ?, ?, ?)
                """, receipt.organizationId(), receipt.agentTokenId(), truncate(receipt.messageId(), 255),
                truncate(receipt.messageType(), 64), truncate(receipt.requestId(), 255));
    }

    /** The receipts of one request, oldest first. */
    public List<Receipt> forRequest(long organizationId, String requestId) {
        return jdbc.query("""
                SELECT organization_id, agent_token_id, message_id, message_type, request_id
                  FROM agent_result_receipts WHERE organization_id = ? AND request_id = ? ORDER BY id
                """, (rs, i) -> new Receipt(rs.getLong("organization_id"),
                        rs.getObject("agent_token_id") == null ? null : rs.getLong("agent_token_id"),
                        rs.getString("message_id"), rs.getString("message_type"), rs.getString("request_id")),
                organizationId, requestId);
    }

    /** The token id a stamped property holds, or null for none or a value that is not a number. */
    public static Long tokenId(Object stamped) {
        if (stamped == null) {
            return null;
        }
        try {
            return Long.valueOf(stamped.toString().trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String truncate(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }
}
