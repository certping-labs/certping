// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Picks the agent a device-source command must go to: the one whose token last advertised the source,
 * because only it holds the source's credentials and SCEP CA. Null (any agent of the organization)
 * when no live token advertised it.
 */
@Component
public class AgentTargets {

    private static final String LIVE_TOKEN = """
            JOIN agent_tokens t ON t.id = s.advertising_agent_token_id
                              AND t.organization_id = s.organization_id
                              AND t.revoked_at IS NULL
                              AND (t.expires_at IS NULL OR t.expires_at > NOW())
            """;

    private final JdbcTemplate jdbc;

    public AgentTargets(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Long forSource(String organizationId, String sourceXref) {
        if (sourceXref == null || sourceXref.isBlank()) {
            return null;
        }
        return first(jdbc.queryForList("SELECT s.advertising_agent_token_id FROM iot_device_source s "
                + LIVE_TOKEN + " WHERE s.organization_id = ? AND s.source_xref = ?",
                Long.class, Long.parseLong(organizationId), sourceXref));
    }

    public Long forCertificate(String organizationId, String certificateXref) {
        if (certificateXref == null || certificateXref.isBlank()) {
            return null;
        }
        return first(jdbc.queryForList("SELECT s.advertising_agent_token_id FROM iot_device_certificate c "
                + "JOIN iot_device_source s ON s.id = c.device_source_id " + LIVE_TOKEN
                + " WHERE c.organization_id = ? AND c.certificate_xref = ?",
                Long.class, Long.parseLong(organizationId), certificateXref));
    }

    private static Long first(List<Long> ids) {
        return ids.isEmpty() ? null : ids.get(0);
    }
}
