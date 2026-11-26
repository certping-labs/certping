// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.telemetry;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/** The installation's random id, minted on first use. */
@Component
public class InstallationIdentity {

    private final JdbcTemplate jdbc;
    private volatile UUID cached;

    public InstallationIdentity(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Transactional
    public UUID get() {
        UUID id = cached;
        if (id != null) {
            return id;
        }
        List<UUID> rows = jdbc.query("SELECT id FROM installation", (rs, i) -> rs.getObject("id", UUID.class));
        if (rows.isEmpty()) {
            id = UUID.randomUUID();
            // Two servers starting at once: the primary key keeps one row, and the loser re-reads.
            jdbc.update("INSERT INTO installation (singleton, id) VALUES (TRUE, ?) ON CONFLICT (singleton) DO NOTHING", id);
            rows = jdbc.query("SELECT id FROM installation", (rs, i) -> rs.getObject("id", UUID.class));
        }
        id = rows.get(0);
        cached = id;
        return id;
    }
}
