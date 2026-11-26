// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.messaging.model.AgentCaStatus;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** The agent_ca_status table on real PostgreSQL: one row per agent, upserted, revoked agents hidden, no extra fields. */
@Testcontainers(disabledWithoutDocker = true)
class AgentCaStatusStorePostgresTest {

    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

    private static JdbcTemplate jdbc;
    private static final ObjectMapper JSON = JsonMapper.builderWithJackson2Defaults().build();

    private AgentCaStatusStore store;
    private long org;

    @BeforeAll
    static void migrate() {
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration").load().migrate();
        jdbc = new JdbcTemplate(new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
    }

    @BeforeEach
    void seed() {
        store = new AgentCaStatusStore(jdbc, JSON);
        String slug = "org-" + UUID.randomUUID();
        org = jdbc.queryForObject("INSERT INTO organizations (name, domain, slug, org_type)"
                + " VALUES (?, ?, ?, 'B2B') RETURNING id", Long.class, slug, slug + ".test", slug);
    }

    private long token(String name, boolean revoked) {
        return jdbc.queryForObject("INSERT INTO agent_tokens (organization_id, name, token_hash, token_prefix, revoked_at)"
                        + " VALUES (?, ?, ?, 'cpa_x', " + (revoked ? "NOW()" : "NULL") + ") RETURNING id",
                Long.class, org, name, UUID.randomUUID().toString().replace("-", "").repeat(2));
    }

    @Test
    void savesOneRowPerAgent_upsertsTheLatest_andHidesRevokedAgents() {
        long edge = token("edge", false);
        long old = token("old", true);

        store.save(org, edge, status(false));
        store.save(org, edge, status(true));
        store.save(org, old, status(true));
        store.save(org, null, status(false));
        store.save(org, null, status(true));

        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM agent_ca_status WHERE organization_id = ?",
                Integer.class, org)).isEqualTo(3);
        List<AgentCaStatusStore.AgentReport> reports = store.list(org);
        assertThat(reports).extracting(AgentCaStatusStore.AgentReport::tokenId).containsExactly(edge, null);
        assertThat(reports).allSatisfy(r -> {
            assertThat(r.caStatus().getGlobalsign().isConfigured()).isTrue();
            assertThat(r.reportedAt()).isNotNull();
        });
        assertThat(reports.get(0).agentName()).isEqualTo("edge");
    }

    @Test
    void storesOnlyTheKnownFields() throws Exception {
        AgentCaStatus parsed = JSON.readValue("""
                {"acme":{"directoryUrl":"https://pebble/dir","accountKey":"-----BEGIN PRIVATE KEY-----"},
                 "otherCa":{"configured":true,"loginPassword":"hunter2"}}
                """, AgentCaStatus.class);
        store.save(org, null, parsed);

        String raw = jdbc.queryForObject("SELECT ca_status::text FROM agent_ca_status WHERE organization_id = ?",
                String.class, org);
        assertThat(raw).contains("https://pebble/dir").doesNotContain("PRIVATE KEY", "hunter2", "accountKey", "otherCa");
    }

    private static AgentCaStatus status(boolean globalsign) {
        return AgentCaStatus.builder()
                .acme(AgentCaStatus.Acme.builder().directoryUrl("https://pebble/dir").environment("CUSTOM")
                        .contactEmail("").accounts(List.of()).build())
                .globalsign(new AgentCaStatus.Configured(globalsign))
                .build();
    }
}
