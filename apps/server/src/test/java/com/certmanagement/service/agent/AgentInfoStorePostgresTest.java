// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.messaging.model.AgentCaStatus;
import com.certmanagement.messaging.model.AgentHealthHeartbeat;
import com.certmanagement.messaging.model.AgentInfo;
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

/** The agent_info table on real PostgreSQL: one row per token, scoped to its organization, no extra fields stored. */
@Testcontainers(disabledWithoutDocker = true)
class AgentInfoStorePostgresTest {

    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

    private static JdbcTemplate jdbc;
    private static final ObjectMapper JSON = JsonMapper.builderWithJackson2Defaults().build();

    private AgentInfoStore store;
    private long org;
    private long otherOrg;

    @BeforeAll
    static void migrate() {
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration").load().migrate();
        jdbc = new JdbcTemplate(new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
    }

    @BeforeEach
    void seed() {
        store = new AgentInfoStore(jdbc, JSON);
        org = organization();
        otherOrg = organization();
    }

    private static long organization() {
        String slug = "org-" + UUID.randomUUID();
        return jdbc.queryForObject("INSERT INTO organizations (name, domain, slug, org_type)"
                + " VALUES (?, ?, ?, 'B2B') RETURNING id", Long.class, slug, slug + ".test", slug);
    }

    private static long token(long organizationId, String name, boolean revoked) {
        return jdbc.queryForObject("INSERT INTO agent_tokens (organization_id, name, token_hash, token_prefix, revoked_at)"
                        + " VALUES (?, ?, ?, 'cpa_x', " + (revoked ? "NOW()" : "NULL") + ") RETURNING id",
                Long.class, organizationId, name, UUID.randomUUID().toString().replace("-", "").repeat(2));
    }

    private static AgentInfo info(String version) {
        return AgentInfo.builder().version(version).hostname("edge-1").secretStore("LOCAL").maxConcurrentJobs(8)
                .capabilities(AgentInfo.Capabilities.builder().deploymentTargets(List.of("AZURE_KEYVAULT")).build())
                .build();
    }

    @Test
    void listsEveryTokenOfTheOrganization_withItsLatestInfo_andRevokedOnesToo() {
        long edge = token(org, "edge", false);
        long old = token(org, "old", true);
        long silent = token(org, "silent", false);

        store.recordHeartbeat(org, edge, info("0.1.0"));
        store.recordHeartbeat(org, edge, info("0.2.0"));
        store.recordHeartbeat(org, old, info("0.1.0"));

        List<AgentInfoStore.AgentRow> rows = store.list(org);
        assertThat(rows).extracting(AgentInfoStore.AgentRow::tokenId).containsExactlyInAnyOrder(edge, old, silent);
        AgentInfoStore.AgentRow edgeRow = store.find(org, edge).orElseThrow();
        assertThat(edgeRow.agentInfo().getVersion()).isEqualTo("0.2.0");
        assertThat(edgeRow.lastHeartbeatAt()).isNotNull();
        assertThat(store.find(org, old).orElseThrow().revokedAt()).isNotNull();
        AgentInfoStore.AgentRow silentRow = store.find(org, silent).orElseThrow();
        assertThat(silentRow.agentInfo()).isNull();
        assertThat(silentRow.lastHeartbeatAt()).isNull();
    }

    @Test
    void aHeartbeatWithoutInfoKeepsTheLastInfo() {
        long edge = token(org, "edge", false);
        store.recordHeartbeat(org, edge, info("0.2.0"));
        store.recordHeartbeat(org, edge, null);

        assertThat(store.find(org, edge).orElseThrow().agentInfo().getVersion()).isEqualTo("0.2.0");
    }

    @Test
    void anotherOrganizationsAgentsNeverAppear() {
        long mine = token(org, "mine", false);
        long theirs = token(otherOrg, "theirs", false);
        store.recordHeartbeat(otherOrg, theirs, info("9.9.9"));
        // A heartbeat claiming another organization's token is not recorded.
        store.recordHeartbeat(org, theirs, info("6.6.6"));
        store.recordHeartbeat(otherOrg, mine, info("6.6.6"));

        assertThat(store.list(org)).extracting(AgentInfoStore.AgentRow::tokenId).containsExactly(mine);
        assertThat(store.find(org, theirs)).isEmpty();
        assertThat(store.find(org, mine).orElseThrow().agentInfo()).isNull();
        assertThat(store.find(otherOrg, theirs).orElseThrow().agentInfo().getVersion()).isEqualTo("9.9.9");
    }

    @Test
    void storesOnlyTheKnownSanitizedFields() {
        long edge = token(org, "edge", false);
        AgentHealthHeartbeat heartbeat = JSON.readValue(AgentDirectoryServiceTest.HOSTILE_HEARTBEAT,
                AgentHealthHeartbeat.class);
        store.recordHeartbeat(org, edge, heartbeat.getAgentInfo());

        String raw = jdbc.queryForObject("SELECT agent_info::text FROM agent_info WHERE agent_token_id = ?",
                String.class, edge);
        assertThat(raw).contains("Linux aarch64", "AZURE_KEYVAULT")
                .doesNotContain("LEAKED", "PRIVATE KEY", "c2VjcmV0", "azure-client-secret", "proxy-pass",
                        "abc123secret", "cf-api-token", "secretStoreKey", "clientSecret", "credentials");
    }

    @Test
    void readsTheCaStatusOfTheSameAgent() {
        long edge = token(org, "edge", false);
        new AgentCaStatusStore(jdbc, JSON).save(org, edge, AgentCaStatus.builder()
                .globalsign(new AgentCaStatus.Configured(true)).build());

        assertThat(store.find(org, edge).orElseThrow().caStatus().getGlobalsign().isConfigured()).isTrue();
    }
}
