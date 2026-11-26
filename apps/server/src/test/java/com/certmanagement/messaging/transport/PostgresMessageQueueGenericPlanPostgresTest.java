// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.transport;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Receive must never lock more than its limit. With a generic plan made while the queue was nearly empty,
 * PostgreSQL can run {@code UPDATE ... WHERE id IN (SELECT ... LIMIT n FOR UPDATE SKIP LOCKED)} as a semi
 * join that re-runs the subquery per outer row, so one receive with a limit of 1 leased every ready row.
 */
@Testcontainers(disabledWithoutDocker = true)
class PostgresMessageQueueGenericPlanPostgresTest {

    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

    private static final String CHANNEL = "1-agent-inbound";

    private SingleConnectionDataSource dataSource;
    private JdbcTemplate jdbc;
    private PostgresMessageQueue queue;

    @BeforeAll
    static void migrate() {
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration").load().migrate();
    }

    @BeforeEach
    void setUp() {
        // One connection, every statement server-prepared from its first use, so the plan made now is reused.
        String url = POSTGRES.getJdbcUrl() + (POSTGRES.getJdbcUrl().contains("?") ? "&" : "?") + "prepareThreshold=1";
        dataSource = new SingleConnectionDataSource(url, POSTGRES.getUsername(), POSTGRES.getPassword(), true);
        jdbc = new JdbcTemplate(dataSource);
        jdbc.update("DELETE FROM message_queue");
        jdbc.execute("SET plan_cache_mode = force_generic_plan");
        queue = new PostgresMessageQueue(jdbc, JsonMapper.builderWithJackson2Defaults().build(),
                new TransportProperties());
    }

    @AfterEach
    void tearDown() {
        jdbc.update("DELETE FROM message_queue");
        dataSource.destroy();
    }

    @Test
    void aGenericPlanMadeOnANearlyEmptyQueueStillLeasesOnlyTheLimit() {
        queue.send(CHANNEL, new TransportMessage("first"));
        jdbc.execute("ANALYZE message_queue");
        // Plans (and caches) the receive statement while one row is waiting.
        assertThat(queue.receive(CHANNEL, 1)).hasSize(1);

        jdbc.update("INSERT INTO message_queue (channel, body, properties, available_at) "
                + "SELECT ?, 'x', '{}'::jsonb, NOW() - interval '1 second' FROM generate_series(1, 1000)", CHANNEL);

        List<PostgresMessageQueue.ReceivedMessage> received = queue.receive(CHANNEL, 1);

        assertThat(received).hasSize(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM message_queue WHERE status = 'LEASED'", Integer.class))
                .isEqualTo(2);
    }

    @Test
    void deploymentCommandsAreReceivedAheadOfOlderIssuanceCommands() {
        for (int i = 0; i < 3; i++) {
            TransportMessage issuance = new TransportMessage("issue-" + i);
            issuance.getApplicationProperties().put("MessageType", "CERT_ISSUANCE");
            queue.send(CHANNEL, issuance);
        }
        TransportMessage deployment = new TransportMessage("deploy");
        deployment.getApplicationProperties().put("MessageType", "CERT_DEPLOYMENT");
        queue.send(CHANNEL, deployment);

        assertThat(queue.receive(CHANNEL, 1)).extracting(PostgresMessageQueue.ReceivedMessage::body)
                .containsExactly("deploy");
        assertThat(queue.receive(CHANNEL, 10)).extracting(PostgresMessageQueue.ReceivedMessage::body)
                .containsExactly("issue-0", "issue-1", "issue-2");
    }

    /**
     * The flake behind the test above: available_at came from the JVM clock and receive compares it with the
     * database's NOW(), so a message sent while the JVM clock ran ahead of the database (a loaded Docker VM)
     * was not ready yet. Unscheduled messages now take the database clock, and their TTL counts from it.
     */
    @Test
    void anUnscheduledMessageIsAvailableByTheDatabaseClockAndExpiresByItsTimeToLive() {
        TransportMessage expiring = new TransportMessage("ttl");
        expiring.setTimeToLive(java.time.Duration.ofSeconds(90));
        queue.send(CHANNEL, expiring);
        queue.send(CHANNEL, new TransportMessage("no-ttl"));

        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM message_queue WHERE available_at <= NOW()",
                Integer.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT EXTRACT(EPOCH FROM expires_at - available_at) FROM message_queue "
                + "WHERE body = 'ttl'", Double.class)).isEqualTo(90.0);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM message_queue WHERE body = 'no-ttl' AND expires_at IS NULL",
                Integer.class)).isEqualTo(1);
    }

    @Test
    void aMessageScheduledForLaterKeepsItsTime() {
        TransportMessage later = new TransportMessage("later");
        java.time.OffsetDateTime at = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC).plusHours(1)
                .truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        later.setScheduledEnqueueTime(at);
        queue.send(CHANNEL, later);

        assertThat(jdbc.queryForObject("SELECT available_at FROM message_queue WHERE body = 'later'",
                java.time.OffsetDateTime.class)).isEqualTo(at);
        assertThat(queue.receive(CHANNEL, 10)).isEmpty();
    }
}
