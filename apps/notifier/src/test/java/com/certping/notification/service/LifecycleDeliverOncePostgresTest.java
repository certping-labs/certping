// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.transport.MessageBody;
import com.certping.notification.transport.InboundMessage;
import com.certping.notification.transport.InboundContext;
import com.certping.notification.transport.MessageSender;
import com.certping.notification.transport.DeadLetterOptions;
import com.certping.notification.config.EmailConfig;
import com.certping.notification.model.NotificationEvent;
import tools.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.task.SyncTaskExecutor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The lifecycle emails the server may publish more than once, against real Postgres: whether the
 * listener reads one body twice or a retry copy of it, each admin is sent the email exactly once,
 * and a dead-lettered one leaves an undelivered record under its key.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
@Import({NotificationService.class, CertManagerNotificationPolicy.class, RoleEmailMapper.class, RecipientDelivery.class, RecipientClaims.class, EmailCopies.class,
        DeliveryTimeouts.class, JacksonAutoConfiguration.class, LifecycleDeliverOncePostgresTest.Metrics.class})
@Testcontainers
class LifecycleDeliverOncePostgresTest {

    @Container
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.sql.init.mode", () -> "always");
        registry.add("spring.sql.init.schema-locations", () -> "classpath:db/notifier-tables.sql");
    }

    @TestConfiguration
    static class Metrics {
        @Bean
        MeterRegistry meterRegistry() {
            return new SimpleMeterRegistry();
        }
    }

    private static final String ADMIN = "admin1@acme.example";
    private static final String SECOND_ADMIN = "admin2@acme.example";

    @Autowired private NotificationService notificationService;
    @Autowired private RoleEmailMapper roleEmailMapper;
    @Autowired private DeliveryTimeouts deliveryTimeouts;
    @Autowired private MeterRegistry meterRegistry;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private JdbcTemplate jdbc;

    @MockitoBean private EmailProvider emailProvider;
    @MockitoBean private EmailConfig emailConfig;

    private final ScheduledRetryService scheduledRetryService = mock(ScheduledRetryService.class);
    private final List<String> retryCopies = new CopyOnWriteArrayList<>();
    private final List<String> sentTo = new CopyOnWriteArrayList<>();
    private NotificationMessageHandler listener;

    @BeforeEach
    void seed() {
        jdbc.update("DELETE FROM notification_records");
        jdbc.update("DELETE FROM user_roles");
        jdbc.update("DELETE FROM roles");
        jdbc.update("DELETE FROM users");
        jdbc.update("INSERT INTO users (id, email, organization_id) VALUES (1, ?, 42), (2, ?, 42)", ADMIN, SECOND_ADMIN);
        jdbc.update("INSERT INTO roles (id, name, organization_id) VALUES (1, 'organization_admin', 42)");
        jdbc.update("INSERT INTO user_roles (user_id, role_id) VALUES (1, 1), (2, 1)");
        meterRegistry.clear();
        reset(emailProvider);
        when(emailConfig.getSupportAddress()).thenReturn("support@example.com");
        when(emailConfig.getFrontendBaseUrl()).thenReturn("https://certping.example.com");
        when(scheduledRetryService.scheduleRetries(any(), anyList())).thenAnswer(invocation -> {
            List<ScheduledRetryService.RetryCopy> copies = invocation.getArgument(1);
            copies.forEach(copy -> retryCopies.add(copy.bodyJson()));
            return copies.stream().map(copy -> ScheduledRetryService.Scheduled.WITHIN_BUDGET).toList();
        });
        UndeliveredEmailService undelivered = new UndeliveredEmailService(jdbc, objectMapper, roleEmailMapper,
                emailProvider, mock(MessageSender.class), meterRegistry, 3);
        listener = new NotificationMessageHandler(notificationService, scheduledRetryService, undelivered,
                new SyncTaskExecutor(), meterRegistry, deliveryTimeouts);
    }

    @Test
    void aRenewedNotDeployedReadTwiceAndRetriedReachesEachAdminOnce() {
        String body = ProducerEnvelopes.renewedNotDeployed();
        AtomicBoolean secondAdminRefused = new AtomicBoolean();
        recordSends(recipient -> SECOND_ADMIN.equals(recipient) && secondAdminRefused.compareAndSet(false, true));

        receive(body, 0);
        assertThat(sentTo).containsExactly(ADMIN);
        assertThat(retryCopies).hasSize(1);
        NotificationEvent copy = ProducerEnvelopes.read(retryCopies.get(0));
        assertThat(copy.isDeliverOnce()).isTrue();
        assertThat(copy.idempotencyKey()).isEqualTo(ProducerEnvelopes.NOT_DEPLOYED_KEY);

        receive(body, 1);
        receive(retryCopies.get(0), 0);

        assertThat(sentTo).containsExactlyInAnyOrder(ADMIN, SECOND_ADMIN);
        assertThat(statuses(ProducerEnvelopes.NOT_DEPLOYED_KEY)).containsOnly("DELIVERED").hasSize(2);
    }

    @Test
    void aFeaturePausedReadTwiceReachesEachAdminOnce() {
        recordSends(recipient -> false);
        String body = ProducerEnvelopes.feature("PAUSED");

        receive(body, 0);
        receive(body, 0);

        assertThat(sentTo).containsExactlyInAnyOrder(ADMIN, SECOND_ADMIN);
        assertThat(statuses(ProducerEnvelopes.featureKey("PAUSED"))).containsOnly("DELIVERED").hasSize(2);
    }

    @Test
    void aDeadLetteredRenewedNotDeployedLeavesAnUndeliveredRecord() {
        recordSends(recipient -> false);

        InboundContext context = receive(ProducerEnvelopes.renewedNotDeployed(), 3);

        verify(context).deadLetter(any(DeadLetterOptions.class));
        assertThat(sentTo).isEmpty();
        assertThat(jdbc.queryForList("SELECT status FROM notification_records WHERE request_id = ? "
                + "AND template_name = 'undelivered-email'", String.class, ProducerEnvelopes.NOT_DEPLOYED_KEY))
                .containsExactly("FAILED");
    }

    /** Records each address sent to; one the predicate picks is refused instead, as SMTP would. */
    private void recordSends(Predicate<String> refuse) {
        doAnswer(invocation -> {
            String recipient = invocation.getArgument(0);
            if (refuse.test(recipient)) {
                throw new RuntimeException("mailbox unavailable");
            }
            sentTo.add(recipient);
            return null;
        }).when(emailProvider).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
    }

    private InboundContext receive(String body, long deliveryCount) {
        InboundContext context = mock(InboundContext.class);
        InboundMessage message = mock(InboundMessage.class);
        when(context.getMessage()).thenReturn(message);
        when(message.getBody()).thenReturn(MessageBody.fromString(body));
        when(message.getMessageId()).thenReturn("msg-lifecycle");
        when(message.getDeliveryCount()).thenReturn(deliveryCount);
        listener.processAccountEvent(context);
        return context;
    }

    private List<String> statuses(String key) {
        return jdbc.queryForList("SELECT status FROM notification_records WHERE request_id LIKE ?", String.class,
                key + "#%");
    }
}
