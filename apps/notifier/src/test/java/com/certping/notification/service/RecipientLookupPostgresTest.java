// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.transport.MessageBody;
import com.certping.notification.transport.InboundMessage;
import com.certping.notification.transport.InboundContext;
import com.certping.notification.transport.DeadLetterOptions;
import com.certping.notification.config.EmailConfig;
import com.certping.notification.enums.IntegrationType;
import com.certping.notification.enums.NotificationAction;
import com.certping.notification.enums.NotificationType;
import com.certping.notification.exception.RetryableNotificationException;
import com.certping.notification.model.NotificationEvent;
import com.certping.notification.model.NotificationRecord;
import com.certping.notification.model.NotificationStatus;
import com.certping.notification.repository.NotificationRepository;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.core.task.SyncTaskExecutor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Recipient resolution against real Postgres, whose failed statement aborts the transaction it
 * runs in: a lookup error must still leave a FAILED row and reach the scheduled retry, not
 * dead-letter an alert its publisher will not send again.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
@Import({NotificationService.class, CertManagerNotificationPolicy.class, RoleEmailMapper.class, RecipientDelivery.class, RecipientClaims.class, EmailCopies.class,
        DeliveryTimeouts.class, JacksonAutoConfiguration.class, RecipientDeliveryPostgresTest.Metrics.class})
@Testcontainers
class RecipientLookupPostgresTest {

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

    @Autowired private NotificationService notificationService;
    @Autowired private NotificationRepository notificationRepository;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private DeliveryTimeouts deliveryTimeouts;

    @MockitoBean private EmailProvider emailProvider;
    @MockitoBean private EmailConfig emailConfig;

    @BeforeEach
    void clean() {
        jdbc.update("DELETE FROM notification_records");
        jdbc.update("DELETE FROM user_roles");
        jdbc.update("DELETE FROM roles");
        jdbc.update("DELETE FROM users");
    }

    @AfterEach
    void restoreUsers() {
        jdbc.execute("""
                DO $$ BEGIN
                    IF to_regclass('user_rows') IS NOT NULL THEN
                        DROP VIEW users;
                        DROP FUNCTION users_timed_out();
                        ALTER TABLE user_rows RENAME TO users;
                    END IF;
                END $$""");
    }

    @Test
    void platformLookupThatTimesOut_isRecordedFailedAndRetryable() {
        timeOutUsersQueries();

        assertThatThrownBy(() -> notificationService.processNotification(healthAlert("health-timeout")))
                .isInstanceOfSatisfying(RetryableNotificationException.class,
                        e -> assertThat(e.getReasonCode()).isEqualTo(RoleEmailMapper.RECIPIENT_LOOKUP_FAILED));

        NotificationRecord row = notificationRepository.findByRequestId("health-timeout").orElseThrow();
        assertThat(row.getStatus()).isEqualTo(NotificationStatus.FAILED);
        assertThat(row.getFailureReason()).startsWith(RoleEmailMapper.RECIPIENT_LOOKUP_FAILED);
        verify(emailProvider, never()).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
    }

    @Test
    void organizationLookupThatTimesOut_isRecordedFailedAndRetryable() {
        timeOutUsersQueries();
        NotificationEvent event = healthAlert("org-timeout").toBuilder()
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS)
                .notificationType(NotificationType.ACCOUNT_EVENT)
                .roles(List.of("ORGANIZATION_ADMIN"))
                .organizationId(7L)
                .build();

        assertThatThrownBy(() -> notificationService.processNotification(event))
                .isInstanceOfSatisfying(RetryableNotificationException.class,
                        e -> assertThat(e.getReasonCode()).isEqualTo(RoleEmailMapper.RECIPIENT_LOOKUP_FAILED));

        assertThat(notificationRepository.findByRequestId("org-timeout").orElseThrow().getStatus())
                .isEqualTo(NotificationStatus.FAILED);
    }

    @Test
    void platformAlertWithNobody_commitsNoRecipientAndIsRetryable() {
        assertThatThrownBy(() -> notificationService.processNotification(healthAlert("health-nobody")))
                .isInstanceOfSatisfying(RetryableNotificationException.class,
                        e -> assertThat(e.getReasonCode()).isEqualTo(NotificationService.NO_RECIPIENT));

        NotificationRecord row = notificationRepository.findByRequestId("health-nobody").orElseThrow();
        assertThat(row.getStatus()).isEqualTo(NotificationStatus.FAILED);
        assertThat(row.getFailureReason()).isEqualTo(NotificationService.NO_RECIPIENT);
    }

    @Test
    void platformAlertToAnActiveSuperAdmin_isDelivered() {
        jdbc.update("INSERT INTO users (id, email) VALUES (1, 'ops@example.com')");
        jdbc.update("INSERT INTO roles (id, name) VALUES (1, 'SUPER_ADMIN')");
        jdbc.update("INSERT INTO user_roles (user_id, role_id) VALUES (1, 1)");

        notificationService.processNotification(healthAlert("health-ok"));

        verify(emailProvider).sendTemplatedEmail(eq("ops@example.com"), anyString(),
                eq("system-dlq-alert"), any());
        assertThat(notificationRepository.findByRequestId("health-ok").orElseThrow().getStatus())
                .isEqualTo(NotificationStatus.DELIVERED);
    }

    @Test
    void listenerReschedulesAPlatformAlertWhoseLookupTimedOut() {
        timeOutUsersQueries();
        ScheduledRetryService retries = mock(ScheduledRetryService.class);
        when(retries.scheduleRetry(any(), any(), anyString(), anyString(), anyString())).thenReturn(true);
        NotificationMessageHandler listener = new NotificationMessageHandler(
                notificationService, retries, mock(UndeliveredEmailService.class),
                new SyncTaskExecutor(), new SimpleMeterRegistry(), deliveryTimeouts);
        InboundContext context = mock(InboundContext.class);
        InboundMessage message = mock(InboundMessage.class);
        when(context.getMessage()).thenReturn(message);
        when(message.getMessageId()).thenReturn("msg-1");
        when(message.getDeliveryCount()).thenReturn(0L);
        when(message.getApplicationProperties()).thenReturn(Map.of());
        when(message.getBody()).thenReturn(MessageBody.fromString(
                "[{\"notificationType\":\"SYSTEM_EVENT\",\"notificationAction\":\"SYSTEM_DLQ_ALERT\","
                        + "\"integrationType\":\"EMAIL\",\"roles\":[\"SUPER_ADMIN\"],\"requestId\":\"health-listener\","
                        + "\"templateFields\":{\"scenario\":\"REFUND_PARKED\",\"count\":1,\"items\":\"a.com\"}}]"));

        listener.processSystemEvent(context);

        verify(retries).scheduleRetry(any(), eq(Duration.ofMinutes(5)), eq(RoleEmailMapper.RECIPIENT_LOOKUP_FAILED),
                anyString(), anyString());
        verify(context, never()).abandon();
        verify(context, never()).deadLetter(any(DeadLetterOptions.class));
        assertThat(notificationRepository.findByRequestId("health-listener").orElseThrow().getStatus())
                .isEqualTo(NotificationStatus.FAILED);
    }

    /**
     * Every users query now fails as a statement timeout does: SQLSTATE 57014. Role holders exist,
     * so the planner cannot skip reading users.
     */
    private void timeOutUsersQueries() {
        jdbc.update("INSERT INTO users (id, email, organization_id) VALUES (1, 'ops@example.com', NULL), (2, 'admin@example.com', 7)");
        jdbc.update("INSERT INTO roles (id, name, organization_id) VALUES (1, 'SUPER_ADMIN', NULL), (2, 'organization_admin', 7)");
        jdbc.update("INSERT INTO user_roles (user_id, role_id) VALUES (1, 1), (2, 2)");
        jdbc.execute("ALTER TABLE users RENAME TO user_rows");
        jdbc.execute("""
                CREATE FUNCTION users_timed_out() RETURNS SETOF user_rows LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE EXCEPTION 'canceling statement due to statement timeout' USING ERRCODE = '57014';
                END $$""");
        jdbc.execute("CREATE VIEW users AS SELECT * FROM users_timed_out()");
    }

    private static NotificationEvent healthAlert(String requestId) {
        return NotificationEvent.builder()
                .source("certping-cert-manager")
                .requestId(requestId)
                .integrationType(IntegrationType.EMAIL)
                .notificationType(NotificationType.SYSTEM_EVENT)
                .notificationAction(NotificationAction.SYSTEM_DLQ_ALERT)
                .roles(List.of("SUPER_ADMIN"))
                .templateFields(new HashMap<>(Map.of("queue", "cert-events", "count", 1)))
                .build();
    }
}
