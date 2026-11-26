// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.config.EmailConfig;
import com.certping.notification.enums.IntegrationType;
import com.certping.notification.enums.NotificationAction;
import com.certping.notification.enums.NotificationType;
import com.certping.notification.exception.RetryableNotificationException;
import com.certping.notification.model.NotificationEvent;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.mail.internet.InternetAddress;
import org.eclipse.angus.mail.smtp.SMTPAddressFailedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Deliver-once emails against real Postgres: each recipient has a record of its own, claimed
 * atomically through the unique request id, completed only by the claim that sent it.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
@Import({NotificationService.class, CertManagerNotificationPolicy.class, RoleEmailMapper.class, RecipientDelivery.class, RecipientClaims.class, EmailCopies.class,
        DeliveryTimeouts.class, JacksonAutoConfiguration.class, RecipientDeliveryPostgresTest.Metrics.class})
@Testcontainers
class RecipientDeliveryPostgresTest {

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

    private static final String ADMIN = "admin@example.com";
    private static final String MEMBER = "member@example.com";

    @Autowired private NotificationService notificationService;
    @Autowired private RecipientClaims claims;
    @Autowired private MeterRegistry meterRegistry;
    @Autowired private JdbcTemplate jdbc;

    @MockitoBean private EmailProvider emailProvider;
    @MockitoBean private EmailConfig emailConfig;

    @BeforeEach
    void seed() {
        jdbc.update("DELETE FROM notification_records");
        jdbc.update("DELETE FROM user_roles");
        jdbc.update("DELETE FROM roles");
        jdbc.update("DELETE FROM users");
        jdbc.update("INSERT INTO users (id, email, organization_id) VALUES (1, ?, 7), (2, ?, 7), (3, 'gone@example.com', 8)",
                ADMIN, MEMBER);
        jdbc.update("INSERT INTO roles (id, name, organization_id) VALUES (1, 'organization_admin', 7)");
        jdbc.update("INSERT INTO user_roles (user_id, role_id) VALUES (1, 1)");
        meterRegistry.clear();
        reset(emailProvider);
    }

    @Test
    void theMemberAndTheAdminsEachGetTheEmailOnce() {
        notificationService.processNotification(issuedEmail("issued-email:1", 2L));

        verify(emailProvider).sendTemplatedEmail(eq(ADMIN), anyString(), anyString(), any());
        verify(emailProvider).sendTemplatedEmail(eq(MEMBER), anyString(), anyString(), any());
        assertThat(statuses("issued-email:1")).containsOnly("DELIVERED").hasSize(2);
    }

    @Test
    void aMemberWhoIsAnAdminGetsOneEmail() {
        notificationService.processNotification(issuedEmail("issued-email:2", 1L));

        verify(emailProvider, times(1)).sendTemplatedEmail(eq(ADMIN), anyString(), anyString(), any());
        verify(emailProvider, times(1)).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
    }

    @Test
    void anExMemberGetsNothing() {
        notificationService.processNotification(issuedEmail("issued-email:3", 3L));

        verify(emailProvider).sendTemplatedEmail(eq(ADMIN), anyString(), anyString(), any());
        verify(emailProvider, never()).sendTemplatedEmail(eq("gone@example.com"), anyString(), anyString(), any());
    }

    @Test
    void partialSuccessRetriesOnlyTheFailedRecipient() {
        doThrow(new RuntimeException("mailbox unavailable"))
                .when(emailProvider).sendTemplatedEmail(eq(MEMBER), anyString(), anyString(), any());

        assertThatThrownBy(() -> notificationService.processNotification(issuedEmail("issued-email:4", 2L)))
                .isInstanceOfSatisfying(RetryableNotificationException.class,
                        e -> assertThat(e.getReasonCode()).isEqualTo(RecipientDelivery.SEND_FAILED));
        assertThat(status("issued-email:4", ADMIN)).isEqualTo("DELIVERED");
        assertThat(status("issued-email:4", MEMBER)).isEqualTo("FAILED");

        reset(emailProvider);
        notificationService.processNotification(issuedEmail("issued-email:4", 2L));

        verify(emailProvider, never()).sendTemplatedEmail(eq(ADMIN), anyString(), anyString(), any());
        verify(emailProvider).sendTemplatedEmail(eq(MEMBER), anyString(), anyString(), any());
        assertThat(statuses("issued-email:4")).containsOnly("DELIVERED");
    }

    @Test
    void aRecipientRefusedForGoodEndsOnlyThatRecipient() throws Exception {
        jdbc.update("INSERT INTO users (id, email, organization_id) VALUES (4, 'second-admin@example.com', 7)");
        jdbc.update("INSERT INTO user_roles (user_id, role_id) VALUES (4, 1)");
        List<String> sentTo = new CopyOnWriteArrayList<>();
        InternetAddress refused = new InternetAddress("refused@example.com");
        doAnswer(invocation -> {
            sentTo.add(invocation.getArgument(0));
            if (sentTo.size() == 1) {
                throw new RuntimeException(new SMTPAddressFailedException(refused, "RCPT TO", 550, "mailbox unavailable"));
            }
            return null;
        }).when(emailProvider).sendTemplatedEmail(anyString(), anyString(), anyString(), any());

        assertThatThrownBy(() -> notificationService.processNotification(issuedEmail("issued-email:9", 2L)))
                .isInstanceOf(RecipientsRefusedException.class);

        assertThat(sentTo).hasSize(3).doesNotHaveDuplicates();
        assertThat(status("issued-email:9", sentTo.get(0))).isEqualTo("FAILED");
        assertThat(status("issued-email:9", sentTo.get(1))).isEqualTo("DELIVERED");
        assertThat(status("issued-email:9", sentTo.get(2))).isEqualTo("DELIVERED");

        assertThatThrownBy(() -> notificationService.processNotification(issuedEmail("issued-email:9", 2L)))
                .isInstanceOf(RecipientsRefusedException.class);
        assertThat(sentTo).hasSize(3);
    }

    @Test
    void twoConsumersSendEachRecipientOnce() throws Exception {
        CountDownLatch firstSendStarted = new CountDownLatch(1);
        CountDownLatch secondConsumerDone = new CountDownLatch(1);
        doAnswer(invocation -> {
            firstSendStarted.countDown();
            assertThat(secondConsumerDone.await(10, TimeUnit.SECONDS)).isTrue();
            return null;
        }).when(emailProvider).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
        NotificationEvent event = issuedEmail("issued-email:5", 1L);

        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<?> first = pool.submit(() -> notificationService.processNotification(event.toBuilder().build()));
            assertThat(firstSendStarted.await(10, TimeUnit.SECONDS)).isTrue();

            assertThatThrownBy(() -> notificationService.processNotification(event.toBuilder().build()))
                    .isInstanceOfSatisfying(RetryableNotificationException.class,
                            e -> assertThat(e.getReasonCode()).isEqualTo(RecipientDelivery.CLAIMED_ELSEWHERE));
            secondConsumerDone.countDown();
            first.get(10, TimeUnit.SECONDS);
        } finally {
            pool.shutdownNow();
        }

        verify(emailProvider, times(1)).sendTemplatedEmail(eq(ADMIN), anyString(), anyString(), any());
        assertThat(status("issued-email:5", ADMIN)).isEqualTo("DELIVERED");
    }

    @Test
    void aHeldClaimIsRetriedJustAfterItsLeaseEnds() {
        NotificationEvent event = issuedEmail("issued-email:6", 1L);
        assertThat(claims.claim(event, ADMIN, "t", "s", "{}")).isInstanceOf(RecipientClaims.Claimed.class);

        assertThatThrownBy(() -> notificationService.processNotification(event))
                .isInstanceOfSatisfying(RetryableNotificationException.class, e -> {
                    assertThat(e.getReasonCode()).isEqualTo(RecipientDelivery.CLAIMED_ELSEWHERE);
                    assertThat(e.getRetryAfter()).isBetween(claims.lease().minusSeconds(30), claims.lease().plusSeconds(30));
                });
        verify(emailProvider, never()).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
    }

    @Test
    void anExpiredClaimIsTakenOverAndCounted() {
        NotificationEvent event = issuedEmail("issued-email:7", 1L);
        assertThat(claims.claim(event, ADMIN, "t", "s", "{}")).isInstanceOf(RecipientClaims.Claimed.class);
        lapse("issued-email:7", ADMIN);

        notificationService.processNotification(event);

        verify(emailProvider).sendTemplatedEmail(eq(ADMIN), anyString(), anyString(), any());
        assertThat(status("issued-email:7", ADMIN)).isEqualTo("DELIVERED");
        assertThat(meterRegistry.counter(RecipientDelivery.LEASE_TAKEN_OVER_METRIC).count()).isEqualTo(1);
    }

    @Test
    void anExpiredHolderNeverMarksOverANewOwner() {
        NotificationEvent event = issuedEmail("issued-email:8", 1L);
        RecipientClaims.Claim stale = ((RecipientClaims.Claimed) claims.claim(event, ADMIN, "t", "s", "{}")).claim();
        lapse("issued-email:8", ADMIN);
        RecipientClaims.Claim owner = ((RecipientClaims.Claimed) claims.claim(event, ADMIN, "t", "s", "{}")).claim();

        assertThat(claims.markDelivered(stale)).isFalse();
        assertThat(claims.markFailed(stale, "late")).isFalse();
        assertThat(status("issued-email:8", ADMIN)).isEqualTo("PENDING");

        assertThat(claims.markDelivered(owner)).isTrue();
        assertThat(status("issued-email:8", ADMIN)).isEqualTo("DELIVERED");
    }

    @Test
    void aDeliveredRecipientIsNeverClaimedAgain() {
        NotificationEvent event = issuedEmail("issued-email:9", 1L);
        RecipientClaims.Claim claim = ((RecipientClaims.Claimed) claims.claim(event, ADMIN, "t", "s", "{}")).claim();
        assertThat(claims.markDelivered(claim)).isTrue();
        lapse("issued-email:9", ADMIN);

        assertThat(claims.claim(event, ADMIN, "t", "s", "{}")).isInstanceOf(RecipientClaims.AlreadyDelivered.class);
    }

    @Test
    void noRecipientIsRecordedAndCounted() {
        jdbc.update("DELETE FROM user_roles");

        notificationService.processNotification(issuedEmail("issued-email:10", 3L));

        verify(emailProvider, never()).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
        assertThat(jdbc.queryForObject("SELECT failure_reason FROM notification_records WHERE request_id = ?",
                String.class, "issued-email:10")).isEqualTo(NotificationService.NO_RECIPIENT);
        assertThat(meterRegistry.counter(NotificationService.NO_RECIPIENT_METRIC,
                "action", "CERT_ISSUANCE_SUCCESS", "source", "certping-cert-manager").count()).isEqualTo(1);
    }

    @Test
    void aRecipientRecordKeysOnTheAddressHashNeverTheAddress() {
        notificationService.processNotification(issuedEmail("issued-email:11", 1L));

        String requestId = jdbc.queryForObject("SELECT request_id FROM notification_records WHERE email = ?",
                String.class, ADMIN);
        assertThat(requestId).startsWith("issued-email:11#").doesNotContain("example");
        assertThat(requestId).isEqualTo(RecipientClaims.recipientRequestId("issued-email:11", " Admin@Example.com "));
    }

    private void lapse(String requestId, String recipient) {
        jdbc.update("UPDATE notification_records SET updated_at = updated_at - interval '6 minutes' WHERE request_id = ?",
                RecipientClaims.recipientRequestId(requestId, recipient));
    }

    private String status(String requestId, String recipient) {
        return jdbc.queryForObject("SELECT status FROM notification_records WHERE request_id = ?", String.class,
                RecipientClaims.recipientRequestId(requestId, recipient));
    }

    private List<String> statuses(String requestId) {
        return jdbc.queryForList("SELECT status FROM notification_records WHERE request_id LIKE ?", String.class,
                requestId + "#%");
    }

    private static NotificationEvent issuedEmail(String requestId, Long member) {
        Map<String, Object> fields = new HashMap<>(Map.of("domain", "example.com", "certificateXref", "cert-1",
                "title", "Certificate for example.com issued", "message", "The certificate is issued."));
        return NotificationEvent.builder()
                .source("certping-cert-manager")
                .requestId(requestId)
                .organizationId(7L)
                .userId(member)
                .roles(List.of("ORGANIZATION_ADMIN"))
                .includeUser(true)
                .deliverOnce(true)
                .integrationType(IntegrationType.EMAIL)
                .notificationType(NotificationType.ACCOUNT_EVENT)
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS)
                .templateFields(fields)
                .build();
    }
}
