// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.config.EmailConfig;
import com.certping.notification.enums.IntegrationType;
import com.certping.notification.enums.NotificationAction;
import com.certping.notification.enums.NotificationType;
import com.certping.notification.model.NotificationEvent;
import tools.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
@Import({NotificationService.class, CertManagerNotificationPolicy.class, RoleEmailMapper.class, RecipientDelivery.class, RecipientClaims.class, EmailCopies.class,
        DeliveryTimeouts.class, JacksonAutoConfiguration.class, RetryRecipientsPostgresTest.Metrics.class})
@Testcontainers
class RetryRecipientsPostgresTest {
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
        MeterRegistry meterRegistry() { return new SimpleMeterRegistry(); }
    }

    @Autowired private NotificationService notificationService;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private ObjectMapper objectMapper;
    @MockitoBean private EmailProvider emailProvider;
    @MockitoBean private EmailConfig emailConfig;

    @Test
    void aRetryAfterTheMemberLeftNeverEmailsThem() throws Exception {
        jdbc.update("INSERT INTO users (id, email, organization_id) VALUES (1, 'member@example.com', 7)");
        jdbc.update("INSERT INTO roles (id, name, organization_id) VALUES (1, 'organization_admin', 7)");
        jdbc.update("INSERT INTO user_roles (user_id, role_id) VALUES (1, 1)");
        doThrow(new RuntimeException("mailbox unavailable"))
                .when(emailProvider).sendTemplatedEmail(eq("member@example.com"), anyString(), anyString(), any());
        NotificationEvent event = NotificationEvent.builder()
                .source("certping-cert-manager").requestId("issued-email:x").organizationId(7L).userId(1L)
                .roles(List.of("ORGANIZATION_ADMIN")).includeUser(true).deliverOnce(true)
                .integrationType(IntegrationType.EMAIL).notificationType(NotificationType.ACCOUNT_EVENT)
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS)
                .templateFields(new HashMap<>(Map.of("domain", "example.com", "certificateXref", "cert-1",
                        "title", "t", "message", "m")))
                .build();
        assertThatThrownBy(() -> notificationService.processNotification(event));

        String body = objectMapper.writeValueAsString(List.of(event));
        NotificationEvent retry = objectMapper.readValue(body, NotificationEvent[].class)[0];

        jdbc.update("UPDATE users SET active = false, is_deleted = true WHERE id = 1");
        reset(emailProvider);
        notificationService.processNotification(retry);

        verify(emailProvider, never()).sendTemplatedEmail(eq("member@example.com"), anyString(), anyString(), any());
        assertThat(jdbc.queryForObject("SELECT failure_reason FROM notification_records WHERE request_id = ?",
                String.class, "issued-email:x")).isEqualTo(NotificationService.NO_RECIPIENT);
    }

    /**
     * A deliver-once notice to the admins and an extra contact in alsoTo: each address is claimed once, an admin's address in another case
     * included, and a retry after the contact's send failed reaches the contact alone.
     */
    @Test
    void aNoticeClaimsTheExtraContactOnceAndRetriesItAlone() throws Exception {
        jdbc.update("INSERT INTO users (id, email, organization_id) VALUES (21, 'admin@example.com', 8)");
        jdbc.update("INSERT INTO roles (id, name, organization_id) VALUES (21, 'organization_admin', 8)");
        jdbc.update("INSERT INTO user_roles (user_id, role_id) VALUES (21, 21)");
        doThrow(new RuntimeException("mailbox unavailable"))
                .when(emailProvider).sendTemplatedEmail(eq("grace@contact.test"), anyString(), anyString(), any());
        NotificationEvent event = contactNotice("cert-expiry-notice:1:a", 8L, " grace@contact.test ");
        assertThatThrownBy(() -> notificationService.processNotification(event));
        verify(emailProvider).sendTemplatedEmail(eq("admin@example.com"), anyString(), anyString(), any());

        String body = objectMapper.writeValueAsString(List.of(event));
        NotificationEvent retry = objectMapper.readValue(body, NotificationEvent[].class)[0];
        reset(emailProvider);
        notificationService.processNotification(retry);

        verify(emailProvider).sendTemplatedEmail(eq("grace@contact.test"), anyString(), anyString(), any());
        verify(emailProvider, never()).sendTemplatedEmail(eq("admin@example.com"), anyString(), anyString(), any());
        assertThat(jdbc.queryForList("SELECT status FROM notification_records WHERE request_id LIKE ?", String.class,
                "cert-expiry-notice:1:a#%")).containsExactly("DELIVERED", "DELIVERED");
    }

    @Test
    void aNoticeToAnExtraContactWhoIsAnAdminGoesOnce() throws Exception {
        jdbc.update("INSERT INTO users (id, email, organization_id) VALUES (31, 'owner@example.com', 9)");
        jdbc.update("INSERT INTO roles (id, name, organization_id) VALUES (31, 'organization_admin', 9)");
        jdbc.update("INSERT INTO user_roles (user_id, role_id) VALUES (31, 31)");

        notificationService.processNotification(contactNotice("cert-expiry-notice:2:a", 9L, "OWNER@Example.com"));

        verify(emailProvider).sendTemplatedEmail(eq("owner@example.com"), anyString(), anyString(), any());
        verify(emailProvider).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM notification_records WHERE request_id LIKE ?", Integer.class,
                "cert-expiry-notice:2:a#%")).isEqualTo(1);
    }

    private static NotificationEvent contactNotice(String key, long organization, String alsoTo) {
        return NotificationEvent.builder()
                .source("certping-cert-manager").requestId(key).organizationId(organization)
                .roles(List.of("ORGANIZATION_ADMIN")).alsoTo(alsoTo).deliverOnce(true)
                .integrationType(IntegrationType.EMAIL).notificationType(NotificationType.ACCOUNT_EVENT)
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS)
                .templateFields(new HashMap<>(Map.of("domain", "example.com", "certificateXref", "cert-2",
                        "validTo", "2026-10-03T09:15:30Z")))
                .build();
    }
}
