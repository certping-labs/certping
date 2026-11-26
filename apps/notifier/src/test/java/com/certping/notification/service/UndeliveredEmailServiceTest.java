// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.transport.TransportMessage;
import com.certping.notification.transport.InboundMessage;
import com.certping.notification.transport.MessageSender;
import com.certping.notification.enums.NotificationAction;
import com.certping.notification.enums.NotificationType;
import com.certping.notification.model.NotificationEvent;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class UndeliveredEmailServiceTest {

    @Test
    void oneRequestAlertsOnceAndItsOpenGaugeReflectsTheDatabase() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        RoleEmailMapper roles = mock(RoleEmailMapper.class);
        EmailProvider provider = mock(EmailProvider.class);
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        UndeliveredEmailService service = new UndeliveredEmailService(jdbc, JsonMapper.builderWithJackson2Defaults().build(), roles,
                provider, mock(MessageSender.class), registry, 3);
        when(jdbc.update(contains("INSERT INTO notification_records"), any(), any(), any(), any(), any(), any(),
                any(), any(), any())).thenReturn(1);
        when(jdbc.update(contains("SET sent_by = ?, sent_at"), any(), any(), any(), any()))
                .thenReturn(1, 0);
        when(roles.resolveRolesToEmails(List.of("SUPER_ADMIN"), null, null))
                .thenReturn(List.of("ops@example.com"));
        when(jdbc.queryForObject(contains("SELECT count(*)"),
                eq(Long.class), any(), eq(1000))).thenReturn(1L);
        NotificationEvent event = NotificationEvent.builder().requestId("order-42").deliverOnce(true)
                .notificationType(NotificationType.ACCOUNT_EVENT)
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS).build();

        service.record(event, UndeliveredEmailService.Outcome.RETRIES_EXHAUSTED, null);
        service.record(event, UndeliveredEmailService.Outcome.RETRIES_EXHAUSTED, null);

        verify(provider, times(1)).sendTemplatedEmail(
                eq("ops@example.com"), anyString(),
                eq("undelivered-email"), any());
        assertThat(registry.get(UndeliveredEmailService.UNDELIVERED_GAUGE).gauge().value()).isEqualTo(1);
        verify(jdbc).queryForObject(contains("failure_reason IS DISTINCT FROM 'PERMANENT_FAILURE'"),
                eq(Long.class), any(), eq(1000));
    }

    @Test
    void replayPublishesTheStoredRequestWithTopicRoutingProperties() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        MessageSender sender = mock(MessageSender.class);
        UndeliveredEmailService service = new UndeliveredEmailService(jdbc, JsonMapper.builderWithJackson2Defaults().build(),
                mock(RoleEmailMapper.class), mock(EmailProvider.class), sender, new SimpleMeterRegistry(), 3);
        String body = "[{\"requestId\":\"order-42\",\"correlationId\":\"corr-http-1\",\"notificationType\":\"ACCOUNT_EVENT\","
                + "\"notificationAction\":\"CERT_ISSUANCE_SUCCESS\",\"deliverOnce\":true}]";
        when(jdbc.queryForList(contains("RETURNING record.id"),
                eq("undelivered-email"),
                eq("RETRIES_EXHAUSTED"),
                eq(3), eq(50)))
                .thenReturn(List.of(Map.of("id", 7L, "request_id", "order-42", "payload_json",
                        body.replace("\"deliverOnce\":true", "\"deliverOnce\":true,\"firstRetryAt\":\"2026-09-01T00:00:00Z\",\"retryCount\":11,\"replayCount\":1,"
                                + "\"originRequestId\":\"req-http-1\","
                                + "\"originTraceparent\":\"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01\""))));

        assertThat(service.replay()).isEqualTo(1);

        ArgumentCaptor<TransportMessage> messages =
                ArgumentCaptor.forClass(TransportMessage.class);
        verify(sender).sendMessage(messages.capture());
        assertThat(messages.getValue().getBody().toString()).contains("order-42");
        assertThat(messages.getValue().getApplicationProperties())
                .containsEntry("notificationType", "ACCOUNT_EVENT")
                .containsEntry("event", "account")
                .containsEntry("correlationId", "corr-http-1")
                .containsEntry("requestId", "req-http-1")
                .containsEntry("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
                .containsEntry("FirstRetryAt", "2026-09-01T00:00:00Z")
                .containsEntry("RetryCount", 11)
                .containsEntry("ReplayCount", 1);
    }

    @Test
    void replaySelectsOnlyFailedRequestsBelowTheCap() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        MessageSender sender = mock(MessageSender.class);
        UndeliveredEmailService service = new UndeliveredEmailService(jdbc, JsonMapper.builderWithJackson2Defaults().build(),
                mock(RoleEmailMapper.class), mock(EmailProvider.class), sender, new SimpleMeterRegistry(), 3);
        when(jdbc.queryForList(anyString(), any(), any(), any(), any())).thenReturn(List.of());

        assertThat(service.replay()).isZero();

        ArgumentCaptor<String> query = ArgumentCaptor.forClass(String.class);
        verify(jdbc).queryForList(query.capture(), eq("undelivered-email"),
                eq("RETRIES_EXHAUSTED"), eq(3),
                eq(50));
        assertThat(query.getValue()).contains("status = 'FAILED'", "failure_reason = ?", "replayCount", "< ?",
                "created_at >=", "LIMIT ?");
        verify(sender, never()).sendMessage(any(TransportMessage.class));
    }

    @Test
    void permanentFailureIsStoredWithAReasonTheReplayExcludes() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        UndeliveredEmailService service = new UndeliveredEmailService(jdbc, JsonMapper.builderWithJackson2Defaults().build(),
                mock(RoleEmailMapper.class), mock(EmailProvider.class), mock(MessageSender.class),
                new SimpleMeterRegistry(), 3);
        NotificationEvent event = NotificationEvent.builder().requestId("order-43").deliverOnce(true)
                .notificationType(NotificationType.ACCOUNT_EVENT)
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS).build();

        service.record(event, UndeliveredEmailService.Outcome.PERMANENT_FAILURE, null);

        verify(jdbc).update(contains("failure_reason IS DISTINCT FROM 'NO_RECIPIENT'"),
                eq("order-43"), any(), any(), any(), any(), any(),
                eq("PERMANENT_FAILURE"), any(), any());
    }

    @Test
    void alertAttemptsEverySuperAdmin() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        RoleEmailMapper roles = mock(RoleEmailMapper.class);
        EmailProvider provider = mock(EmailProvider.class);
        UndeliveredEmailService service = new UndeliveredEmailService(jdbc, JsonMapper.builderWithJackson2Defaults().build(), roles,
                provider, mock(MessageSender.class), new SimpleMeterRegistry(), 3);
        when(jdbc.update(contains("INSERT INTO notification_records"), any(), any(), any(), any(), any(), any(),
                any(), any(), any())).thenReturn(1);
        when(jdbc.update(contains("SET sent_by = ?, sent_at"), any(), any(), any(), any())).thenReturn(1);
        when(roles.resolveRolesToEmails(List.of("SUPER_ADMIN"), null, null))
                .thenReturn(List.of("first@example.com", "second@example.com"));
        NotificationEvent event = NotificationEvent.builder().requestId("order-44").deliverOnce(true)
                .notificationType(NotificationType.ACCOUNT_EVENT)
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS).build();

        service.record(event, UndeliveredEmailService.Outcome.RETRIES_EXHAUSTED, null);

        verify(provider).sendTemplatedEmail(eq("first@example.com"), anyString(), anyString(), any());
        verify(provider).sendTemplatedEmail(eq("second@example.com"), anyString(), anyString(), any());
    }

    @Test
    void anExistingNoRecipientRecordIsNotOverwrittenOrAlerted() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        EmailProvider provider = mock(EmailProvider.class);
        UndeliveredEmailService service = new UndeliveredEmailService(jdbc, JsonMapper.builderWithJackson2Defaults().build(),
                mock(RoleEmailMapper.class), provider, mock(MessageSender.class),
                new SimpleMeterRegistry(), 3);
        NotificationEvent event = NotificationEvent.builder().requestId("nobody-1").deliverOnce(true)
                .notificationType(NotificationType.ACCOUNT_EVENT)
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS).build();

        assertThat(service.record(event, UndeliveredEmailService.Outcome.RETRIES_EXHAUSTED, null)).isFalse();

        verify(jdbc).update(contains("failure_reason IS DISTINCT FROM 'NO_RECIPIENT'"),
                eq("nobody-1"), any(), any(), any(), any(), any(), any(), any(), any());
        verify(provider, never()).sendTemplatedEmail(anyString(), anyString(), anyString(), any());
    }

    @Test
    void recordingAnExhaustedChainKeepsItsFirstRetryTimeAndCount() throws Exception {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        ObjectMapper mapper = JsonMapper.builderWithJackson2Defaults().build();
        UndeliveredEmailService service = new UndeliveredEmailService(jdbc, mapper,
                mock(RoleEmailMapper.class), mock(EmailProvider.class), mock(MessageSender.class),
                new SimpleMeterRegistry(), 3);
        when(jdbc.update(contains("INSERT INTO notification_records"), any(), any(), any(), any(), any(), any(),
                any(), any(), any())).thenReturn(1);
        InboundMessage message = mock(InboundMessage.class);
        when(message.getApplicationProperties()).thenReturn(Map.of("FirstRetryAt", "2026-09-01T00:00:00Z",
                "RetryCount", 11, "ReplayCount", 2, "correlationId", "corr-http-1", "requestId", "req-http-1",
                "traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"));
        NotificationEvent event = NotificationEvent.builder().requestId("order-45").deliverOnce(true)
                .notificationType(NotificationType.ACCOUNT_EVENT)
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS).build();

        assertThat(service.record(event, UndeliveredEmailService.Outcome.PENDING_RETRY, message)).isTrue();

        ArgumentCaptor<String> body = ArgumentCaptor.forClass(String.class);
        verify(jdbc).update(contains("INSERT INTO notification_records"),
                eq("order-45"), any(), any(), any(),
                eq("PENDING"), body.capture(), any(), any(), any());
        assertThat(mapper.readTree(body.getValue()).get(0).path("firstRetryAt").asString())
                .isEqualTo("2026-09-01T00:00:00Z");
        assertThat(mapper.readTree(body.getValue()).get(0).path("retryCount").asInt()).isEqualTo(11);
        assertThat(mapper.readTree(body.getValue()).get(0).path("replayCount").asInt()).isEqualTo(2);
        assertThat(mapper.readTree(body.getValue()).get(0).path("originCorrelationId").asString()).isEqualTo("corr-http-1");
        assertThat(mapper.readTree(body.getValue()).get(0).path("originRequestId").asString()).isEqualTo("req-http-1");
        assertThat(mapper.readTree(body.getValue()).get(0).path("originTraceparent").asString())
                .isEqualTo("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01");
    }

    @Test
    void anAlertOneAdminReceivedIsNotSentAgainToTheOthers() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        RoleEmailMapper roles = mock(RoleEmailMapper.class);
        EmailProvider provider = mock(EmailProvider.class);
        UndeliveredEmailService service = new UndeliveredEmailService(jdbc, JsonMapper.builderWithJackson2Defaults().build(), roles,
                provider, mock(MessageSender.class), new SimpleMeterRegistry(), 3);
        when(jdbc.update(contains("INSERT INTO notification_records"), any(), any(), any(), any(), any(), any(),
                any(), any(), any())).thenReturn(1);
        when(jdbc.update(contains("SET sent_by = ?, sent_at"), any(), any(), any(), any())).thenReturn(1);
        when(roles.resolveRolesToEmails(List.of("SUPER_ADMIN"), null, null))
                .thenReturn(List.of("first@example.com", "second@example.com"));
        doThrow(new RuntimeException("mailbox full"))
                .when(provider).sendTemplatedEmail(eq("first@example.com"), anyString(), anyString(), any());

        service.record(event("order-46"), UndeliveredEmailService.Outcome.RETRIES_EXHAUSTED, null);

        verify(jdbc).update(contains("SET sent_by = ? WHERE"), eq("UNDELIVERED_ALERT_SENT"), eq("order-46"),
                eq("UNDELIVERED_ALERT_CLAIMED"));
    }

    @Test
    void anAlertNobodyReceivedIsReleasedForTheNextRecord() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        RoleEmailMapper roles = mock(RoleEmailMapper.class);
        EmailProvider provider = mock(EmailProvider.class);
        UndeliveredEmailService service = new UndeliveredEmailService(jdbc, JsonMapper.builderWithJackson2Defaults().build(), roles,
                provider, mock(MessageSender.class), new SimpleMeterRegistry(), 3);
        when(jdbc.update(contains("INSERT INTO notification_records"), any(), any(), any(), any(), any(), any(),
                any(), any(), any())).thenReturn(1);
        when(jdbc.update(contains("SET sent_by = ?, sent_at"), any(), any(), any(), any())).thenReturn(1);
        when(roles.resolveRolesToEmails(List.of("SUPER_ADMIN"), null, null)).thenReturn(List.of("ops@example.com"));
        doThrow(new RuntimeException("smtp down"))
                .when(provider).sendTemplatedEmail(anyString(), anyString(), anyString(), any());

        service.record(event("order-47"), UndeliveredEmailService.Outcome.RETRIES_EXHAUSTED, null);

        verify(jdbc).update(contains("SET sent_by = ? WHERE"), isNull(), eq("order-47"), eq("UNDELIVERED_ALERT_CLAIMED"));
    }

    private static NotificationEvent event(String requestId) {
        return NotificationEvent.builder().requestId(requestId).deliverOnce(true)
                .notificationType(NotificationType.ACCOUNT_EVENT)
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS).build();
    }
}
