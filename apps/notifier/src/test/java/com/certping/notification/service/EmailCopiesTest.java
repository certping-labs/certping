// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.certping.notification.enums.NotificationAction;
import com.certping.notification.model.NotificationEvent;
import tools.jackson.databind.json.JsonMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class EmailCopiesTest {

    private static final List<String> CC = List.of("legal@example.com");

    private final EmailCopies copies = new EmailCopies("example.com, Example.net");

    @Test
    void keepsBareAllowedDistinctCopiesThatAreNotAlreadyRecipients() {
        NotificationEvent event = NotificationEvent.builder()
                .cc(List.of(" legal@example.com ", "LEGAL@example.com", "not an address", "",
                        "attorney@law.test", "ops@example.net", "reviewer@example.com"))
                .build();

        assertThat(copies.of(event, List.of("Reviewer@example.com")))
                .containsExactly("legal@example.com", "ops@example.net");
    }

    @Test
    void refusesDisplayNamesGroupsAndDotlessDomains() {
        assertThat(EmailCopies.bareAddress("CertPing <legal@example.com>")).isNull();
        assertThat(EmailCopies.bareAddress("\"Legal\" <legal@example.com>")).isNull();
        assertThat(EmailCopies.bareAddress("team: a@example.com, b@example.com;")).isNull();
        assertThat(EmailCopies.bareAddress("legal@example")).isNull();
        assertThat(EmailCopies.bareAddress("legal@example.")).isNull();
        assertThat(EmailCopies.bareAddress("a@b@example.com")).isNull();
        assertThat(EmailCopies.bareAddress(" legal@example.com ")).isEqualTo("legal@example.com");
    }

    @Test
    void dropsAnAddressOutsideTheAllowedDomainsAndLogsOnlyItsDomain() {
        Logger logger = (Logger) LoggerFactory.getLogger(EmailCopies.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            NotificationEvent event = NotificationEvent.builder()
                    .cc(List.of("someone@outside.test", "legal@sub.example.com", "legal@example.com")).build();

            assertThat(copies.of(event, List.of("attorney@law.test"))).containsExactly("legal@example.com");
            assertThat(appender.list).extracting(ILoggingEvent::getFormattedMessage)
                    .anySatisfy(message -> assertThat(message).endsWith("outside.test").doesNotContain("someone"))
                    .noneSatisfy(message -> assertThat(message).contains("someone@"));
        } finally {
            logger.detachAppender(appender);
        }
    }

    @Test
    void anEventWithoutCopiesHasNone() {
        assertThat(copies.of(NotificationEvent.builder().build(), List.of("a@b.test"))).isEmpty();
    }

    @Test
    void theCarrierIsTheRecipientWhoseAddressSortsFirstWhateverTheOrder() {
        assertThat(EmailCopies.carrier(List.of("zed@law.test", "Amy@law.test", "bob@law.test"))).isEqualTo(1);
        assertThat(EmailCopies.carrier(List.of("bob@law.test", "zed@law.test", "amy@law.test"))).isEqualTo(2);
    }

    @Test
    void anEventFromAProducerThatAddsFieldsStillParses() throws Exception {
        NotificationEvent event = JsonMapper.builderWithJackson2Defaults().build().readValue(
                "{\"email\":\"a@b.test\",\"cc\":[\"legal@example.com\"],\"someNewField\":1}", NotificationEvent.class);

        assertThat(event.getCc()).containsExactly("legal@example.com");
    }

    // ── Deliver-once delivery ────────────────────────────────────────────

    @Test
    void aDeliverOnceEventCopiesCcOnTheCarriersMessageOnly() {
        RecipientClaims claims = mock(RecipientClaims.class);
        EmailProvider provider = mock(EmailProvider.class);
        RecipientDelivery delivery = delivery(claims, provider);
        when(claims.claim(any(), any(), any(), any(), any())).thenAnswer(invocation -> claimed());
        when(claims.markDelivered(any())).thenReturn(true);
        try {
            delivery.deliver(event("cc-1"), List.of("zed@law.test", "amy@law.test"), "template", "subject", Map.of(), "{}");
        } finally {
            delivery.stop();
        }

        verify(provider).sendTemplatedEmail(eq("amy@law.test"), eq(CC), eq("subject"), eq("template"), any());
        verify(provider).sendTemplatedEmail("zed@law.test", "subject", "template", Map.of());
        verify(provider, times(1)).sendTemplatedEmail(any(), anyList(), any(), any(), any());
        verify(claims, never()).claim(any(), eq("legal@example.com"), any(), any(), any());
    }

    @Test
    void aDeliverOnceRetryDoesNotCopyAgainOnceTheCarrierHasIt() {
        RecipientClaims claims = mock(RecipientClaims.class);
        EmailProvider provider = mock(EmailProvider.class);
        RecipientDelivery delivery = delivery(claims, provider);
        when(claims.claim(any(), eq("amy@law.test"), any(), any(), any())).thenReturn(new RecipientClaims.AlreadyDelivered());
        when(claims.claim(any(), eq("zed@law.test"), any(), any(), any())).thenAnswer(invocation -> claimed());
        when(claims.markDelivered(any())).thenReturn(true);
        try {
            delivery.deliver(event("cc-2"), List.of("zed@law.test", "amy@law.test"), "template", "subject", Map.of(), "{}");
        } finally {
            delivery.stop();
        }

        verify(provider, never()).sendTemplatedEmail(any(), anyList(), any(), any(), any());
        verify(provider).sendTemplatedEmail("zed@law.test", "subject", "template", Map.of());
    }

    @Test
    void aDeliverOnceRetryOfTheCarrierCopiesAgainBecauseItsFirstSendDidNotLand() {
        RecipientClaims claims = mock(RecipientClaims.class);
        EmailProvider provider = mock(EmailProvider.class);
        RecipientDelivery delivery = delivery(claims, provider);
        when(claims.claim(any(), eq("amy@law.test"), any(), any(), any())).thenAnswer(invocation -> claimed());
        when(claims.claim(any(), eq("zed@law.test"), any(), any(), any())).thenReturn(new RecipientClaims.AlreadyDelivered());
        when(claims.markDelivered(any())).thenReturn(true);
        try {
            delivery.deliver(event("cc-3"), List.of("zed@law.test", "amy@law.test"), "template", "subject", Map.of(), "{}");
        } finally {
            delivery.stop();
        }

        verify(provider).sendTemplatedEmail(eq("amy@law.test"), eq(CC), eq("subject"), eq("template"), any());
        verify(provider, never()).sendTemplatedEmail(eq("zed@law.test"), any(), any(), any());
    }

    private RecipientDelivery delivery(RecipientClaims claims, EmailProvider provider) {
        when(claims.lease()).thenReturn(Duration.ofMinutes(5));
        DeliveryTimeouts timeouts = new DeliveryTimeouts("smtp", 100, 100, 100, Duration.ofSeconds(5), Duration.ofMinutes(5));
        return new RecipientDelivery(claims, provider, timeouts, new SimpleMeterRegistry(), copies);
    }

    private static RecipientClaims.Claimed claimed() {
        return new RecipientClaims.Claimed(new RecipientClaims.Claim(1, OffsetDateTime.now(), System.nanoTime(), false));
    }

    private static NotificationEvent event(String requestId) {
        return NotificationEvent.builder().requestId(requestId)
                .notificationAction(NotificationAction.CERT_ISSUANCE_SUCCESS)
                .cc(CC).build();
    }
}
