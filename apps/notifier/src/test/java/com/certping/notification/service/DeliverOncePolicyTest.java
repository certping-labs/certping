// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.enums.NotificationAction;
import com.certping.notification.model.NotificationEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Which key DeliverOncePolicy makes an event deliver-once under, and when it leaves the event alone. */
class DeliverOncePolicyTest {

    private static final String KEY = ProducerEnvelopes.featureKey("PAUSED");

    @Test
    void theFeatureEnvelopeStaysDeliverOnceUnderThePublishersKey() {
        NotificationEvent event = ProducerEnvelopes.read(ProducerEnvelopes.feature("PAUSED"));
        assertThat(event.isDeliverOnce()).as("the producer's own flag").isTrue();
        assertThat(event.getRequestId()).isEqualTo(KEY);

        DeliverOncePolicy.apply(event);
        DeliverOncePolicy.apply(event);

        assertThat(event.idempotencyKey()).isEqualTo(KEY);
        assertThat(event.isDeliverOnce()).isTrue();
    }

    @Test
    void theNotDeployedEnvelopeBecomesDeliverOnceUnderItsRequestId() {
        NotificationEvent event = ProducerEnvelopes.read(ProducerEnvelopes.renewedNotDeployed());
        assertThat(event.isDeliverOnce()).as("the producer sets no flag").isFalse();

        DeliverOncePolicy.apply(event);

        assertThat(event.idempotencyKey()).isEqualTo(ProducerEnvelopes.NOT_DEPLOYED_KEY);
        assertThat(event.getNotificationKey()).isNull();
        assertThat(event.isDeliverOnce()).isTrue();
    }

    @Test
    void anExplicitNotificationKeyWins() {
        NotificationEvent event = event(NotificationAction.FEATURE_RESUMED, "req-1",
                Map.of("idempotencyKey", KEY, "requestId", "field-req"));
        event.setNotificationKey("explicit-key");

        DeliverOncePolicy.apply(event);

        assertThat(event.idempotencyKey()).isEqualTo("explicit-key");
        assertThat(event.isDeliverOnce()).isTrue();
    }

    @Test
    void thePublishersKeyWinsOverTheRequestIds() {
        NotificationEvent event = event(NotificationAction.FEATURE_PAUSED, "req-1",
                Map.of("idempotencyKey", KEY, "requestId", "field-req"));

        DeliverOncePolicy.apply(event);

        assertThat(event.idempotencyKey()).isEqualTo(KEY);
    }

    @Test
    void theEnvelopeRequestIdWinsOverTheTemplateFieldOne() {
        NotificationEvent event = event(NotificationAction.CERT_RENEWED_NOT_DEPLOYED, "req-1",
                Map.of("requestId", "field-req"));

        DeliverOncePolicy.apply(event);

        assertThat(event.idempotencyKey()).isEqualTo("req-1");
        assertThat(event.isDeliverOnce()).isTrue();
    }

    @Test
    void invalidKeysAreSkippedForTheNextValidOne() {
        NotificationEvent event = event(NotificationAction.CERT_RENEWED_NOT_DEPLOYED, "bad id\r\nX-Header: 1",
                Map.of("idempotencyKey", "also bad", "requestId", "field-req:not-deployed"));

        DeliverOncePolicy.apply(event);

        assertThat(event.idempotencyKey()).isEqualTo("field-req:not-deployed");
        assertThat(event.isDeliverOnce()).isTrue();
    }

    @ParameterizedTest
    @EnumSource(value = NotificationAction.class,
            names = {"FEATURE_PAUSED", "FEATURE_RESUMED", "CERT_RENEWED_NOT_DEPLOYED"})
    void anEventWithNoValidKeyIsDeliveredAsUsual(NotificationAction action) {
        NotificationEvent event = event(action, "bad id", Map.of("idempotencyKey", "{{x}}", "requestId", ""));

        DeliverOncePolicy.apply(event);

        assertThat(event.isDeliverOnce()).isFalse();
        assertThat(event.getNotificationKey()).isNull();
        assertThat(event.getRequestId()).isEqualTo("bad id");
    }

    @Test
    void otherActionsAreLeftAlone() {
        NotificationEvent event = event(NotificationAction.CERT_RENEWAL_SUCCESS, "req-1", Map.of("idempotencyKey", KEY));

        DeliverOncePolicy.apply(event);

        assertThat(event.getNotificationKey()).isNull();
        assertThat(event.isDeliverOnce()).isFalse();
    }

    @Test
    void aNullEventIsIgnored() {
        DeliverOncePolicy.apply(null);
    }

    private static NotificationEvent event(NotificationAction action, String requestId, Map<String, Object> fields) {
        return NotificationEvent.builder().notificationAction(action).requestId(requestId)
                .templateFields(new HashMap<>(fields)).build();
    }
}
