// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.model.NotificationEvent;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.cfg.EnumFeature;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Message bodies built the way the server builds them, step by step:
 * FEATURE_* through FeatureLifecycleNotifier.templateFields and
 * OrgAdminNotificationPublisher.publishOnceToOrgAdmins; CERT_RENEWED_NOT_DEPLOYED through
 * CertResponseProcessor's follow-up details and CERT_REVOCATION_FAILED through its agent-error details,
 * both sent by CertpingNotificationPublisher.publish.
 */
final class ProducerEnvelopes {

    static final long ORGANIZATION_ID = 42L;
    static final String CORRELATION_ID = "corr-1";
    static final String RENEWAL_REQUEST_ID = "renewal-req-9";
    /** CertResponseProcessor.notDeployedRequestId: the renewal response's request id + ":not-deployed". */
    static final String NOT_DEPLOYED_KEY = RENEWAL_REQUEST_ID + ":not-deployed";
    /** The revocation command's request id, which the agent's error echoes. */
    static final String REVOCATION_REQUEST_ID = "revoke-req-3";

    /** The listener's mapper settings: unknown fields and unknown enum values are tolerated. */
    static final ObjectMapper LISTENER_MAPPER = JsonMapper.builderWithJackson2Defaults()
            .configure(EnumFeature.READ_UNKNOWN_ENUM_VALUES_AS_NULL, true)
            // Publishers may add fields the notifier does not read yet; never fail on them.
            .disable(tools.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    private static final ObjectMapper PRODUCER_MAPPER = JsonMapper.builderWithJackson2Defaults().build();

    private ProducerEnvelopes() {
    }

    /** FeatureLifecycleState.idempotencyKey: organization, feature, transition and sequence. */
    static String featureKey(String transition) {
        return ORGANIZATION_ID + ":DISCOVERY:" + transition + ":9001";
    }

    /** "PAUSED" publishes FEATURE_PAUSED, "RESUMED" FEATURE_RESUMED. */
    static String feature(String transition) {
        return feature(transition, featureFields(transition));
    }

    static String feature(String transition, Map<String, Object> templateFields) {
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("notificationType", "ACCOUNT_EVENT");
        event.put("notificationAction", "FEATURE_" + transition);
        event.put("integrationType", "EMAIL");
        event.put("organizationId", String.valueOf(ORGANIZATION_ID));
        event.put("source", "certping-cert-manager");
        event.put("templateFields", new LinkedHashMap<>(templateFields));
        event.put("roles", List.of("ORGANIZATION_ADMIN"));
        event.put("requestId", featureKey(transition));
        event.put("correlationId", CORRELATION_ID);
        event.put("deliverOnce", true);
        return write(event);
    }

    static Map<String, Object> featureFields(String transition) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("organizationId", ORGANIZATION_ID);
        fields.put("organizationName", "Acme Ltd");
        fields.put("featureKey", "DISCOVERY");
        fields.put("featureName", "Certificate discovery");
        fields.put("items", List.of(Map.of("label", "Discovery configurations", "count", 12),
                Map.of("label", "Cloud accounts", "count", 3)));
        fields.put("occurredAt", Instant.parse("2026-10-06T09:15:00Z").toString());
        fields.put("idempotencyKey", featureKey(transition));
        return fields;
    }

    static String renewedNotDeployed() {
        return renewedNotDeployed(renewalDetails(), "CERT-NEW-2");
    }

    /** The follow-up's details; previousValidTo is the old certificate's OffsetDateTime.toString(). */
    static Map<String, Object> renewalDetails() {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("domain", "shop.example.com");
        details.put("validTo", "2027-01-04T12:00:00Z");
        details.put("previousValidTo", OffsetDateTime.parse("2026-11-01T00:00:00Z").toString());
        details.put("reason", "CERTIFICATE_DEPLOYMENT_DISABLED");
        details.put("previousCertificateXref", "CERT-OLD-1");
        details.put("requestId", NOT_DEPLOYED_KEY);
        return details;
    }

    static String renewedNotDeployed(Map<String, Object> details, String certificateXref) {
        return certificateEvent("CERT_RENEWED_NOT_DEPLOYED", details, certificateXref);
    }

    static String revocationFailed() {
        return revocationFailed(revocationErrorDetails(), "CERT-REV-7");
    }

    /** CertResponseProcessor.applyCertificateAgentError's details for a failed CERT_REVOCATION_COMMAND. */
    static Map<String, Object> revocationErrorDetails() {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("errorCode", "CA_UNAVAILABLE");
        details.put("domain", "shop.example.com");
        details.put("requestId", REVOCATION_REQUEST_ID);
        return details;
    }

    static String revocationFailed(Map<String, Object> details, String certificateXref) {
        return certificateEvent("CERT_REVOCATION_FAILED", details, certificateXref);
    }

    /** CertpingNotificationPublisher.publish: the details plus the certificate reference. */
    private static String certificateEvent(String action, Map<String, Object> details, String certificateXref) {
        Map<String, Object> templateFields = new LinkedHashMap<>(details);
        templateFields.put("certificateXref", certificateXref);
        String requestId = String.valueOf(templateFields.get("requestId"));
        String messageId = "msg-" + shortDigest(String.join("|", action, String.valueOf(ORGANIZATION_ID),
                certificateXref, requestId));
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("notificationType", "ACCOUNT_EVENT");
        event.put("notificationAction", action);
        event.put("integrationType", "EMAIL");
        event.put("organizationId", String.valueOf(ORGANIZATION_ID));
        event.put("roles", List.of("ORGANIZATION_ADMIN"));
        event.put("source", "certping-cert-manager");
        event.put("messageId", messageId);
        event.put("requestId", requestId);
        event.put("correlationId", CORRELATION_ID);
        event.put("templateFields", templateFields);
        return write(event);
    }

    static NotificationEvent read(String body) {
        try {
            List<NotificationEvent> events = LISTENER_MAPPER.readValue(body, new TypeReference<>() {});
            assertThat(events).hasSize(1);
            return events.get(0);
        } catch (Exception unreadable) {
            throw new IllegalStateException(unreadable);
        }
    }

    /** Read as the listener reads a body: deserialized, then DeliverOncePolicy applied. */
    static NotificationEvent readAsListener(String body) {
        NotificationEvent event = read(body);
        DeliverOncePolicy.apply(event);
        return event;
    }

    private static String write(Map<String, Object> event) {
        try {
            return PRODUCER_MAPPER.writeValueAsString(List.of(event));
        } catch (Exception unwritable) {
            throw new IllegalStateException(unwritable);
        }
    }

    /** CertpingNotificationPublisher.shortDigest: the first 12 bytes of SHA-256, as hex. */
    private static String shortDigest(String fingerprint) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(fingerprint.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash, 0, 12);
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
