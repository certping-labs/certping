// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditEvents;
import com.certmanagement.audit.AuditReason;
import com.certmanagement.audit.AuditReasons;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditScope;
import com.certmanagement.audit.AuditSubject;
import com.certmanagement.support.common.ApiException;
import com.certmanagement.support.incidents.domain.Incident;
import com.certmanagement.support.incidents.domain.IncidentCreationSource;
import com.certmanagement.support.integrations.domain.Integration;
import com.certmanagement.support.integrations.domain.IntegrationAuditAction;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.micrometer.core.instrument.Metrics;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Writes the integration events of the audit trail: integrations added, changed and removed; notifications
 * CertPing posted to a chat integration; incidents raised in PagerDuty or ServiceNow.
 *
 * <p>A change of CertPing's own data is written in that change's transaction ({@link AuditRecorder#record}, which
 * requires one): one {@code audit_events} row per action. An incident or notification CertPing raised on its
 * own is CertPing's row ({@link #DISPATCH_JOB}).
 *
 * <p>Notifications: a delivered one is not an audit event (the integration's delivery history has it). One CertPing
 * could not deliver is recorded as a failure, through the bounded async writer, at most once per organization,
 * integration and reason every {@value #NOTIFY_FAILURE_MINUTES} minutes: a broken webhook fails every notification
 * until someone fixes it, and one row says so. The rest are counted in
 * {@code certping_audit_throttled_total{event="integration.notified"}}. The throttle is per pod (Caffeine, at most
 * {@value #MAX_KEYS} keys).
 *
 * <p>Privacy: no secret (a webhook URL, a routing key, OAuth credentials) and no message is ever part of a row.
 */
@Component
public class SupportAuditRecorder {

    /** The job CertPing's own notifications and incidents act as. */
    public static final String DISPATCH_JOB = "integration-dispatch";

    /** A chat integration that did not accept the message. */
    public static final AuditReason INTEGRATION_DELIVERY_FAILED = AuditReason.of("INTEGRATION_DELIVERY_FAILED");

    private static final Pattern CODE = Pattern.compile("^[A-Z][A-Z0-9_]{0,63}$");

    static final long NOTIFY_FAILURE_MINUTES = 15;
    static final int MAX_KEYS = 10_000;
    /** The counter {@code AuditFailures} counts its throttled rows in. */
    static final String THROTTLED_METRIC = "certping.audit.throttled";

    private final AuditRecorder recorder;
    private final ConcurrentMap<String, Boolean> recentNotifyFailures;

    public SupportAuditRecorder(AuditRecorder recorder, Clock clock) {
        this.recorder = recorder;
        this.recentNotifyFailures = Caffeine.newBuilder()
                .ticker(() -> TimeUnit.MILLISECONDS.toNanos(clock.millis()))
                .expireAfterWrite(Duration.ofMinutes(NOTIFY_FAILURE_MINUTES))
                .maximumSize(MAX_KEYS)
                .<String, Boolean>build()
                .asMap();
    }

    // ── Integrations ─────────────────────────────────────────────────────

    /** {@code integration} was added, changed or removed; in the change's transaction. */
    public void integrationChanged(IntegrationAuditAction action, Integration integration) {
        AuditEventType type = switch (action) {
            case CREATED -> AuditEventType.INTEGRATION_CREATED;
            case UPDATED -> AuditEventType.INTEGRATION_UPDATED;
            case DELETED -> AuditEventType.INTEGRATION_DELETED;
        };
        Map<String, String> attributes = new LinkedHashMap<>();
        if (integration.getStatus() != null) {
            attributes.put("status", integration.getStatus().name());
        }
        recorder.record(AuditEvents.success(type, AuditSubject.builder()
                .organizationId(integration.getOrganizationId())
                .resourceId(integration.getId())
                .resourceRef(integration.getId() == null ? null : integration.getId().toString())
                .provider(providerName(integration.getProvider()))
                .attributes(attributes)
                .build()));
    }

    /**
     * CertPing could not post the {@code notification} event (its code, e.g. CERT_RENEWAL_FAILED) to
     * {@code provider}, for {@code failure}: recorded once per organization, integration and reason every
     * {@value #NOTIFY_FAILURE_MINUTES} minutes, the rest counted.
     */
    public void integrationNotifyFailed(Long organizationId, IntegrationProvider provider, String notification,
                                        Throwable failure) {
        AuditReason reason = deliveryReason(failure);
        String key = organizationId + "|" + provider + "|" + reason.code();
        if (recentNotifyFailures.putIfAbsent(key, Boolean.TRUE) != null) {
            Metrics.counter(THROTTLED_METRIC, "event", AuditEventType.INTEGRATION_NOTIFIED.key()).increment();
            return;
        }
        try (AuditScope scope = AuditScope.system(DISPATCH_JOB, organizationId)) {
            recorder.recordFailure(AuditEvents.failure(AuditEventType.INTEGRATION_NOTIFIED,
                    notification(organizationId, provider, notification), reason));
        }
    }

    // ── Incidents ────────────────────────────────────────────────────────

    /**
     * {@code incident} was raised; in the transaction that stored it. One CertPing raised on
     * its own ({@link IncidentCreationSource#INTERNAL_API}) is CertPing's row.
     */
    public void incidentTriggered(Incident incident) {
        Supplier<AuditEventRow> row = () -> AuditEvents.success(AuditEventType.INCIDENT_TRIGGERED,
                incident(incident.getOrganizationId(), incident.getSource(), incident.getProvider())
                        .resourceId(incident.getId())
                        .resourceRef(incident.getId() == null ? null : incident.getId().toString())
                        .attributes(incidentAttributes(incident.getSource(), incident.getExternalReference()))
                        .build());
        if (incident.getSource() == IncidentCreationSource.INTERNAL_API) {
            // CertPing's own incident: already raised at the provider, so its row never rolls the incident back.
            try (AuditScope scope = AuditScope.system(DISPATCH_JOB, incident.getOrganizationId())) {
                recorder.recordIsolated(row.get());
            }
        } else {
            recorder.record(row.get());
        }
    }

    /**
     * CertPing could not raise the incident it started on its own. A member's refused incident is recorded by
     * the endpoint ({@code @AuditFailure}), so this records CertPing's only.
     */
    public void incidentFailed(Long organizationId, IncidentCreationSource source, IntegrationProvider provider,
                               Throwable failure) {
        if (source != IncidentCreationSource.INTERNAL_API) {
            return;
        }
        try (AuditScope scope = AuditScope.system(DISPATCH_JOB, organizationId)) {
            recorder.recordFailure(AuditEvents.failure(AuditEventType.INCIDENT_TRIGGERED,
                    incident(organizationId, source, provider).attributes(incidentAttributes(source, null)).build(),
                    deliveryReason(failure)));
        }
    }

    /** "Slack", "Microsoft Teams", "PagerDuty", "ServiceNow"; null for none. */
    public static String providerName(IntegrationProvider provider) {
        if (provider == null) {
            return null;
        }
        return switch (provider) {
            case SLACK -> "Slack";
            case TEAMS -> "Microsoft Teams";
            case PAGERDUTY -> "PagerDuty";
            case SERVICENOW_ITSM -> "ServiceNow";
        };
    }

    /**
     * Why a delivery failed, by the failure's type and status only: a 404 is the integration gone, a refusal of
     * the request is what it is, and anything the provider or the network did is {@link #INTEGRATION_DELIVERY_FAILED}.
     */
    static AuditReason deliveryReason(Throwable failure) {
        if (failure instanceof ApiException api && api.status() >= 500) {
            return INTEGRATION_DELIVERY_FAILED;
        }
        AuditReason reason = AuditReasons.of(failure);
        return AuditReason.INTERNAL_ERROR.equals(reason) ? INTEGRATION_DELIVERY_FAILED : reason;
    }

    private static AuditSubject notification(Long organizationId, IntegrationProvider provider, String notification) {
        Map<String, String> attributes = new LinkedHashMap<>();
        if (notification != null && CODE.matcher(notification).matches()) {
            attributes.put("notification", notification);
        }
        return AuditSubject.builder().organizationId(organizationId).provider(providerName(provider))
                .attributes(attributes).build();
    }

    private static AuditSubject.AuditSubjectBuilder incident(Long organizationId, IncidentCreationSource source,
                                                             IntegrationProvider provider) {
        return AuditSubject.builder().organizationId(organizationId).provider(providerName(provider));
    }

    private static Map<String, String> incidentAttributes(IncidentCreationSource source, String reference) {
        Map<String, String> attributes = new LinkedHashMap<>();
        if (source != null) {
            attributes.put("source", source.name());
        }
        if (reference != null && !reference.isBlank()) {
            attributes.put("incidentReference", reference);
        }
        return attributes;
    }

}
