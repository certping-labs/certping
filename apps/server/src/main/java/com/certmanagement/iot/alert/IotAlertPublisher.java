// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.alert;

import com.certmanagement.messaging.NotificationPublisher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Publishes IoT operational alerts onto whichever channels an organization has enabled.
 *
 * <p>Severity maps onto the platform's existing routing rather than a new mechanism: CRITICAL uses a
 * failure action, so it also opens a PagerDuty or ServiceNow incident, while WARNING stays on email
 * and chat.
 *
 * <p>Rate limiting rides on {@code dedupeKey} instead of a state table. The key becomes part of the
 * deterministic {@code requestId} that the notifier treats as a natural key, so a caller either binds
 * an alert to one operation (pass that operation's xref, alerting exactly once) or to one per window
 * (pass {@link #hourBucket()}, collapsing a storm into a single alert per hour).
 *
 * <p>The payload is built eagerly but the send is deferred to after commit when a transaction is
 * open, so no database transaction is held across the outbound call and a rolled-back change never
 * alerts. Alerting must not break the flow that noticed the problem, so failures here are swallowed.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class IotAlertPublisher {

    public enum Severity { CRITICAL, WARNING }

    private static final String ACTION_CRITICAL = "IOT_CRITICAL_ALERT";
    private static final String ACTION_WARNING  = "IOT_WARNING_ALERT";

    private final NotificationPublisher notificationPublisher;

    public void critical(Long organizationId, String scenario, String title, String summary,
                         String dedupeKey, String certificateXref, Map<String, Object> facts) {
        publish(Severity.CRITICAL, organizationId, scenario, title, summary, dedupeKey,
                certificateXref, facts);
    }

    public void warning(Long organizationId, String scenario, String title, String summary,
                        String dedupeKey, String certificateXref, Map<String, Object> facts) {
        publish(Severity.WARNING, organizationId, scenario, title, summary, dedupeKey,
                certificateXref, facts);
    }

    public void publish(Severity severity, Long organizationId, String scenario, String title,
                        String summary, String dedupeKey, String certificateXref,
                        Map<String, Object> facts) {
        if (organizationId == null) {
            return;
        }
        String action = severity == Severity.CRITICAL ? ACTION_CRITICAL : ACTION_WARNING;
        Map<String, Object> details =
                buildDetails(severity, organizationId, scenario, title, summary, dedupeKey, facts);

        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    send(action, severity, organizationId, scenario, dedupeKey, certificateXref, details);
                }
            });
            return;
        }
        send(action, severity, organizationId, scenario, dedupeKey, certificateXref, details);
    }

    private Map<String, Object> buildDetails(Severity severity, Long organizationId, String scenario,
                                             String title, String summary, String dedupeKey,
                                             Map<String, Object> facts) {
        Map<String, Object> details = new LinkedHashMap<>();
        // Every token an alert template references must be present, because the notifier leaves
        // unmatched {{placeholders}} in the rendered body verbatim.
        details.put("alertScenario", scenario);
        details.put("alertSeverity", severity.name());
        details.put("alertTitle", title);
        details.put("alertSummary", summary);
        details.put("alertDetail", joinFacts(facts));
        if (facts != null) {
            facts.forEach((key, value) -> {
                if (value != null) {
                    details.putIfAbsent(key, value);
                }
            });
        }
        details.put("requestId", "iot-alert:" + scenario + ":" + organizationId + ":" + dedupeKey);
        return details;
    }

    private void send(String action, Severity severity, Long organizationId, String scenario,
                      String dedupeKey, String certificateXref, Map<String, Object> details) {
        try {
            notificationPublisher.publish(action, String.valueOf(organizationId), certificateXref, details);
            log.info("[IotAlert] {} alert published org={} scenario={} dedupe={}",
                    severity, organizationId, scenario, dedupeKey);
        } catch (Exception exception) {
            log.error("[IotAlert] Failed to publish {} alert org={} scenario={}: {}",
                    severity, organizationId, scenario, exception.getMessage(), exception);
        }
    }

    /** Collapses repeat alerts to one per organization per hour when passed as the dedupe key. */
    public static String hourBucket() {
        return OffsetDateTime.now().truncatedTo(ChronoUnit.HOURS).toString();
    }

    /** Same idea over a day, for a condition that persists and would be noise repeated hourly. */
    public static String dayBucket() {
        return OffsetDateTime.now().toLocalDate().toString();
    }

    private static String joinFacts(Map<String, Object> facts) {
        if (facts == null || facts.isEmpty()) {
            return "";
        }
        return facts.entrySet().stream()
                .filter(entry -> entry.getValue() != null && !entry.getValue().toString().isBlank())
                .map(entry -> entry.getKey() + ": " + entry.getValue())
                .collect(Collectors.joining(" · "));
    }
}
