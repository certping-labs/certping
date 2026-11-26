// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.integration;

import com.certmanagement.service.audit.SupportAuditRecorder;
import com.certmanagement.service.notification.NotificationPreferenceService;
import com.certmanagement.support.incidents.api.model.InternalPagerDutyIncidentPayload;
import com.certmanagement.support.incidents.api.model.InternalServiceNowIncidentPayload;
import com.certmanagement.support.incidents.api.model.PagerDutyIncidentSeverity;
import com.certmanagement.support.incidents.api.model.ServiceNowIncidentImpact;
import com.certmanagement.support.incidents.api.model.ServiceNowIncidentUrgency;
import com.certmanagement.support.incidents.application.IncidentService;
import com.certmanagement.support.integrations.api.model.IntegrationNotificationData;
import com.certmanagement.support.integrations.api.model.IntegrationResponse;
import com.certmanagement.support.integrations.api.model.SendIntegrationNotificationRequest;
import com.certmanagement.support.integrations.application.IntegrationDeliveryGate;
import com.certmanagement.support.integrations.application.IntegrationNotificationService;
import com.certmanagement.support.integrations.application.IntegrationService;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import com.certmanagement.support.integrations.domain.IntegrationStatus;
import com.certmanagement.util.MdcContextPropagator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/**
 * Dispatches certificate, agent and IoT events to all active organization integrations
 * (Teams, Slack, PagerDuty, ServiceNow ITSM) by calling the support module's services directly.
 */
@Slf4j
@Component
public class IntegrationNotificationClient {

    // Actions that should also trigger PagerDuty / ServiceNow incidents.
    static final Set<String> FAILURE_ACTIONS = Set.of(
            "CERT_ISSUANCE_FAILED",
            "CERT_RENEWAL_FAILED",
            "CERT_DEPLOYMENT_FAILED",
            "CERT_REVOCATION_FAILED",
            "AGENT_ERROR",
            "IOT_CRITICAL_ALERT"
    );

    static final String SUPPRESSED_CHANNEL = "integration";

    // Virtual-thread-per-task executor — cheap, I/O-optimised, no pool starvation.
    private final Executor virtualExecutor = Executors.newVirtualThreadPerTaskExecutor();

    private final IntegrationService integrationService;
    private final IntegrationNotificationService integrationNotificationService;
    private final IncidentService incidentService;
    private final IntegrationDeliveryGate deliveryGate;
    /** The organization's notification settings: a category its admins turned off is not posted either. */
    private final NotificationPreferenceService preferences;
    /** Records a notification CertPing could not post as its integration.notified failure row (async, throttled). */
    private final SupportAuditRecorder supportAudit;

    @Value("${app.dashboard-base-url:}")
    private String dashboardBaseUrl;

    public IntegrationNotificationClient(IntegrationService integrationService,
                                         IntegrationNotificationService integrationNotificationService,
                                         IncidentService incidentService,
                                         IntegrationDeliveryGate deliveryGate,
                                         NotificationPreferenceService preferences,
                                         SupportAuditRecorder supportAudit) {
        this.integrationService = integrationService;
        this.integrationNotificationService = integrationNotificationService;
        this.incidentService = incidentService;
        this.deliveryGate = deliveryGate;
        this.preferences = preferences;
        this.supportAudit = supportAudit;
    }

    // Public API 

    /**
     * Submit the notification dispatch for {@code action} and return immediately.
     * All HTTP calls happen on background virtual threads.
     */
    public void dispatch(String orgId, String action, String certXref,
                              Map<String, Object> details) {
        Long orgIdLong = parseLong(orgId);
        if (orgIdLong == null) {
            log.warn("Integration dispatch skipped — cannot parse orgId='{}' for action={}", orgId, action);
            return;
        }
        // Submit to a virtual thread and return immediately to the caller. MdcContextPropagator
        // copies the caller's [req/corr/msg/org] MDC onto the virtual thread so dispatch logs
        // remain greppable by request ID.
        virtualExecutor.execute(MdcContextPropagator.wrap(
                () -> dispatchAll(orgIdLong, orgId, action, certXref, details)));
    }

    // Dispatch orchestration 

    private void dispatchAll(Long orgIdLong, String orgId, String action,
                             String certXref, Map<String, Object> details) {
        // 1. Discover active integrations (one synchronous call on a virtual thread).
        List<IntegrationResponse> recipients;
        try {
            recipients = fetchActiveIntegrations(orgIdLong).stream()
                    .filter(i -> i.provider().isWebhookProvider() || FAILURE_ACTIONS.contains(action))
                    .toList();
        } catch (Exception e) {
            log.warn("Integration dispatch aborted — failed to fetch integrations for orgId={}: {}",
                    orgId, e.getMessage());
            return;
        }

        if (recipients.isEmpty()) {
            log.debug("No active integrations for orgId={} — skipping dispatch for action={}", orgId, action);
            return;
        }
        if (!preferences.allows(orgIdLong, action)) {
            preferences.recordSuppressed(orgIdLong, action, SUPPRESSED_CHANNEL);
            return;
        }
        if (!deliveryGate.deliveryAllowed(orgIdLong)) {
            recipients.forEach(i -> deliveryGate.recordSkipped(orgIdLong, i.provider(), i.id(), action));
            return;
        }
        Set<String> active = recipients.stream().map(i -> i.provider().name()).collect(Collectors.toSet());

        log.debug("Active integrations for orgId={}: {} — dispatching action={}", orgId, active, action);

        // 2. Launch each provider notification in its own virtual thread (parallel).
        List<Runnable> tasks = new ArrayList<>();

        if (active.contains("SLACK")) {
            tasks.add(() -> sendNotification(orgIdLong, "SLACK", action, certXref, details));
        }
        if (active.contains("TEAMS")) {
            tasks.add(() -> sendNotification(orgIdLong, "TEAMS", action, certXref, details));
        }

        // Incident providers only on failures.
        if (FAILURE_ACTIONS.contains(action)) {
            if (active.contains("PAGERDUTY")) {
                tasks.add(() -> sendPagerDutyIncident(orgIdLong, action, certXref, details));
            }
            if (active.contains("SERVICENOW_ITSM")) {
                tasks.add(() -> sendServiceNowIncident(orgIdLong, action, certXref, details));
            }
        }

        // Each provider task runs on its own virtual thread; wrap so each inherits the MDC of the
        // dispatch call (which itself inherited from the original request via the wrap above).
        tasks.forEach(t -> virtualExecutor.execute(MdcContextPropagator.wrap(t)));
    }

    // Integration discovery 

    private List<IntegrationResponse> fetchActiveIntegrations(long orgId) {
        List<IntegrationResponse> body = integrationService.listIntegrationsForOrganization(orgId);
        if (body == null) return List.of();
        return body.stream()
                .filter(i -> i.status() == IntegrationStatus.ACTIVE)
                .toList();
    }

    // Teams / Slack notification 

    private void sendNotification(Long orgId, String provider, String action,
                                  String certXref, Map<String, Object> details) {
        try {
            String domain = domainOf(details, "");

            String linkUrl = buildLinkUrl(action, certXref, details);
            Map<String, String> facts = buildFacts(action, certXref, details);

            IntegrationNotificationData data = new IntegrationNotificationData(
                    buildTitle(action, domain, details),
                    buildMessage(action, domain, details),
                    linkUrl,
                    linkUrl != null ? "View in CertPing" : null,
                    facts.isEmpty() ? null : facts,
                    null
            );

            SendIntegrationNotificationRequest request = new SendIntegrationNotificationRequest(
                    orgId, IntegrationProvider.valueOf(provider), data);
            integrationNotificationService.sendNotification(request);
            log.info("Integration notification sent: provider={}, action={}, orgId={}", provider, action, orgId);
        } catch (Exception e) {
            log.warn("Integration notification failed (non-fatal): provider={}, action={}, orgId={}, error={}",
                    provider, action, orgId, e.getMessage());
            recordNotificationFailure(orgId, provider, action, e);
        }
    }

    /**
     * A notification that could not be posted, in the organization's trail; a delivered one is in the integration's
     * delivery history only. A failure to record is logged, never thrown into the dispatch.
     */
    private void recordNotificationFailure(Long orgId, String provider, String action, Exception failure) {
        try {
            supportAudit.integrationNotifyFailed(orgId, IntegrationProvider.valueOf(provider), action, failure);
        } catch (RuntimeException e) {
            log.warn("Integration notification audit row not recorded: provider={}, action={}, orgId={}, cause={}",
                    provider, action, orgId, e.getClass().getSimpleName());
        }
    }

    // PagerDuty incident 

    private void sendPagerDutyIncident(Long orgId, String action, String certXref,
                                       Map<String, Object> details) {
        try {
            String domain = domainOf(details, "unknown");
            String subject = incidentSubject(action, domain, details);
            String title  = buildTitle(action, domain, details).trim();

            InternalPagerDutyIncidentPayload payload = new InternalPagerDutyIncidentPayload(
                    stableAlertId(action, subject, String.valueOf(orgId)),
                    title,
                    "certping/certificate-monitor",
                    PagerDutyIncidentSeverity.valueOf(pagerDutySeverity(action)),
                    "certificate:" + subject,
                    null,
                    null,
                    null,
                    buildCustomDetails(action, certXref, details),
                    null
            );
            incidentService.createInternalPagerDutyIncident(orgId, payload);
            log.info("PagerDuty incident created: action={}, orgId={}, domain={}", action, orgId, domain);
        } catch (Exception e) {
            log.warn("PagerDuty incident failed (non-fatal): action={}, orgId={}, error={}",
                    action, orgId, e.getMessage());
        }
    }

    // ServiceNow incident ─

    private void sendServiceNowIncident(Long orgId, String action, String certXref,
                                        Map<String, Object> details) {
        try {
            String domain = domainOf(details, "unknown");
            String subject = incidentSubject(action, domain, details);
            String shortDesc = buildTitle(action, domain, details).trim();
            String desc = buildMessage(action, domain, details);
            String correlationDisplay = (certXref != null && !certXref.isBlank()) ? certXref : null;

            InternalServiceNowIncidentPayload payload = new InternalServiceNowIncidentPayload(
                    stableAlertId(action, subject, String.valueOf(orgId)),
                    shortDesc,
                    desc,
                    ServiceNowIncidentImpact.valueOf(serviceNowImpact(action)),
                    ServiceNowIncidentUrgency.valueOf(serviceNowUrgency(action)),
                    "inquiry",
                    "certificate",
                    null,
                    null,
                    null,
                    null,
                    "certificate:" + subject,
                    correlationDisplay,
                    null,
                    null
            );
            incidentService.createInternalServiceNowIncident(orgId, payload);
            log.info("ServiceNow incident created: action={}, orgId={}, domain={}", action, orgId, domain);
        } catch (Exception e) {
            log.warn("ServiceNow incident failed (non-fatal): action={}, orgId={}, error={}",
                    action, orgId, e.getMessage());
        }
    }

    // Payload builders ─

    private String buildTitle(String action, String domain, Map<String, Object> details) {
        String suffix = domain.isBlank() ? "" : " – " + domain;
        return switch (action) {
            case "IOT_CRITICAL_ALERT", "IOT_WARNING_ALERT" ->
                    str(details.get("alertTitle"), "IoT Device Certificate Alert");
            case "CERT_ISSUANCE_SUCCESS"           -> "Certificate Issued" + suffix;
            case "CERT_ISSUANCE_FAILED"            -> "Certificate Issuance Failed" + suffix;
            case "CERT_MANUAL_TXT_READY"           -> "DNS Action Required" + suffix;
            case "CERT_RENEWAL_SUCCESS"            -> "Certificate Renewed" + suffix;
            case "CERT_RENEWAL_FAILED"             -> "Certificate Renewal Failed" + suffix;
            case "CERT_DEPLOYMENT_SUCCESS"         -> "Certificate Deployed" + suffix;
            case "CERT_DEPLOYMENT_FAILED"          -> "Certificate Deployment Failed" + suffix;
            case "CERT_REVOCATION_SUCCESS"         -> "Certificate Revoked" + suffix;
            case "CERT_REVOCATION_FAILED"          -> "Certificate Revocation Failed" + suffix;
            case "CERT_EXPIRY_ALERT"               -> "Certificate Expiring Soon" + suffix;
            case "CERT_EXPIRED"                    -> "Certificate Expired" + suffix;
            case "IOT_ACTIVITY_DIGEST"             -> "IoT Device Certificate Activity";
            case "AGENT_ERROR"                     -> "Agent Error" + suffix;
            default -> action.replace("_", " ") + suffix;
        };
    }

    private String buildMessage(String action, String domain, Map<String, Object> details) {
        String d = domain.isBlank() ? "the domain" : domain;
        return switch (action) {
            case "CERT_ISSUANCE_SUCCESS"  -> "Certificate for " + d + " was successfully issued and is ready for use.";
            case "CERT_ISSUANCE_FAILED"   -> "Failed to issue certificate for " + d + ". " + errorDetail(details);
            case "CERT_MANUAL_TXT_READY"  -> "A DNS TXT record must be added for " + d + " to complete validation. Open the certificate details for the exact record value.";
            case "CERT_RENEWAL_SUCCESS"   -> "Certificate for " + d + " was successfully renewed.";
            case "CERT_RENEWAL_FAILED"    -> "Failed to renew certificate for " + d + ". " + errorDetail(details);
            case "CERT_DEPLOYMENT_SUCCESS"-> "Certificate for " + d + " was successfully deployed to the configured target.";
            case "CERT_DEPLOYMENT_FAILED" -> "Failed to deploy certificate for " + d + ". " + errorDetail(details);
            case "CERT_REVOCATION_SUCCESS"-> "Certificate for " + d + " has been revoked.";
            case "CERT_REVOCATION_FAILED" -> "Failed to revoke certificate for " + d + ". " + errorDetail(details);
            case "CERT_EXPIRY_ALERT"      -> {
                String days = str(details.get("daysRemaining"), "");
                yield days.isBlank()
                        ? "Certificate for " + d + " is expiring soon. Renew now to avoid disruption."
                        : "Certificate for " + d + " expires in " + days + " day(s). Renew now to avoid downtime.";
            }
            case "CERT_EXPIRED"           -> "Certificate for " + d + " has expired. Renew immediately to restore HTTPS.";
            case "IOT_ACTIVITY_DIGEST"    -> iotDigestMessage(details);
            case "IOT_CRITICAL_ALERT", "IOT_WARNING_ALERT" -> iotAlertMessage(details);
            case "AGENT_ERROR"            -> "An agent error occurred for " + d + ". " + errorDetail(details);
            default -> action.replace("_", " ") + " for " + d + ".";
        };
    }

    /** Count-driven summary for the IoT activity digest, which names a whole fleet, not one domain. */
    private String iotDigestMessage(Map<String, Object> details) {
        StringBuilder message = new StringBuilder("In the last ")
                .append(str(details.get("windowHours"), "24")).append(" hours: ")
                .append(str(details.get("certificatesIssued"), "0")).append(" issued, ")
                .append(str(details.get("enrollmentsFailed"), "0")).append(" enrollment failure(s), ")
                .append(str(details.get("certificatesRenewed"), "0")).append(" renewed, ")
                .append(str(details.get("certificatesRevoked"), "0")).append(" revoked.");
        String attention = str(details.get("revocationsNeedingAttention"), "0");
        if (!"0".equals(attention)) {
            message.append(" ").append(attention).append(" revocation(s) were not confirmed and need review.");
        }
        return message.toString();
    }

    /** IoT alerts name a connection or a fleet rather than a domain, so the body carries both lines. */
    private String iotAlertMessage(Map<String, Object> details) {
        String summary = str(details.get("alertSummary"), "");
        String detail = str(details.get("alertDetail"), "");
        if (summary.isBlank()) {
            return detail.isBlank() ? "An IoT device certificate alert was raised." : detail;
        }
        return detail.isBlank() ? summary : summary + " (" + detail + ")";
    }

    private Map<String, String> buildFacts(String action, String certXref, Map<String, Object> details) {
        Map<String, String> facts = new LinkedHashMap<>();
        addFact(facts, "Domain",           details.get("domain"));
        addFact(facts, "CA Provider",      details.get("caProvider"));
        addFact(facts, "Valid From",       details.get("validFrom"));
        addFact(facts, "Valid To",         details.get("validTo"));
        addFact(facts, "Days Remaining",   details.get("daysRemaining"));
        addFact(facts, "Deploy Target",    details.get("deploymentTarget"));
        addFact(facts, "Deploy Provider",  details.get("deploymentProvider"));
        addFact(facts, "Error Code",       details.get("errorCode"));
        addFact(facts, "Error Message",    details.get("errorMessage"));
        // IoT digest counts; absent (and so skipped) for every per-certificate action.
        addFact(facts, "Issued",             details.get("certificatesIssued"));
        addFact(facts, "Enrollment Failures", details.get("enrollmentsFailed"));
        addFact(facts, "Renewed",            details.get("certificatesRenewed"));
        addFact(facts, "Revoked",            details.get("certificatesRevoked"));
        addFact(facts, "Needs Attention",    details.get("revocationsNeedingAttention"));
        // IoT alert context; absent (and so skipped) for every other action.
        addFact(facts, "Scenario",         details.get("alertScenario"));
        addFact(facts, "Severity",         details.get("alertSeverity"));
        addFact(facts, "Common Name",      details.get("commonName"));
        addFact(facts, "Serial Number",    details.get("serialNumber"));
        addFact(facts, "Device Source",    details.get("sourceXref"));
        addFact(facts, "Stage",            details.get("stage"));
        addFact(facts, "Affected Devices", details.get("affectedDevices"));
        addFact(facts, "Certificate Ref",  certXref);
        return facts;
    }

    private Map<String, Object> buildCustomDetails(String action, String certXref, Map<String, Object> details) {
        Map<String, Object> d = new LinkedHashMap<>();
        addDetail(d, "domain",        details.get("domain"));
        addDetail(d, "caProvider",    details.get("caProvider"));
        addDetail(d, "validTo",       details.get("validTo"));
        addDetail(d, "errorCode",     details.get("errorCode"));
        addDetail(d, "errorMessage",  details.get("errorMessage"));
        addDetail(d, "alertScenario", details.get("alertScenario"));
        addDetail(d, "alertSummary",  details.get("alertSummary"));
        addDetail(d, "sourceXref",    details.get("sourceXref"));
        addDetail(d, "certXref",      certXref);
        return d;
    }

    /**
     * Builds an action-aware dashboard deep-link URL.
     *
     * <ul>
     *   <li>Deployment events  → {@code /cert-manager/deployments/{userDomainCertId}/{deploymentId}}</li>
     *   <li>All other cert events → {@code /cert-manager/manage/{certXref}}</li>
     * </ul>
     *
     * Returns {@code null} when {@code dashboardBaseUrl} is not configured or required
     * identifiers are missing for the given action type.
     */
    private String buildLinkUrl(String action, String certXref, Map<String, Object> details) {
        // Caller-supplied explicit URL always wins.
        String explicit = str(details.get("dashboardUrl"), "");
        if (!explicit.isBlank()) return explicit;
        if (dashboardBaseUrl == null || dashboardBaseUrl.isBlank()) return null;

        // app.dashboard-base-url may point at the dashboard page itself
        // (e.g. https://app.example.com/dashboard); strip back to the origin
        // so frontend routes like /cert-manager/... resolve without a doubled-up
        // /dashboard prefix.
        String origin = frontendOrigin(dashboardBaseUrl);

        // Deployment events.
        if (action != null && action.startsWith("CERT_DEPLOYMENT_")) {
            String udcId      = str(details.get("userDomainCertId"), "");
            String deployId   = str(details.get("deploymentId"), "");
            if (udcId.isBlank() || deployId.isBlank()) return null;
            return origin + "/cert-manager/deployments/" + udcId + "/" + deployId;
        }

        // IoT device-certificate events. The digest is org-wide and carries no xref, so it lands on
        // the inventory; a future per-certificate IoT action deep-links to that certificate.
        if (action != null && action.startsWith("IOT_")) {
            return (certXref == null || certXref.isBlank())
                    ? origin + "/machine-identity/device-certificates"
                    : origin + "/machine-identity/device-certificates/" + certXref;
        }

        // All other cert lifecycle events.
        if (certXref == null || certXref.isBlank()) return null;
        return origin + "/cert-manager/manage/" + certXref;
    }

    /** Extracts scheme://host[:port] from a configured base URL, dropping any path. */
    private static String frontendOrigin(String baseUrl) {
        String base = baseUrl == null ? "" : baseUrl.trim();
        try {
            java.net.URI uri = java.net.URI.create(base);
            if (uri.getScheme() != null && uri.getAuthority() != null) {
                return uri.getScheme() + "://" + uri.getAuthority();
            }
        } catch (IllegalArgumentException ignored) {
            // Not a parseable URI — fall through to best-effort trimming.
        }
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        return base;
    }

    // Severity / impact mappings 

    private String pagerDutySeverity(String action) {
        return switch (action) {
            case "CERT_EXPIRED", "AGENT_ERROR", "IOT_CRITICAL_ALERT"   -> "CRITICAL";
            case "CERT_ISSUANCE_FAILED", "CERT_RENEWAL_FAILED"         -> "ERROR";
            case "CERT_DEPLOYMENT_FAILED", "CERT_REVOCATION_FAILED"    -> "WARNING";
            default                                                     -> "ERROR";
        };
    }

    private String serviceNowImpact(String action) {
        return switch (action) {
            case "CERT_EXPIRED", "CERT_ISSUANCE_FAILED",
                    "CERT_RENEWAL_FAILED", "AGENT_ERROR",
                    "IOT_CRITICAL_ALERT"                               -> "HIGH";
            default                                                     -> "MEDIUM";
        };
    }

    private String serviceNowUrgency(String action) {
        return switch (action) {
            case "CERT_EXPIRED", "AGENT_ERROR", "IOT_CRITICAL_ALERT"   -> "HIGH";
            case "CERT_ISSUANCE_FAILED", "CERT_RENEWAL_FAILED",
                    "CERT_DEPLOYMENT_FAILED", "CERT_REVOCATION_FAILED" -> "HIGH";
            default                                                     -> "MEDIUM";
        };
    }

    // Utility ─

    private long stableAlertId(String action, String subject, String orgId) {
        return Math.abs((long) (action + ":" + subject + ":" + orgId).hashCode());
    }

    /**
     * The incident dedup and grouping key. IoT alerts carry no domain, so without the scenario every
     * one of them would collapse into a single incident per organization.
     */
    private String incidentSubject(String action, String domain, Map<String, Object> details) {
        if (action != null && action.startsWith("IOT_")) {
            return str(details.get("alertScenario"), "iot");
        }
        return domain;
    }

    /** Certificate events carry the certificate's {@code domain}. */
    private String domainOf(Map<String, Object> details, String fallback) {
        return str(details.get("domain"), fallback);
    }

    private String errorDetail(Map<String, Object> details) {
        String code = str(details.get("errorCode"), "");
        String msg  = str(details.get("errorMessage"), "");
        if (!code.isBlank() && !msg.isBlank()) return "Error: " + code + " — " + msg;
        if (!code.isBlank()) return "Error code: " + code;
        if (!msg.isBlank()) return msg;
        return "";
    }

    private void addFact(Map<String, String> facts, String key, Object value) {
        if (value == null) return;
        String s = value.toString().trim();
        if (!s.isBlank()) facts.put(key, s);
    }

    private void addDetail(Map<String, Object> map, String key, Object value) {
        if (value == null) return;
        String s = value.toString().trim();
        if (!s.isBlank()) map.put(key, s);
    }

    private String str(Object value, String fallback) {
        if (value == null) return fallback;
        String s = value.toString().trim();
        return s.isBlank() ? fallback : s;
    }

    private Long parseLong(String value) {
        try {
            return Long.parseLong(value);
        } catch (Exception e) {
            return null;
        }
    }
}
