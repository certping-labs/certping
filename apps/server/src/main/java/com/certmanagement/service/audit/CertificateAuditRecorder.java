// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditActorType;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditEvents;
import com.certmanagement.audit.AuditOutcome;
import com.certmanagement.audit.AuditReason;
import com.certmanagement.audit.AuditReasons;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditSubject;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.enums.CaProvider;
import io.micrometer.core.instrument.Metrics;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Writes the certificate and deployment events of the audit trail: a member's requests (issue, manual issue,
 * DNS validation, renewal, revocation, deployment, deletion, conversion), what CertPing then reports for them
 * (issued, renewed, revoked, deployed, or failed, with the reason), and what CertPing does on its own (automatic
 * renewals and deploys, the ones it skipped because a feature is off, expiry, cleanup).
 *
 * <p>Who acted comes from the {@link com.certmanagement.audit.AuditContext}: the request's member, or CertPing
 * inside an {@link com.certmanagement.audit.AuditScope#system} the caller opened (a job, an agent response). A
 * row from an agent response names the member whose request it answers by id only ({@code requestedBy}).
 *
 * <p>Two write paths, each method saying which it takes:
 * <ul>
 *   <li>most methods write in the caller's transaction, so the row commits and rolls back with the change it
 *       describes: a member's request through {@link AuditRecorder#record}, CertPing's own work through
 *       {@link AuditRecorder#recordIsolated}, which can never fail the agent result or job it describes;</li>
 *   <li>the methods for work that runs with no transaction open (an automatic deploy's per-target dispatch, a
 *       manual deploy refused after it was accepted) queue the row for the bounded async writer.</li>
 * </ul>
 *
 * <p>A failure's cause is an {@link AuditReason} code only: an agent's code goes through
 * {@link AuditReason#fromAgent} (which unwraps {@code RETRY_GIVE_UP}); its error text is never passed in.
 */
@Slf4j
@Component
public class CertificateAuditRecorder {

    /** The job agent responses are recorded as. */
    public static final String AGENT_JOB = "agent-response";
    /** The automatic renewal job. */
    public static final String RENEWAL_JOB = "trigger-renewals";
    /** The job that ends renewals whose agent result never arrived. */
    public static final String RENEWAL_RECOVERY_JOB = "recover-stalled-renewals";
    /** The reason a renewal is held for an expired CertPing DNS key. */
    static final String DNS_KEY_EXPIRED = "DNS_KEY_EXPIRED";
    /** The job that marks certificates expired. */
    public static final String EXPIRY_JOB = "mark-expired-certs";
    /** The job that removes certificates a day after they expired or were revoked. */
    public static final String CLEANUP_JOB = "expiry-cleanup";

    /** What removed a certificate when it was not its own delete. */
    public static final String SOURCE_MANAGED_DOMAIN = "MANAGED_DOMAIN";
    public static final String SOURCE_EXPIRY_CLEANUP = "EXPIRY_CLEANUP";

    /** How often the same skip of one certificate's automatic renewal is written by the renewal job. */
    static final Duration SKIP_REPEAT_EVERY = Duration.ofHours(24);
    static final String THROTTLED_METRIC = "certping.audit.throttled";
    static final String UNRECORDED_METRIC = "certping.audit.failure.unrecorded";
    private static final Pattern CODE = Pattern.compile("^[A-Z][A-Z0-9_]{0,63}$");

    private static final Map<CaProvider, String> CA_LABELS = Map.of(
            CaProvider.LETS_ENCRYPT, "Let's Encrypt",
            CaProvider.DIGICERT, "DigiCert",
            CaProvider.GLOBALSIGN, "GlobalSign");

    private static final Map<String, String> TARGET_LABELS = Map.ofEntries(
            Map.entry("AZURE_KV", "Azure Key Vault"),
            Map.entry("AWS_ACM", "AWS Certificate Manager"),
            Map.entry("AZURE_APP_GW", "Azure Application Gateway"),
            Map.entry("AZURE_APP_GW_CONTAINERS", "Azure Application Gateway for Containers"),
            Map.entry("AZURE_AFD", "Azure Front Door"),
            Map.entry("AWS_ALB", "AWS Application Load Balancer"),
            Map.entry("AWS_NLB", "AWS Network Load Balancer"),
            Map.entry("AWS_API_GW_REST", "AWS API Gateway (REST)"),
            Map.entry("AWS_API_GW_HTTP", "AWS API Gateway (HTTP)"),
            Map.entry("AWS_CLOUDFRONT", "AWS CloudFront"),
            Map.entry("AWS_ORGANIZATION", "AWS Organization"),
            Map.entry("GCP_CERT_MANAGER", "Google Cloud Certificate Manager"),
            Map.entry("GCP_ALB", "Google Cloud Application Load Balancer"),
            Map.entry("GCP_PROXY_NLB", "Google Cloud Proxy Network Load Balancer"),
            Map.entry("GCP_API_GW", "Google Cloud API Gateway"),
            Map.entry("GCP_CLOUD_CDN", "Google Cloud CDN"),
            Map.entry("CLOUDFLARE_EDGE", "Cloudflare"),
            Map.entry("KUBERNETES_SECRETS", "Kubernetes"),
            Map.entry("AKAMAI_CPS", "Akamai"),
            Map.entry("F5_BIGIP", "F5 BIG-IP"));

    private static final Map<String, String> FEATURE_LABELS = Map.of(
            FeatureFlags.CERTIFICATE_RENEWAL, "Certificate Renewal",
            FeatureFlags.CERTIFICATE_DEPLOYMENT, "Certificate Deployment",
            FeatureFlags.CERTIFICATE_ISSUANCE, "Certificate Issuance",
            FeatureFlags.CA_LETS_ENCRYPT, "Let's Encrypt",
            FeatureFlags.CA_DIGICERT, "DigiCert",
            FeatureFlags.CA_GLOBALSIGN, "GlobalSign");

    private final AuditRecorder recorder;
    private final Clock clock;
    private final CredentialAuditRecorder credentialAudit;
    private final CredentialReferenceRepository credentials;

    public CertificateAuditRecorder(AuditRecorder recorder, Clock clock, CredentialAuditRecorder credentialAudit,
                                    CredentialReferenceRepository credentials) {
        this.recorder = recorder;
        this.credentialAudit = credentialAudit;
        this.credentials = credentials;
        this.clock = clock;
    }

    // ── A member's requests (the change's transaction) ──────────────────

    /** A certificate was requested, to be deployed to {@code deploymentTargets} targets once issued. */
    public void issueRequested(CertificateEntity cert, int deploymentTargets) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "wildcard", Boolean.TRUE.equals(cert.getWildcard()) ? "true" : null);
        put(attributes, "sanDomains", sanCount(cert));
        put(attributes, "deploymentTargets", deploymentTargets > 0 ? Integer.toString(deploymentTargets) : null);
        record(AuditEvents.success(AuditEventType.CERTIFICATE_ISSUE_REQUESTED,
                certificate(cert).attributes(attributes).build()));
    }

    /** A manual (DNS TXT record) issuance was started. */
    public void manualIssueRequested(CertificateEntity cert) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "wildcard", Boolean.TRUE.equals(cert.getWildcard()) ? "true" : null);
        put(attributes, "sanDomains", sanCount(cert));
        record(AuditEvents.success(AuditEventType.CERTIFICATE_MANUAL_ISSUE_REQUESTED,
                certificate(cert).attributes(attributes).build()));
    }

    /** The member confirmed a manual issuance's DNS records and CertPing started validating them. */
    public void dnsValidationStarted(CertificateEntity cert) {
        record(AuditEvents.success(AuditEventType.CERTIFICATE_DNS_VALIDATED, certificate(cert).build()));
    }

    /** A member requested renewal of {@code cert}. */
    public void renewalRequested(CertificateEntity cert) {
        record(AuditEvents.success(AuditEventType.CERTIFICATE_RENEWAL_REQUESTED, certificate(cert).build()));
    }

    /** Revocation of {@code cert} was requested, for {@code revocationReason} (an RFC 5280 reason name). */
    public void revokeRequested(CertificateEntity cert, String revocationReason) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "revocationReason", code(revocationReason));
        record(AuditEvents.success(AuditEventType.CERTIFICATE_REVOKE_REQUESTED,
                certificate(cert).attributes(attributes).build()));
    }

    /**
     * {@code cert} was deleted, by the member (its own delete or its managed domain's) or by CertPing.
     *
     * @param source         null for the certificate's own delete; {@link #SOURCE_MANAGED_DOMAIN} or
     *                       {@link #SOURCE_EXPIRY_CLEANUP} otherwise
     * @param previousStatus the status it was deleted in
     */
    public void deleted(CertificateEntity cert, String source, String previousStatus) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "source", source);
        put(attributes, "status", code(previousStatus));
        record(AuditEvents.success(AuditEventType.CERTIFICATE_DELETED, certificate(cert).attributes(attributes).build()));
    }

    /** {@code cert} was switched to automatic renewal; what happens next is {@code plannedAction}. */
    public void convertedToAutomated(CertificateEntity cert, String activationMode, String plannedAction,
                                     int deploymentTargets) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "activationMode", code(activationMode));
        put(attributes, "plannedAction", code(plannedAction));
        put(attributes, "deploymentTargets", Integer.toString(deploymentTargets));
        record(AuditEvents.success(AuditEventType.CERTIFICATE_CONVERTED_TO_AUTOMATED,
                certificate(cert).attributes(attributes).build()));
    }

    /** A member started deploying {@code cert} to a target of {@code targetType}. */
    public void deploymentRequested(CertificateEntity cert, String targetType) {
        record(AuditEvents.success(AuditEventType.DEPLOYMENT_REQUESTED, deployment(cert, targetType, null)
                .attributes(deploymentAttributes(targetType, null, null)).build()));
    }

    /**
     * The deployment targets of {@code domain}'s certificate were replaced from {@code before} to {@code after} by an
     * issuance, a renewal or a conversion that named its own: one {@code deployment_target.added} or {@code .removed}
     * row per target that changed, as the targets' own endpoints write them. The credentials named are read in one
     * query, only when something changed; one that is not the organization's, or no longer exists, is named by its
     * reference only.
     */
    public void deploymentTargetsReplaced(Long organizationId, String domain, Collection<String> before,
                                          Collection<String> after) {
        Set<String> was = before == null ? Set.of() : new LinkedHashSet<>(before);
        Set<String> now = after == null ? Set.of() : new LinkedHashSet<>(after);
        List<String> added = now.stream().filter(xref -> !was.contains(xref)).toList();
        List<String> removed = was.stream().filter(xref -> !now.contains(xref)).toList();
        if (added.isEmpty() && removed.isEmpty()) {
            return;
        }
        List<String> changed = new ArrayList<>(added);
        changed.addAll(removed);
        Map<String, CredentialReferenceEntity> known = new HashMap<>();
        for (CredentialReferenceEntity credential : credentials.findByCredentialXrefIn(changed)) {
            if (Objects.equals(credential.getOrganizationId(), organizationId)) {
                known.put(credential.getCredentialXref(), credential);
            }
        }
        for (String xref : added) {
            CredentialReferenceEntity credential = known.get(xref);
            if (credential != null) {
                credentialAudit.deploymentTargetAdded(credential, domain, false);
            } else {
                record(AuditEvents.success(AuditEventType.DEPLOYMENT_TARGET_ADDED, AuditSubject.builder()
                        .organizationId(organizationId).resourceRef(xref).domain(domain).build()));
            }
        }
        for (String xref : removed) {
            credentialAudit.deploymentTargetRemoved(organizationId, xref, known.get(xref), domain);
        }
    }

    // ── Outcomes and CertPing's own work (the change's transaction) ─────

    /**
     * The agent issued {@code cert}.
     *
     * @param requestedBy the member whose request this answers, or null
     */
    public void issued(CertificateEntity cert, Integer requestedBy, String special) {
        Map<String, String> attributes = requested(requestedBy);
        put(attributes, "validTo", cert.getValidTo() == null ? null : cert.getValidTo().toString());
        put(attributes, "special", code(special));
        record(AuditEvents.success(AuditEventType.CERTIFICATE_ISSUED, certificate(cert).attributes(attributes).build()));
    }

    /** Issuing {@code cert} failed for {@code reason}. */
    public void issueFailed(CertificateEntity cert, AuditReason reason, Integer requestedBy) {
        record(AuditEvents.failure(AuditEventType.CERTIFICATE_ISSUED,
                certificate(cert).attributes(requested(requestedBy)).build(), reason));
    }

    /** The agent renewed the certificate: {@code renewed} replaces {@code previousXref}. */
    public void renewed(CertificateEntity renewed, String previousXref, Integer requestedBy) {
        Map<String, String> attributes = requested(requestedBy);
        put(attributes, "validTo", renewed.getValidTo() == null ? null : renewed.getValidTo().toString());
        put(attributes, "replaces", previousXref);
        record(AuditEvents.success(AuditEventType.CERTIFICATE_RENEWED, certificate(renewed).attributes(attributes)
                .build()));
    }

    /** Renewing {@code cert} failed for {@code reason}. */
    public void renewalFailed(CertificateEntity cert, AuditReason reason, Integer requestedBy) {
        record(AuditEvents.failure(AuditEventType.CERTIFICATE_RENEWED,
                certificate(cert).attributes(requested(requestedBy)).build(), reason));
    }

    /** The certificate authority revoked {@code cert}. */
    public void revoked(CertificateEntity cert, Integer requestedBy, String revocationReason) {
        Map<String, String> attributes = requested(requestedBy);
        put(attributes, "revocationReason", code(revocationReason));
        record(AuditEvents.success(AuditEventType.CERTIFICATE_REVOKED, certificate(cert).attributes(attributes)
                .build()));
    }

    /** Revoking {@code cert} failed for {@code reason}. */
    public void revocationFailed(CertificateEntity cert, AuditReason reason, Integer requestedBy) {
        record(AuditEvents.failure(AuditEventType.CERTIFICATE_REVOKED,
                certificate(cert).attributes(requested(requestedBy)).build(), reason));
    }

    /** CertPing started renewing {@code cert} on its own (the renewal job). */
    public void autoRenewalStarted(CertificateEntity cert, String special) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "special", code(special));
        record(AuditEvents.success(AuditEventType.CERTIFICATE_AUTO_RENEWAL_STARTED,
                certificate(cert).attributes(attributes).build()));
    }

    /**
     * Automatic renewal of {@code cert} was left off after it was issued or renewed, because {@code featureKeys}
     * (renewal, its certificate authority) are off.
     */
    public void autoRenewalSkipped(CertificateEntity cert, Collection<String> featureKeys, String flow) {
        record(AuditEvents.failure(AuditEventType.CERTIFICATE_AUTO_RENEWAL_SKIPPED,
                skip(certificate(cert), featureKeys, flow), AuditReason.of("FEATURE_OFF")));
    }

    /**
     * The renewal job skipped {@code cert} because {@code featureKey} (its certificate authority) is off. The job
     * re-checks the certificate every few minutes while it stays off, and every pod runs it (rows are shared out with
     * {@code SKIP LOCKED}, no leader), so the window is kept in the trail itself: the skip is written when the
     * certificate has none from the last day, read on the job's transaction, which holds the schedule's row lock, so
     * two pods cannot both find none. The rest are counted in {@code certping_audit_throttled_total}.
     */
    public void autoRenewalSkippedByJob(CertificateEntity cert, String featureKey) {
        Long organizationId = cert.getOrganizationId();
        if (organizationId != null && recorder.recordedSince(organizationId,
                AuditEventType.CERTIFICATE_AUTO_RENEWAL_SKIPPED, cert.getCertificateXref(),
                clock.instant().minus(SKIP_REPEAT_EVERY))) {
            Metrics.counter(THROTTLED_METRIC, "event", AuditEventType.CERTIFICATE_AUTO_RENEWAL_SKIPPED.key())
                    .increment();
            return;
        }
        autoRenewalSkipped(cert, List.of(featureKey), RENEWAL_JOB);
    }

    /**
     * The renewal job held {@code cert} because a CertPing DNS key its renewal needs expired at {@code expiredAt};
     * renewing the key resumes it.
     */
    public void autoRenewalHeldByExpiredDnsKey(CertificateEntity cert, Instant expiredAt) {
        AuditSubject subject = skip(certificate(cert), List.of(), RENEWAL_JOB);
        Map<String, String> attributes = new LinkedHashMap<>(subject.attributes());
        put(attributes, "dnsKeyExpiredOn", LocalDate.ofInstant(expiredAt, ZoneOffset.UTC).toString());
        record(AuditEvents.failure(AuditEventType.CERTIFICATE_AUTO_RENEWAL_SKIPPED,
                subject.toBuilder().attributes(attributes).build(), AuditReason.of(DNS_KEY_EXPIRED)));
    }

    /** {@code cert} reached its expiry date. */
    public void expired(CertificateEntity cert) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "validTo", cert.getValidTo() == null ? null : cert.getValidTo().toString());
        record(AuditEvents.success(AuditEventType.CERTIFICATE_EXPIRED, certificate(cert).attributes(attributes)
                .build()));
    }

    /** The agent deployed {@code cert} to a target of {@code targetType}. */
    public void deploymentSucceeded(CertificateEntity cert, String targetType, String flow, Integer requestedBy) {
        record(AuditEvents.success(AuditEventType.DEPLOYMENT_SUCCEEDED,
                deployment(cert, targetType, flow).attributes(deploymentAttributes(targetType, flow, requestedBy))
                        .build()));
    }

    /** Deploying {@code cert} to a target of {@code targetType} failed for {@code reason}. */
    public void deploymentFailed(CertificateEntity cert, String targetType, String flow, AuditReason reason,
                                 Integer requestedBy) {
        record(deploymentFailure(cert, targetType, flow, reason, requestedBy));
    }

    /** The automatic deploy of {@code cert} after it was issued or renewed was skipped: deployment is off. */
    public void autoDeploySkipped(CertificateEntity cert, String flow) {
        record(AuditEvents.failure(AuditEventType.DEPLOYMENT_AUTO_SKIPPED,
                skip(deployment(cert, null, flow), List.of(FeatureFlags.CERTIFICATE_DEPLOYMENT), flow),
                AuditReason.of("FEATURE_OFF")));
    }

    // ── Work with no transaction open (the bounded async writer) ────────

    /** CertPing dispatched the automatic deploy of {@code cert} to one target. Queued: no transaction is open. */
    public void autoDeployStarted(CertificateEntity cert, String targetType, String flow) {
        queue(AuditEventType.DEPLOYMENT_AUTO_STARTED, () -> AuditEvents.success(AuditEventType.DEPLOYMENT_AUTO_STARTED,
                deployment(cert, targetType, flow).attributes(deploymentAttributes(targetType, flow, null)).build()));
    }

    /**
     * Deploying {@code cert} to one target failed before the agent was reached: one target of an automatic deploy
     * (the others are still attempted), or a member's deploy refused after it was accepted. Queued: no transaction
     * is open.
     */
    public void deploymentDispatchFailed(CertificateEntity cert, String targetType, String flow, AuditReason reason) {
        queue(AuditEventType.DEPLOYMENT_FAILED, () -> deploymentFailure(cert, targetType, flow, reason, null));
    }

    // ── Labels ───────────────────────────────────────────────────────────

    /** "Let's Encrypt"; null for no CA. */
    public static String caLabel(CaProvider provider) {
        return provider == null ? null : CA_LABELS.get(provider);
    }

    /** "Azure Key Vault"; null for an unknown or missing target type (the sentence then names none). */
    public static String targetLabel(String targetType) {
        return targetType == null ? null : TARGET_LABELS.get(targetType);
    }

    /** "Certificate Deployment"; a key without a label reads as itself, anything else as nothing. */
    static String featureLabel(String featureKey) {
        if (featureKey == null) {
            return null;
        }
        String label = FEATURE_LABELS.get(featureKey);
        return label != null ? label : code(featureKey);
    }

    // ── Rows ─────────────────────────────────────────────────────────────

    /**
     * Writes a row in the caller's transaction. CertPing's own rows (an agent's result, a job: the actor of an open
     * {@link com.certmanagement.audit.AuditScope#system}) are isolated behind a savepoint
     * ({@link AuditRecorder#recordIsolated}): a row the database refuses goes to the async writer and never rolls back
     * the certificate's state. A member's request keeps {@link AuditRecorder#record}: a row that cannot be written
     * fails the request, which the member can retry.
     */
    private void record(AuditEventRow row) {
        if (row.actorType() == AuditActorType.SYSTEM) {
            recorder.recordIsolated(row);
        } else {
            recorder.record(row);
        }
    }

    /**
     * Queues a row for the async writer. Never throws: the callers are loops over deployment targets that must
     * attempt every target, so a row that cannot be built or queued is counted
     * ({@code certping_audit_failure_unrecorded_total}) and logged with its type only.
     */
    private void queue(AuditEventType type, Supplier<AuditEventRow> row) {
        try {
            AuditEventRow built = row.get();
            if (built.outcome() == AuditOutcome.FAILURE) {
                recorder.recordFailure(built);
            } else {
                recorder.recordAsync(built);
            }
        } catch (RuntimeException e) {
            Metrics.counter(UNRECORDED_METRIC, "event", type.key()).increment();
            log.warn("[CertificateAudit] could not queue {} ({})", type.key(), e.getClass().getSimpleName());
        }
    }

    private static AuditEventRow deploymentFailure(CertificateEntity cert, String targetType, String flow,
                                                   AuditReason reason, Integer requestedBy) {
        return AuditEvents.failure(AuditEventType.DEPLOYMENT_FAILED, deployment(cert, targetType, flow)
                .attributes(deploymentAttributes(targetType, flow, requestedBy)).build(), reason);
    }

    private static AuditSubject.AuditSubjectBuilder certificate(CertificateEntity cert) {
        return AuditSubject.builder()
                .organizationId(cert.getOrganizationId())
                .resourceId(cert.getId())
                .resourceRef(cert.getCertificateXref())
                .domain(cert.getDomain())
                .provider(caLabel(cert.getCaProvider()));
    }

    /** A deployment of {@code cert}: referenced by the certificate's xref, the target in words as its provider. */
    private static AuditSubject.AuditSubjectBuilder deployment(CertificateEntity cert, String targetType, String flow) {
        return AuditSubject.builder()
                .organizationId(cert.getOrganizationId())
                .resourceRef(cert.getCertificateXref())
                .domain(cert.getDomain())
                .provider(targetLabel(targetType));
    }

    private static Map<String, String> deploymentAttributes(String targetType, String flow, Integer requestedBy) {
        Map<String, String> attributes = requested(requestedBy);
        put(attributes, "targetType", code(targetType));
        put(attributes, "flow", code(flow));
        return attributes;
    }

    private static AuditSubject skip(AuditSubject.AuditSubjectBuilder subject, Collection<String> featureKeys,
                                     String flow) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "feature", featureKeys == null ? null : String.join(", ", featureKeys.stream()
                .map(CertificateAuditRecorder::featureLabel).filter(label -> label != null).toList()));
        put(attributes, "flow", code(flow));
        return subject.attributes(attributes).build();
    }

    private static Map<String, String> requested(Integer requestedBy) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "requestedBy", requestedBy == null ? null : requestedBy.toString());
        return attributes;
    }

    private static String sanCount(CertificateEntity cert) {
        String[] sans = cert.getSanDomains();
        return sans == null || sans.length == 0 ? null : Integer.toString(sans.length);
    }

    /** A value of our own vocabulary (a status, a mode, a target type); anything else is left out. */
    private static String code(String value) {
        return value != null && CODE.matcher(value).matches() ? value : null;
    }

    private static void put(Map<String, String> attributes, String name, String value) {
        if (value != null && !value.isBlank()) {
            attributes.put(name, value);
        }
    }
}
