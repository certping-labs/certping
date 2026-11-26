// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditEvents;
import com.certmanagement.audit.AuditReason;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditScope;
import com.certmanagement.audit.AuditSubject;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DiscoveryConfigEntity;
import com.certmanagement.entity.DiscoveryScanEntity;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Writes the discovery events of the audit trail: a scan started by a member, a saved configuration deleted, and
 * what became of a scan (finished, failed, stopped because the feature was turned off), which is CertPing's row
 * ({@link AuditScope#system}) since it learns it from the agent or decides it itself.
 *
 * <p>Successes, and the outcomes CertPing records with the scan's own state change, are written in that change's
 * transaction ({@link AuditRecorder#record}, which requires one): they commit and roll back with it. A scan
 * a member asked for that could not start is a failure row through the async writer
 * ({@link AuditRecorder#recordFailure}), one per configuration, so a run of every saved configuration records each
 * one that did not start. Each row here is its action's one customer row.
 *
 * <p>A scan is referenced by its request id, so its start and its outcome are found together; the configuration
 * is the resource id. The target is in words ({@link CredentialAuditRecorder#providerName}) and the credential is
 * named by its description; the agent's error detail is never stored, only its code.
 */
@Component
public class DiscoveryAuditRecorder {

    /** The job CertPing's discovery outcome rows act as. */
    public static final String JOB = "discovery";

    /** A scan the agent did not pick up before its command expired. */
    public static final AuditReason NOT_PICKED_UP = AuditReason.of("DISCOVERY_NOT_PICKED_UP");
    /** A scan the agent reported failed without a code of its own. */
    public static final AuditReason AGENT_FAILED = AuditReason.of("DISCOVERY_FAILED");
    /** A scan whose command could not be sent to the agent. */
    public static final AuditReason NOT_SENT = AuditReason.of("SERVICE_UNAVAILABLE");
    /** A saved configuration whose credential was deleted or turned off. */
    public static final AuditReason CREDENTIAL_NOT_ACTIVE = AuditReason.of("CREDENTIAL_NOT_ACTIVE");
    /** A saved configuration whose credential can no longer be used for the scan. */
    public static final AuditReason CREDENTIAL_INVALID = AuditReason.of("CREDENTIAL_DETAILS_INVALID");

    /** How a scan was started. */
    public enum Trigger {
        /** A scan of a target and credential the member chose. */
        NEW,
        /** One saved configuration run again. */
        SAVED,
        /** Every saved configuration run at once. */
        ALL_SAVED
    }

    private final AuditRecorder recorder;

    public DiscoveryAuditRecorder(AuditRecorder recorder) {
        this.recorder = recorder;
    }

    // ── The member acting ────────────────────────────────────────────────

    /** The scan {@code requestId} of {@code config} was recorded and will be sent to the agent. */
    public void scanStarted(DiscoveryConfigEntity config, CredentialReferenceEntity credential, String requestId,
                            Trigger trigger) {
        Map<String, String> attributes = targetType(config.getTargetType());
        attributes.put("trigger", trigger.name());
        recorder.record(AuditEvents.success(AuditEventType.DISCOVERY_SCAN_STARTED, config(config)
                .resourceRef(requestId)
                .name(credential == null ? null : credential.getDescription())
                .attributes(attributes)
                .build()));
    }

    /** A saved configuration was not run, for {@code reason}; one row per configuration, whatever else ran. */
    public void scanNotStarted(DiscoveryConfigEntity config, Trigger trigger, AuditReason reason) {
        Map<String, String> attributes = targetType(config.getTargetType());
        attributes.put("trigger", trigger.name());
        recorder.recordFailure(AuditEvents.failure(AuditEventType.DISCOVERY_SCAN_STARTED,
                config(config).attributes(attributes).build(), reason));
    }

    /** {@code config} was deleted. */
    public void configDeleted(DiscoveryConfigEntity config) {
        recorder.record(AuditEvents.success(AuditEventType.DISCOVERY_CONFIG_DELETED,
                config(config).attributes(targetType(config.getTargetType())).build()));
    }

    // ── CertPing acting, on what the agent reported ──────────────────────

    /** Every batch of {@code scan} arrived and its results were reconciled. */
    public void scanCompleted(DiscoveryScanEntity scan) {
        system(scan.getOrganizationId(), () -> AuditEvents.success(AuditEventType.DISCOVERY_SCAN_COMPLETED,
                scan(scan).count(scan.getReportedTotalCerts()).build()));
    }

    /** {@code scan} failed, for {@code reason}: the agent's code, or why CertPing gave it up. */
    public void scanFailed(DiscoveryScanEntity scan, AuditReason reason) {
        system(scan.getOrganizationId(), () -> AuditEvents.failure(AuditEventType.DISCOVERY_SCAN_FAILED,
                scan(scan).build(), reason));
    }

    /** The agent's failure code for a scan as the reason it is stored with; never the agent's detail text. */
    public static AuditReason agentReason(String errorCode) {
        return errorCode == null || errorCode.isBlank() ? AGENT_FAILED : AuditReason.fromAgent(errorCode, null);
    }

    /** {@code scan} was stopped because certificate discovery is turned off for its organization. */
    public void scanCancelled(DiscoveryScanEntity scan) {
        Map<String, String> attributes = targetType(scan.getTargetType());
        attributes.put("cause", "FEATURE_OFF");
        system(scan.getOrganizationId(), () -> AuditEvents.success(AuditEventType.DISCOVERY_SCANS_CANCELLED,
                scan(scan).count(1).attributes(attributes).build()));
    }

    /**
     * CertPing's row about the agent's work, in the transaction that stores the scan's state but isolated from it
     * ({@link AuditRecorder#recordIsolated}): a row that cannot be written never rolls back the agent's result.
     */
    private void system(Long organizationId, Supplier<AuditEventRow> row) {
        try (AuditScope scope = AuditScope.system(JOB, organizationId)) {
            recorder.recordIsolated(row.get());
        }
    }

    private static AuditSubject.AuditSubjectBuilder config(DiscoveryConfigEntity config) {
        return AuditSubject.builder()
                .organizationId(config.getOrganizationId())
                .resourceId(config.getId())
                .provider(CredentialAuditRecorder.providerName(config.getTargetType()));
    }

    private static AuditSubject.AuditSubjectBuilder scan(DiscoveryScanEntity scan) {
        return AuditSubject.builder()
                .organizationId(scan.getOrganizationId())
                .resourceRef(scan.getRequestId())
                .provider(CredentialAuditRecorder.providerName(scan.getTargetType()))
                .attributes(targetType(scan.getTargetType()));
    }

    private static Map<String, String> targetType(String targetType) {
        Map<String, String> attributes = new LinkedHashMap<>();
        String code = CredentialAuditRecorder.providerName(targetType) == null ? null : targetType.trim();
        if (code != null && code.matches("^[A-Z][A-Z0-9_]{0,39}$")) {
            attributes.put("targetType", code);
        }
        return attributes;
    }
}
