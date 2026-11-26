// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import com.certmanagement.iot.certificate.IotDeviceCertificate;
import com.certmanagement.iot.certificate.IotDeviceCertificateRepository;
import com.certmanagement.iot.config.IotRevocationProperties;
import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.service.IotDeviceEventService;
import com.certmanagement.service.OrgTypeResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

/** Claims durable work in short batches; queue sends happen after this transaction returns. */
@Slf4j
@Service
@RequiredArgsConstructor
public class IotRevocationDispatchStore {
    private final IotCertificateRevocationRepository revocationRepository;
    private final IotDeviceCertificateRepository certificateRepository;
    private final IotDeviceEventService eventService;
    private final OrgTypeResolver orgTypeResolver;
    private final IotRevocationProperties properties;
    private final Clock clock;

    @Transactional
    public ClaimBatch claimBatch() {
        OffsetDateTime now = OffsetDateTime.now(clock);
        List<IotCertificateRevocation> operations = revocationRepository.claimDue(
                now, properties.getClaimBatchSize());
        if (operations.isEmpty()) return new ClaimBatch(false, List.of());

        Map<Long, IotDeviceCertificate> certificates = certificateRepository.lockAllByIdIn(
                        operations.stream().map(IotCertificateRevocation::getCertificateId)
                                .filter(Objects::nonNull).toList())
                .stream().collect(Collectors.toMap(IotDeviceCertificate::getId, Function.identity()));
        Map<Long, String> orgTypes = orgTypeResolver.resolveAll(operations.stream()
                .map(IotCertificateRevocation::getOrganizationId).collect(Collectors.toSet()));
        List<Claim> claims = new ArrayList<>(operations.size());
        for (IotCertificateRevocation operation : operations) {
            Claim claim = claim(operation, certificates.get(operation.getCertificateId()),
                    orgTypes.get(operation.getOrganizationId()), now);
            if (claim != null) claims.add(claim);
        }
        revocationRepository.saveAll(operations);
        return new ClaimBatch(true, List.copyOf(claims));
    }

    private Claim claim(IotCertificateRevocation operation,
                        IotDeviceCertificate certificate,
                        String orgType,
                        OffsetDateTime now) {
        if (certificate == null
                || !operation.getOrganizationId().equals(certificate.getOrganizationId())) {
            fail(operation, null, "CERTIFICATE_NOT_FOUND",
                    "The certificate no longer exists", now, false);
            return null;
        }
        if ("REVOKED".equals(certificate.getStatus())) {
            operation.setStatus(IotCertificateRevocationStatus.CONFIRMED);
            operation.setCompletedAt(now);
            operation.setUpdatedAt(now);
            return null;
        }
        if (attemptBudgetExhausted(operation, now)) {
            boolean outcomeUnknown = operation.getStatus() == IotCertificateRevocationStatus.DISPATCHED;
            fail(operation, certificate, "REVOCATION_RETRY_EXHAUSTED",
                    "Certificate revocation did not complete within the retry budget",
                    now, outcomeUnknown);
            return null;
        }

        int attempt = operation.getAttemptCount() + 1;
        String requestId = requestId(operation, attempt);
        operation.setAttemptCount(attempt);
        operation.setDispatchedAt(null);
        operation.setNextAttemptAt(now.plus(properties.getClaimLease()));
        operation.setUpdatedAt(now);
        return new Claim(operation.getId(), attempt,
                IotCertificateRevocationCommand.builder()
                        .messageVersion(1).requestId(requestId)
                        .correlationId(operation.getOperationXref())
                        .organizationId(operation.getOrganizationId().toString())
                        .orgType(orgType).operationXref(operation.getOperationXref())
                        .dispatchAttempt(attempt)
                        .certificateXref(certificate.getCertificateXref())
                        .caProvider(certificate.getCaProvider())
                        .issuerDn(certificate.getIssuerDn())
                        .serialNumber(certificate.getSerialNumber())
                        .reason(operation.getReason().name())
                        .requestedAt(operation.getCreatedAt().toString()).build());
    }

    @Transactional
    public void completeBatch(Collection<PublishOutcome> outcomes) {
        if (outcomes == null || outcomes.isEmpty()) return;
        OffsetDateTime now = OffsetDateTime.now(clock);
        Map<Long, PublishOutcome> byId = outcomes.stream().collect(Collectors.toMap(
                PublishOutcome::operationId, Function.identity(), (first, ignored) -> first));
        List<IotCertificateRevocation> operations =
                revocationRepository.findAllByIdIn(byId.keySet());
        Map<Long, IotDeviceCertificate> certificates = certificateRepository.lockAllByIdIn(
                        operations.stream().map(IotCertificateRevocation::getCertificateId)
                                .filter(Objects::nonNull).toList())
                .stream().collect(Collectors.toMap(IotDeviceCertificate::getId, Function.identity()));

        List<IotDeviceCertificate> changedCertificates = new ArrayList<>();
        for (IotCertificateRevocation operation : operations) {
            PublishOutcome outcome = byId.get(operation.getId());
            if (outcome == null || operation.getAttemptCount() != outcome.attempt()
                    || terminal(operation.getStatus())
                    || (outcome.published() && operation.getDispatchedAt() != null)) continue;
            if (outcome.published()) {
                IotDeviceCertificate certificate = certificates.get(operation.getCertificateId());
                markDispatched(operation, certificate, now);
                if (certificate != null) changedCertificates.add(certificate);
            } else {
                operation.setStatus(IotCertificateRevocationStatus.PENDING);
                operation.setErrorCode("QUEUE_PUBLISH_FAILED");
                operation.setErrorMessage(truncate(outcome.errorMessage(), 500));
                operation.setNextAttemptAt(now.plusMinutes(
                        Math.min(30, 1L << Math.min(outcome.attempt() - 1, 4))));
                operation.setUpdatedAt(now);
            }
        }
        revocationRepository.saveAll(operations);
        certificateRepository.saveAll(changedCertificates);
    }

    private void markDispatched(IotCertificateRevocation operation,
                                IotDeviceCertificate certificate,
                                OffsetDateTime now) {
        operation.setStatus(IotCertificateRevocationStatus.DISPATCHED);
        operation.setDispatchedAt(now);
        operation.setNextAttemptAt(now.plus(properties.getResponseTimeout()));
        operation.setErrorCode(null);
        operation.setErrorMessage(null);
        operation.setUpdatedAt(now);
        if (certificate == null) return;
        if (!"REVOKED".equals(certificate.getStatus())) {
            certificate.setStatus("REVOCATION_DISPATCHED");
            certificate.setUpdatedAt(now);
        }
        eventService.recordCertificateUnderWorkflowLock(certificate,
                DeviceEventType.CERTIFICATE_REVOCATION_DISPATCHED,
                "DISPATCHED", "Certificate revocation sent to the agent",
                ActorSource.PLATFORM, null,
                Map.of("operationXref", operation.getOperationXref(),
                        "caProvider", certificate.getCaProvider(),
                        "attempt", operation.getAttemptCount()),
                operation.getOperationXref(), operation.getOperationXref()
                        + ":dispatched:" + requestId(operation, operation.getAttemptCount()), now);
        log.info("IoT revocation dispatched: operation={} certificate={} caProvider={} attempt={}",
                operation.getOperationXref(), certificate.getCertificateXref(),
                certificate.getCaProvider(), operation.getAttemptCount());
    }

    private boolean attemptBudgetExhausted(IotCertificateRevocation operation, OffsetDateTime now) {
        return operation.getAttemptCount() >= properties.getMaxDispatchAttempts()
                || operation.getCreatedAt().plus(properties.getMaxOperationAge()).isBefore(now);
    }

    private void fail(IotCertificateRevocation operation,
                      IotDeviceCertificate certificate,
                      String code,
                      String message,
                      OffsetDateTime now,
                      boolean outcomeUnknown) {
        operation.setStatus(outcomeUnknown
                ? IotCertificateRevocationStatus.OUTCOME_UNKNOWN
                : IotCertificateRevocationStatus.FAILED);
        operation.setErrorCode(code);
        operation.setErrorMessage(message);
        operation.setCompletedAt(now);
        operation.setUpdatedAt(now);
        if (certificate != null) {
            if (!"REVOKED".equals(certificate.getStatus())) {
                certificate.setStatus(outcomeUnknown
                        ? "REVOCATION_OUTCOME_UNKNOWN" : "REVOCATION_FAILED");
                certificate.setUpdatedAt(now);
            }
            certificateRepository.save(certificate);
            eventService.recordCertificateUnderWorkflowLock(certificate,
                    outcomeUnknown ? DeviceEventType.CERTIFICATE_REVOCATION_OUTCOME_UNKNOWN
                            : DeviceEventType.CERTIFICATE_REVOCATION_FAILED,
                    operation.getStatus().name(), message, ActorSource.PLATFORM, null,
                    Map.of("operationXref", operation.getOperationXref(), "errorCode", code),
                    operation.getOperationXref(), operation.getOperationXref()
                            + ":" + operation.getStatus() + eventCycle(operation), now);
        }
        // errorMessage stays out: it is agent-supplied text and lives in the event row instead.
        log.warn("IoT revocation ended without confirmation: operation={} certificate={} status={} "
                        + "errorCode={} attempt={}",
                operation.getOperationXref(),
                certificate == null ? null : certificate.getCertificateXref(),
                operation.getStatus(), code, operation.getAttemptCount());
    }

    private static boolean terminal(IotCertificateRevocationStatus status) {
        return status == IotCertificateRevocationStatus.CONFIRMED
                || status == IotCertificateRevocationStatus.FAILED
                || status == IotCertificateRevocationStatus.OUTCOME_UNKNOWN;
    }

    private static String requestId(IotCertificateRevocation operation, int attempt) {
        if (operation.getSource() == IotCertificateRevocationSource.INTUNE) {
            return operation.getOperationXref() + ":" + operation.getIntuneTransactionId()
                    + ":" + attempt;
        }
        return operation.getOperationXref() + ":" + attempt;
    }

    private static String eventCycle(IotCertificateRevocation operation) {
        return operation.getSource() == IotCertificateRevocationSource.INTUNE
                ? ":" + operation.getIntuneTransactionId() : "";
    }

    private static String truncate(String value, int length) {
        if (value == null) return null;
        return value.length() <= length ? value : value.substring(0, length);
    }

    public record ClaimBatch(boolean foundRows, List<Claim> claims) {}
    public record Claim(Long operationId, int attempt,
                        IotCertificateRevocationCommand command) {}
    public record PublishOutcome(Long operationId, int attempt,
                                 boolean published, String errorMessage) {
        public static PublishOutcome published(Claim claim) {
            return new PublishOutcome(claim.operationId(), claim.attempt(), true, null);
        }
        public static PublishOutcome failed(Claim claim, String message) {
            return new PublishOutcome(claim.operationId(), claim.attempt(), false, message);
        }
    }
}
