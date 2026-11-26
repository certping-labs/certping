// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import com.certmanagement.iot.certificate.IotDeviceCertificate;
import com.certmanagement.iot.certificate.IotDeviceCertificateRepository;
import com.certmanagement.iot.config.IotRevocationProperties;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.service.IotDeviceEventService;
import com.certmanagement.messaging.model.AgentErrorMessage;
import com.certmanagement.service.OrgTypeResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class IotIntuneRevocationWorkflow {
    private static final Duration CLAIM_LEASE = Duration.ofMinutes(5);
    private static final Duration RESPONSE_TIMEOUT = Duration.ofMinutes(15);
    private static final Duration INTUNE_COOLDOWN = Duration.ofMinutes(65);
    private static final List<IotCertificateRevocationStatus> ACTIVE = List.of(
            IotCertificateRevocationStatus.PENDING,
            IotCertificateRevocationStatus.DISPATCHED);

    private final IotIntuneRevocationPollStateRepository stateRepository;
    private final IotCertificateRevocationRepository revocationRepository;
    private final IotDeviceCertificateRepository certificateRepository;
    private final IotDeviceSourceRepository sourceRepository;
    private final IotDeviceEventService eventService;
    private final OrgTypeResolver orgTypeResolver;
    private final IotRevocationProperties properties;
    private final Clock clock;

    @Transactional
    public Optional<Work> claimNext() {
        OffsetDateTime now = OffsetDateTime.now(clock);
        Optional<IotIntuneRevocationPollState> candidate = stateRepository.claimNextDue(now);
        if (candidate.isEmpty()) return Optional.empty();
        IotIntuneRevocationPollState state = candidate.get();
        IotDeviceSource source = sourceRepository.findById(state.getDeviceSourceId()).orElse(null);
        if (source == null) {
            stateRepository.delete(state);
            return Optional.of(Work.skippedWork());
        }

        if (state.getStatus() == IotIntuneRevocationPollStatus.PROCESSING) {
            long active = revocationRepository
                    .countByDeviceSourceIdAndIntuneTransactionIdAndStatusIn(
                            state.getDeviceSourceId(), state.getTransactionId(), ACTIVE);
            boolean timedOut = state.getRequestedAt() != null
                    && !state.getRequestedAt().plus(properties.getIntuneTransactionTimeout())
                            .isAfter(now);
            if (active > 0 && !timedOut) {
                state.setNextAttemptAt(now.plus(properties.getIntuneProcessingPollInterval()));
                state.setUpdatedAt(now);
                stateRepository.save(state);
                return Optional.of(Work.skippedWork());
            }
            state.setStatus(IotIntuneRevocationPollStatus.PENDING_UPLOAD);
        }

        if (state.getStatus() == IotIntuneRevocationPollStatus.IDLE
                || state.getStatus() == IotIntuneRevocationPollStatus.FAILED) {
            state.setTransactionId(UUID.randomUUID().toString());
            state.setStatus(IotIntuneRevocationPollStatus.PENDING_POLL);
            state.setAttemptCount(0);
            state.setRequestedAt(now);
            state.setDownloadedAt(null);
            state.setUploadedAt(null);
            state.setLastErrorCode(null);
            state.setLastErrorMessage(null);
        }
        int attempt = state.getAttemptCount() + 1;
        state.setAttemptCount(attempt);
        state.setNextAttemptAt(now.plus(CLAIM_LEASE));
        state.setUpdatedAt(now);
        stateRepository.save(state);

        if (state.getStatus() == IotIntuneRevocationPollStatus.PENDING_UPLOAD
                || state.getStatus() == IotIntuneRevocationPollStatus.UPLOAD_DISPATCHED) {
            List<IotIntuneRevocationUploadCommand.Result> results = revocationRepository
                    .findAllByDeviceSourceIdAndIntuneTransactionIdOrderById(
                            state.getDeviceSourceId(), state.getTransactionId())
                    .stream().map(operation -> new IotIntuneRevocationUploadCommand.Result(
                            operation.getRequestContext(),
                            operation.getStatus() == IotCertificateRevocationStatus.CONFIRMED,
                            operation.getStatus() == IotCertificateRevocationStatus.CONFIRMED
                                    ? "0" : intuneErrorCode(operation),
                            operation.getStatus() == IotCertificateRevocationStatus.CONFIRMED
                                    ? null : value(operation.getErrorMessage(),
                                            "Certificate revocation was not confirmed")))
                    .toList();
            if (results.isEmpty()) {
                resetToIdle(state, now);
                return Optional.of(Work.skippedWork());
            }
            return Optional.of(Work.upload(state.getId(), attempt,
                    IotIntuneRevocationUploadCommand.builder()
                            .messageVersion(1).requestId(state.getTransactionId()
                                    + ":upload:" + attempt)
                            .correlationId(state.getTransactionId())
                            .organizationId(state.getOrganizationId().toString())
                            .orgType(orgTypeResolver.resolve(state.getOrganizationId()))
                            .sourceXref(source.getSourceXref())
                            .connectionProfileRef(source.getConnectionProfileRef())
                            .transactionId(state.getTransactionId()).dispatchAttempt(attempt)
                            .results(results).build()));
        }
        return Optional.of(Work.poll(state.getId(), attempt,
                IotIntuneRevocationPollCommand.builder()
                        .messageVersion(1).requestId(state.getTransactionId()
                                + ":poll:" + attempt)
                        .correlationId(state.getTransactionId())
                        .organizationId(state.getOrganizationId().toString())
                        .orgType(orgTypeResolver.resolve(state.getOrganizationId()))
                        .sourceXref(source.getSourceXref())
                        .connectionProfileRef(source.getConnectionProfileRef())
                        .transactionId(state.getTransactionId()).dispatchAttempt(attempt)
                        .maxRequests(100).build()));
    }

    @Transactional
    public void markDispatched(Long stateId, int attempt, WorkType type) {
        OffsetDateTime now = OffsetDateTime.now(clock);
        IotIntuneRevocationPollState state = stateRepository.findByIdForUpdate(stateId).orElse(null);
        if (state == null || state.getAttemptCount() != attempt
                || !awaitingDispatch(state.getStatus(), type)) return;
        state.setStatus(type == WorkType.POLL
                ? IotIntuneRevocationPollStatus.POLL_DISPATCHED
                : IotIntuneRevocationPollStatus.UPLOAD_DISPATCHED);
        state.setDispatchedAt(now);
        state.setNextAttemptAt(now.plus(RESPONSE_TIMEOUT));
        state.setLastErrorCode(null);
        state.setLastErrorMessage(null);
        state.setUpdatedAt(now);
        stateRepository.save(state);
    }

    @Transactional
    public void markPublishFailed(Long stateId, int attempt, String message) {
        IotIntuneRevocationPollState state = stateRepository.findByIdForUpdate(stateId).orElse(null);
        if (state == null || state.getAttemptCount() != attempt) return;
        OffsetDateTime now = OffsetDateTime.now(clock);
        state.setLastErrorCode("QUEUE_PUBLISH_FAILED");
        state.setLastErrorMessage(truncate(message, 500));
        state.setNextAttemptAt(now.plusMinutes(Math.min(30, 1L << Math.min(attempt - 1, 4))));
        state.setUpdatedAt(now);
        stateRepository.save(state);
    }

    @Transactional
    public void handlePollResult(IotIntuneRevocationPollResult result) {
        IotDeviceSource source = requireSource(result.getOrganizationId(), result.getSourceXref());
        if (source == null) return;
        IotIntuneRevocationPollState state = stateRepository.findByDeviceSourceIdForUpdate(source.getId())
                .orElse(null);
        if (!matches(state, result.getTransactionId())
                || !awaitingPollResult(state.getStatus())
                || !validAttempt(result.getRequestId(), result.getDispatchAttempt(), state,
                        "poll", "SUCCESS".equalsIgnoreCase(result.getOutcome()))) return;
        OffsetDateTime now = OffsetDateTime.now(clock);
        if (!"SUCCESS".equalsIgnoreCase(result.getOutcome())) {
            state.setStatus(IotIntuneRevocationPollStatus.FAILED);
            state.setLastErrorCode(truncate(result.getErrorCode(), 100));
            state.setLastErrorMessage(truncate(result.getErrorMessage(), 500));
            state.setNextAttemptAt(now.plus(INTUNE_COOLDOWN));
            state.setUpdatedAt(now);
            stateRepository.save(state);
            return;
        }
        List<IotIntuneRevocationPollResult.Request> requests = result.getRequests() == null
                ? List.of() : result.getRequests().stream().limit(100).toList();
        state.setDownloadedAt(now);
        if (requests.isEmpty()) {
            if (Boolean.TRUE.equals(result.getRedelivered())
                    || result.getDispatchAttempt() > 1) {
                state.setStatus(IotIntuneRevocationPollStatus.FAILED);
                state.setLastErrorCode("INTUNE_POLL_REDELIVERED_EMPTY");
                state.setLastErrorMessage(
                        "A retried poll returned no requests; retrying after the Intune cooldown");
                state.setNextAttemptAt(now.plus(INTUNE_COOLDOWN));
                state.setUpdatedAt(now);
                stateRepository.save(state);
                return;
            }
            resetToIdle(state, now);
            return;
        }
        for (IotIntuneRevocationPollResult.Request request : requests) {
            acceptRequest(state, request, now);
        }
        // requestContext is an opaque Intune blob that can carry device or user identifiers, so
        // only the count travels here; per-request detail is in the operation rows.
        log.info("Intune revocation requests downloaded: source={} txn={} requests={}",
                result.getSourceXref(), state.getTransactionId(), requests.size());
        state.setStatus(IotIntuneRevocationPollStatus.PROCESSING);
        state.setNextAttemptAt(now);
        state.setUpdatedAt(now);
        stateRepository.save(state);
    }

    @Transactional
    public void handleUploadResult(IotIntuneRevocationUploadResult result) {
        IotDeviceSource source = requireSource(result.getOrganizationId(), result.getSourceXref());
        if (source == null) return;
        IotIntuneRevocationPollState state = stateRepository.findByDeviceSourceIdForUpdate(source.getId())
                .orElse(null);
        if (!matches(state, result.getTransactionId())
                || !awaitingUploadResult(state.getStatus())
                || !validAttempt(result.getRequestId(), result.getDispatchAttempt(), state,
                        "upload", "SUCCESS".equalsIgnoreCase(result.getOutcome()))) return;
        OffsetDateTime now = OffsetDateTime.now(clock);
        if (!"SUCCESS".equalsIgnoreCase(result.getOutcome())) {
            state.setStatus(IotIntuneRevocationPollStatus.PENDING_UPLOAD);
            state.setLastErrorCode(truncate(result.getErrorCode(), 100));
            state.setLastErrorMessage(truncate(result.getErrorMessage(), 500));
            state.setNextAttemptAt(now.plusMinutes(5));
            state.setUpdatedAt(now);
            stateRepository.save(state);
            log.warn("Intune revocation result upload failed, will retry: source={} txn={} "
                            + "errorCode={}",
                    result.getSourceXref(), state.getTransactionId(), result.getErrorCode());
            return;
        }
        List<IotCertificateRevocation> operations = revocationRepository
                .findAllByDeviceSourceIdAndIntuneTransactionIdOrderById(
                        source.getId(), state.getTransactionId());
        Map<Long, IotDeviceCertificate> certificates = certificateRepository.findAllById(
                        operations.stream().map(IotCertificateRevocation::getCertificateId)
                                .filter(java.util.Objects::nonNull).toList())
                .stream().collect(java.util.stream.Collectors.toMap(
                        IotDeviceCertificate::getId, certificate -> certificate));
        for (IotCertificateRevocation operation : operations) {
            IotDeviceCertificate certificate = certificates.get(operation.getCertificateId());
            if (certificate == null) continue;
            eventService.recordCertificateUnderWorkflowLock(certificate,
                    DeviceEventType.INTUNE_REVOCATION_RESULT_UPLOADED,
                    "UPLOADED", "Revocation result uploaded to Intune",
                    ActorSource.PLATFORM, null,
                    Map.of("operationXref", operation.getOperationXref(),
                            "succeeded", operation.getStatus()
                                    == IotCertificateRevocationStatus.CONFIRMED),
                    result.getCorrelationId(), operation.getOperationXref()
                            + ":intune-uploaded:" + result.getTransactionId(), now);
        }
        log.info("Intune revocation results uploaded: source={} txn={} operations={}",
                result.getSourceXref(), state.getTransactionId(), operations.size());
        state.setUploadedAt(now);
        resetToIdle(state, now);
    }

    @Transactional
    public void handleAgentError(AgentErrorMessage error, boolean upload) {
        IotDeviceSource source = requireSource(error.getOrganizationId(), error.getSourceXref());
        if (source == null) return;
        IotIntuneRevocationPollState state = stateRepository.findByDeviceSourceIdForUpdate(source.getId())
                .orElse(null);
        String transactionId = error.getCorrelationId();
        Integer attempt = requestAttempt(error.getRequestId(), upload ? "upload" : "poll");
        IotIntuneRevocationPollStatus status = state == null ? null : state.getStatus();
        boolean awaitingResult = upload ? awaitingUploadResult(status) : awaitingPollResult(status);
        if (!matches(state, transactionId) || !awaitingResult || attempt == null
                || attempt != state.getAttemptCount()) return;
        OffsetDateTime now = OffsetDateTime.now(clock);
        state.setStatus(upload ? IotIntuneRevocationPollStatus.PENDING_UPLOAD
                : IotIntuneRevocationPollStatus.FAILED);
        state.setLastErrorCode(truncate(error.getErrorCode(), 100));
        state.setLastErrorMessage(truncate(error.getErrorDetail(), 500));
        state.setNextAttemptAt(now.plus(upload ? Duration.ofMinutes(5) : INTUNE_COOLDOWN));
        state.setUpdatedAt(now);
        stateRepository.save(state);
    }

    private void acceptRequest(IotIntuneRevocationPollState state,
                               IotIntuneRevocationPollResult.Request request,
                               OffsetDateTime now) {
        if (request == null) {
            return;
        }
        String context = requiredOpaque(request.getRequestContext(), 1000);
        if (context == null) {
            return;
        }
        String contextHash = sha256(context);
        IotCertificateRevocation duplicate = revocationRepository
                .findByDeviceSourceIdAndRequestContextHash(
                        state.getDeviceSourceId(), contextHash).orElse(null);
        if (duplicate != null) {
            if (!context.equals(duplicate.getRequestContext())) {
                throw new IllegalStateException("SHA-256 collision for Intune request context");
            }
            IotDeviceCertificate certificate = duplicate.getCertificateId() == null ? null
                    : certificateRepository.findById(duplicate.getCertificateId()).orElse(null);
            duplicate.setIntuneTransactionId(state.getTransactionId());
            if (duplicate.getStatus() == IotCertificateRevocationStatus.OUTCOME_UNKNOWN) {
                boolean alreadyRevoked = certificate != null
                        && "REVOKED".equals(certificate.getStatus());
                duplicate.setStatus(alreadyRevoked ? IotCertificateRevocationStatus.CONFIRMED
                        : IotCertificateRevocationStatus.PENDING);
                duplicate.setAttemptCount(0);
                duplicate.setDispatchedAt(null);
                duplicate.setCompletedAt(alreadyRevoked ? now : null);
                duplicate.setNextAttemptAt(now);
            }
            duplicate.setUpdatedAt(now);
            revocationRepository.save(duplicate);
            if (certificate != null) {
                eventService.recordCertificate(certificate,
                        DeviceEventType.INTUNE_REVOCATION_REQUEST_DOWNLOADED,
                        duplicate.getStatus().name(), "Intune re-offered certificate revocation",
                        ActorSource.PLATFORM, null,
                        Map.of("operationXref", duplicate.getOperationXref(),
                                "reoffered", true,
                                "caProvider", value(certificate.getCaProvider(), "UNKNOWN")),
                        state.getTransactionId(), duplicate.getOperationXref()
                                + ":intune-downloaded:" + state.getTransactionId(), now);
            }
            return;
        }
        String issuer = required(request.getIssuerName(), 2000);
        String serial = required(request.getSerialNumber(), 160);
        List<IotDeviceCertificate> matches = issuer == null || serial == null ? List.of()
                : certificateRepository.findAllByOrganizationIdAndIssuerDnAndSerialNumber(
                        state.getOrganizationId(), issuer, serial);
        IotDeviceCertificate certificate = matches.size() == 1 ? matches.getFirst() : null;
        boolean supportedProvider = certificate != null
                && ("EJBCA".equalsIgnoreCase(certificate.getCaProvider())
                    || "SMALLSTEP".equalsIgnoreCase(certificate.getCaProvider()));
        boolean supported = supportedProvider
                && !Boolean.TRUE.equals(certificate.getCertificateAuthority());
        boolean alreadyRevoked = supported && "REVOKED".equals(certificate.getStatus());
        IotCertificateRevocation operation = IotCertificateRevocation.builder()
                .operationXref("iotrevoke_" + UUID.randomUUID())
                .organizationId(state.getOrganizationId())
                .certificateId(certificate == null ? null : certificate.getId())
                .deviceSourceId(state.getDeviceSourceId())
                .source(IotCertificateRevocationSource.INTUNE)
                .intuneTransactionId(state.getTransactionId())
                .requestContext(context)
                .requestContextHash(contextHash)
                .reason(IotRevocationReason.CESSATION_OF_OPERATION)
                .status(alreadyRevoked ? IotCertificateRevocationStatus.CONFIRMED
                        : supported ? IotCertificateRevocationStatus.PENDING
                        : IotCertificateRevocationStatus.FAILED)
                .attemptCount(0).nextAttemptAt(now)
                .errorCode(supported ? null : certificate == null
                        ? matches.size() > 1 ? "CERTIFICATE_MATCH_AMBIGUOUS" : "CERTIFICATE_NOT_FOUND"
                        : Boolean.TRUE.equals(certificate.getCertificateAuthority())
                            ? "IOT_CA_CERTIFICATE_NOT_REVOCABLE"
                            : "IOT_CA_REVOCATION_UNSUPPORTED")
                .errorMessage(supported ? null : certificate == null
                        ? matches.size() > 1
                            ? "More than one IoT certificate matched the Intune revocation request"
                            : "No issued IoT certificate matched the Intune revocation request"
                        : Boolean.TRUE.equals(certificate.getCertificateAuthority())
                            ? "Intune cannot revoke a certificate authority certificate"
                            : "The certificate authority provider does not support IoT revocation")
                .completedAt(alreadyRevoked || !supported ? now : null)
                .createdAt(now).updatedAt(now).build();
        revocationRepository.save(operation);
        if (certificate != null) {
            if (supported && !alreadyRevoked) {
                certificate.setStatus("REVOCATION_PENDING");
                certificate.setUpdatedAt(now);
                certificateRepository.save(certificate);
            }
            eventService.recordCertificateUnderWorkflowLock(certificate,
                    DeviceEventType.INTUNE_REVOCATION_REQUEST_DOWNLOADED,
                    alreadyRevoked ? "CONFIRMED" : supported ? "PENDING" : "FAILED",
                    "Intune requested certificate revocation", ActorSource.PLATFORM, null,
                    Map.of("operationXref", operation.getOperationXref(),
                            "matched", true, "supported", supported),
                    state.getTransactionId(), operation.getOperationXref()
                            + ":intune-downloaded:" + state.getTransactionId(), now);
        }
    }

    private IotDeviceSource requireSource(String organizationIdValue, String sourceXref) {
        try {
            return sourceRepository.findBySourceXrefAndOrganizationId(
                    sourceXref, Long.valueOf(organizationIdValue)).orElse(null);
        } catch (NumberFormatException exception) {
            return null;
        }
    }

    private void resetToIdle(IotIntuneRevocationPollState state, OffsetDateTime now) {
        state.setStatus(IotIntuneRevocationPollStatus.IDLE);
        state.setTransactionId(null);
        state.setAttemptCount(0);
        state.setNextAttemptAt(now.plus(INTUNE_COOLDOWN));
        state.setLastErrorCode(null);
        state.setLastErrorMessage(null);
        state.setUpdatedAt(now);
        stateRepository.save(state);
    }

    private static boolean matches(IotIntuneRevocationPollState state, String transactionId) {
        return state != null && state.getTransactionId() != null
                && state.getTransactionId().equals(transactionId);
    }

    private static boolean awaitingDispatch(IotIntuneRevocationPollStatus status, WorkType type) {
        return type == WorkType.POLL
                ? status == IotIntuneRevocationPollStatus.PENDING_POLL
                    || status == IotIntuneRevocationPollStatus.POLL_DISPATCHED
                : status == IotIntuneRevocationPollStatus.PENDING_UPLOAD
                    || status == IotIntuneRevocationPollStatus.UPLOAD_DISPATCHED;
    }

    private static boolean awaitingPollResult(IotIntuneRevocationPollStatus status) {
        return status == IotIntuneRevocationPollStatus.PENDING_POLL
                || status == IotIntuneRevocationPollStatus.POLL_DISPATCHED;
    }

    private static boolean awaitingUploadResult(IotIntuneRevocationPollStatus status) {
        return status == IotIntuneRevocationPollStatus.PENDING_UPLOAD
                || status == IotIntuneRevocationPollStatus.UPLOAD_DISPATCHED;
    }

    private static boolean validAttempt(String requestId, Integer attempt,
                                        IotIntuneRevocationPollState state,
                                        String operation, boolean success) {
        if (attempt == null || attempt < 1 || attempt > state.getAttemptCount()) return false;
        if (!(state.getTransactionId() + ":" + operation + ":" + attempt).equals(requestId)) {
            return false;
        }
        return success || attempt.equals(state.getAttemptCount());
    }

    private static Integer requestAttempt(String requestId, String operation) {
        if (requestId == null) return null;
        int separator = requestId.lastIndexOf(':');
        if (separator < 1 || !requestId.substring(0, separator)
                .endsWith(":" + operation)) return null;
        try {
            return Integer.valueOf(requestId.substring(separator + 1));
        } catch (NumberFormatException exception) {
            return null;
        }
    }

    private static String intuneErrorCode(IotCertificateRevocation operation) {
        String code = value(operation.getErrorCode(), "REVOCATION_FAILED");
        return switch (code) {
            case "CERTIFICATE_NOT_FOUND" -> "4004";
            case "CERTIFICATE_MATCH_AMBIGUOUS" -> "4005";
            case "IOT_CA_REVOCATION_UNSUPPORTED" -> "4006";
            case "IOT_CA_CERTIFICATE_NOT_REVOCABLE" -> "4002";
            case "IOT_REVOCATION_COMMAND_INVALID", "INTUNE_REVOCATION_REQUEST_INVALID" -> "4002";
            case "PLATFORM_NOT_CONFIGURED", "INTUNE_REVOCATION_REJECTED" -> "4103";
            case "INTUNE_REVOCATION_THROTTLED" -> "4102";
            case "INTUNE_REVOCATION_UNAVAILABLE", "SEND_FAILED" -> "4101";
            case "RETRY_GIVE_UP", "REVOCATION_RETRY_EXHAUSTED" -> "4100";
            default -> operation.getStatus() == IotCertificateRevocationStatus.OUTCOME_UNKNOWN
                    || ACTIVE.contains(operation.getStatus()) ? "4100" : "4000";
        };
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static String required(String value, int max) {
        if (value == null || value.isBlank() || value.trim().length() > max) return null;
        return value.trim();
    }

    private static String requiredOpaque(String value, int max) {
        if (value == null || value.isBlank() || value.length() > max) return null;
        return value;
    }

    private static String truncate(String value, int max) {
        if (value == null) return null;
        return value.length() <= max ? value : value.substring(0, max);
    }

    private static String value(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    public enum WorkType { POLL, UPLOAD, SKIP }

    public record Work(WorkType type, Long stateId, int attempt,
                       IotIntuneRevocationPollCommand pollCommand,
                       IotIntuneRevocationUploadCommand uploadCommand) {
        static Work poll(Long id, int attempt, IotIntuneRevocationPollCommand command) {
            return new Work(WorkType.POLL, id, attempt, command, null);
        }
        static Work upload(Long id, int attempt, IotIntuneRevocationUploadCommand command) {
            return new Work(WorkType.UPLOAD, id, attempt, null, command);
        }
        static Work skippedWork() {
            return new Work(WorkType.SKIP, null, 0, null, null);
        }
    }
}
