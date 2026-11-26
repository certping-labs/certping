// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import com.certmanagement.iot.alert.IotAlertPublisher;
import com.certmanagement.iot.certificate.IotDeviceCertificate;
import com.certmanagement.iot.certificate.IotDeviceCertificateRepository;
import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.service.IotDeviceEventService;
import com.certmanagement.messaging.model.AgentErrorMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class IotRevocationResultService {
    private final IotCertificateRevocationRepository revocationRepository;
    private final IotDeviceCertificateRepository certificateRepository;
    private final IotDeviceEventService eventService;
    private final IotAlertPublisher alertPublisher;
    private final Clock clock;

    @Transactional
    public void handle(IotCertificateRevocationResult result) {
        Long organizationId = parseOrganizationId(result.getOrganizationId());
        if (organizationId == null || blank(result.getOperationXref())) {
            log.warn("Dropping malformed IoT revocation result operation={}",
                    result.getOperationXref());
            return;
        }
        IotCertificateRevocation operation = revocationRepository
                .findByOrganizationIdAndOperationXref(organizationId, result.getOperationXref())
                .orElse(null);
        if (operation == null) {
            log.warn("Dropping IoT revocation result for unknown operation={} org={}",
                    result.getOperationXref(), organizationId);
            return;
        }
        Outcome outcome = normalizeOutcome(result.getOutcome());
        if (outcome == null) {
            log.warn("Dropping IoT revocation result with unsupported outcome={} operation={}",
                    result.getOutcome(), result.getOperationXref());
            return;
        }
        if (!validAttempt(result, operation, outcome)) return;
        if (operation.getStatus() == IotCertificateRevocationStatus.CONFIRMED
                || (terminal(operation.getStatus()) && outcome != Outcome.CONFIRMED)) return;
        // Locked, because the status read below decides whether to record a failure over it and a
        // second operation for the same certificate can be completing concurrently.
        IotDeviceCertificate certificate = certificateRepository
                .findByIdForUpdate(operation.getCertificateId())
                .filter(row -> row.getOrganizationId().equals(organizationId)).orElse(null);
        if (certificate == null || !certificate.getCertificateXref().equals(result.getCertificateXref())) {
            log.warn("Dropping mismatched IoT revocation result operation={} certificate={}",
                    result.getOperationXref(), result.getCertificateXref());
            return;
        }

        OffsetDateTime now = OffsetDateTime.now(clock);
        switch (outcome) {
            case CONFIRMED -> completeConfirmed(operation, certificate, result, now);
            case FAILED -> completeFailure(operation, certificate, result, now, false);
            case OUTCOME_UNKNOWN -> completeFailure(operation, certificate, result, now, true);
        }
    }

    public void handleAgentError(AgentErrorMessage error) {
        AttemptIdentity identity = parseAttemptIdentity(error.getRequestId());
        if (identity == null) return;
        IotCertificateRevocationResult result = new IotCertificateRevocationResult();
        result.setRequestId(error.getRequestId());
        result.setCorrelationId(error.getCorrelationId());
        result.setOrganizationId(error.getOrganizationId());
        result.setOperationXref(identity.operationXref());
        result.setDispatchAttempt(identity.attempt());
        result.setCertificateXref(error.getCertificateXref());
        result.setOutcome("RETRY_GIVE_UP".equals(error.getErrorCode())
                ? "OUTCOME_UNKNOWN" : "FAILED");
        result.setErrorCode(error.getErrorCode());
        result.setErrorMessage(error.getErrorDetail());
        handle(result);
    }

    private static boolean validAttempt(IotCertificateRevocationResult result,
                                        IotCertificateRevocation operation,
                                        Outcome outcome) {
        Integer attempt = result.getDispatchAttempt();
        if (attempt == null || attempt < 1 || attempt > operation.getAttemptCount()) return false;
        if (outcome == Outcome.CONFIRMED) {
            return requestIdentityMatches(result.getRequestId(), operation.getOperationXref(), attempt);
        }
        return attempt.equals(operation.getAttemptCount())
                && currentRequestId(operation, attempt).equals(result.getRequestId());
    }

    private static AttemptIdentity parseAttemptIdentity(String requestId) {
        if (blank(requestId)) return null;
        int separator = requestId.lastIndexOf(':');
        if (separator < 1 || separator == requestId.length() - 1) return null;
        try {
            int firstSeparator = requestId.indexOf(':');
            if (firstSeparator < 1) return null;
            return new AttemptIdentity(requestId.substring(0, firstSeparator),
                    Integer.parseInt(requestId.substring(separator + 1)));
        } catch (NumberFormatException exception) {
            return null;
        }
    }

    private void completeConfirmed(IotCertificateRevocation operation,
                                   IotDeviceCertificate certificate,
                                   IotCertificateRevocationResult result,
                                   OffsetDateTime now) {
        operation.setStatus(IotCertificateRevocationStatus.CONFIRMED);
        operation.setCaObservedReason(truncate(result.getCaObservedReason(), 100));
        operation.setCaObservedAt(parseObservedAt(result.getObservedAt(), now));
        operation.setErrorCode(null);
        operation.setErrorMessage(null);
        operation.setCompletedAt(now);
        operation.setUpdatedAt(now);
        revocationRepository.save(operation);
        certificate.setStatus("REVOKED");
        certificate.setUpdatedAt(now);
        certificateRepository.save(certificate);
        eventService.recordCertificateUnderWorkflowLock(certificate,
                DeviceEventType.CERTIFICATE_REVOCATION_CONFIRMED,
                "CONFIRMED", "Certificate authority confirmed certificate revocation",
                ActorSource.AGENT, null,
                Map.of("operationXref", operation.getOperationXref(),
                        "reason", operation.getReason().name(),
                        "caProvider", value(certificate.getCaProvider()),
                        "caObservedReason", value(result.getCaObservedReason())),
                result.getCorrelationId(), operation.getOperationXref() + ":confirmed", now);
        log.info("IoT revocation confirmed by the CA: operation={} certificate={} caProvider={}",
                operation.getOperationXref(), certificate.getCertificateXref(),
                value(certificate.getCaProvider()));
    }

    private void completeFailure(IotCertificateRevocation operation,
                                 IotDeviceCertificate certificate,
                                 IotCertificateRevocationResult result,
                                 OffsetDateTime now,
                                 boolean unknown) {
        IotCertificateRevocationStatus status = unknown
                ? IotCertificateRevocationStatus.OUTCOME_UNKNOWN
                : IotCertificateRevocationStatus.FAILED;
        operation.setStatus(status);
        operation.setErrorCode(truncate(result.getErrorCode(), 100));
        operation.setErrorMessage(truncate(result.getErrorMessage(), 500));
        operation.setCompletedAt(now);
        operation.setUpdatedAt(now);
        revocationRepository.save(operation);
        if (!"REVOKED".equals(certificate.getStatus())) {
            certificate.setStatus(unknown ? "REVOCATION_OUTCOME_UNKNOWN" : "REVOCATION_FAILED");
            certificate.setUpdatedAt(now);
        }
        certificateRepository.save(certificate);
        // errorMessage stays out of the log: agent-supplied text, already truncated into the event.
        log.warn("IoT revocation result was not a confirmation: operation={} certificate={} "
                        + "status={} errorCode={}",
                operation.getOperationXref(), certificate.getCertificateXref(), status,
                result.getErrorCode());
        eventService.recordCertificateUnderWorkflowLock(certificate,
                unknown ? DeviceEventType.CERTIFICATE_REVOCATION_OUTCOME_UNKNOWN
                        : DeviceEventType.CERTIFICATE_REVOCATION_FAILED,
                status.name(), unknown ? "Certificate revocation outcome is unknown"
                        : "Certificate revocation failed",
                ActorSource.AGENT, null,
                Map.of("operationXref", operation.getOperationXref(),
                        "caProvider", value(certificate.getCaProvider()),
                        "errorCode", value(result.getErrorCode()),
                        "errorMessage", value(truncate(result.getErrorMessage(), 500))),
                result.getCorrelationId(), operation.getOperationXref() + ":" + status.name()
                        + eventCycle(operation), now);
        alertRevocationFailure(operation, certificate, result, unknown);
    }

    /**
     * A revocation that did not confirm leaves a certificate the operator believes is dead still
     * trusted, so it pages rather than waiting for the daily digest. Deduping on the operation xref
     * means one alert per revocation attempt, however many times the result is redelivered.
     */
    private void alertRevocationFailure(IotCertificateRevocation operation,
                                        IotDeviceCertificate certificate,
                                        IotCertificateRevocationResult result,
                                        boolean unknown) {
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("commonName", value(certificate.getCommonName()));
        facts.put("serialNumber", value(certificate.getSerialNumber()));
        facts.put("caProvider", value(certificate.getCaProvider()));
        facts.put("operationXref", operation.getOperationXref());
        facts.put("revocationReason", operation.getReason().name());
        facts.put("errorCode", value(result.getErrorCode()));
        facts.put("errorMessage", value(truncate(result.getErrorMessage(), 500)));
        alertPublisher.critical(certificate.getOrganizationId(),
                unknown ? "REVOCATION_OUTCOME_UNKNOWN" : "REVOCATION_FAILED",
                unknown ? "Certificate revocation was not confirmed"
                        : "Certificate revocation failed",
                unknown
                        ? "CertPing dispatched the revocation but the certificate authority never "
                                + "confirmed it. Treat the certificate as still trusted until you "
                                + "verify its state directly with the CA."
                        : "The certificate authority rejected the revocation. The certificate is "
                                + "still trusted and the device can keep authenticating with it.",
                operation.getOperationXref(), certificate.getCertificateXref(), facts);
    }

    private static Outcome normalizeOutcome(String value) {
        try {
            return Outcome.valueOf(value == null ? ""
                    : value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    private static String currentRequestId(IotCertificateRevocation operation, int attempt) {
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

    private static boolean requestIdentityMatches(String requestId, String operationXref,
                                                   int attempt) {
        String suffix = ":" + attempt;
        if ((operationXref + suffix).equals(requestId)) return true;
        if (blank(requestId) || !requestId.startsWith(operationXref + ":")
                || !requestId.endsWith(suffix)) return false;
        int start = operationXref.length() + 1;
        int end = requestId.length() - suffix.length();
        return end > start && !requestId.substring(start, end).isBlank();
    }

    private static OffsetDateTime parseObservedAt(String value, OffsetDateTime fallback) {
        if (blank(value)) return fallback;
        try {
            return OffsetDateTime.parse(value);
        } catch (DateTimeParseException exception) {
            return fallback;
        }
    }

    private static Long parseOrganizationId(String value) {
        try {
            return Long.valueOf(value);
        } catch (NumberFormatException exception) {
            return null;
        }
    }

    private static boolean terminal(IotCertificateRevocationStatus status) {
        return status == IotCertificateRevocationStatus.CONFIRMED
                || status == IotCertificateRevocationStatus.FAILED
                || status == IotCertificateRevocationStatus.OUTCOME_UNKNOWN;
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static String truncate(String value, int length) {
        if (value == null) return null;
        return value.length() <= length ? value : value.substring(0, length);
    }

    private static String value(String value) {
        return value == null ? "" : value;
    }

    private enum Outcome { CONFIRMED, FAILED, OUTCOME_UNKNOWN }
    private record AttemptIdentity(String operationXref, int attempt) {}
}
