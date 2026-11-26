// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.iot.certificate.IotDeviceCertificate;
import com.certmanagement.iot.certificate.IotDeviceCertificateRepository;
import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.service.IotDeviceEventService;
import com.certmanagement.util.MdcIds;
import com.certmanagement.service.audit.IotAuditRecorder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class IotCertificateRevocationService {
    private static final List<IotCertificateRevocationStatus> ACTIVE = List.of(
            IotCertificateRevocationStatus.PENDING,
            IotCertificateRevocationStatus.DISPATCHED);

    private final IotDeviceCertificateRepository certificateRepository;
    private final IotCertificateRevocationRepository revocationRepository;
    private final IotDeviceEventService eventService;
    private final Clock clock;
    /** The machine-identity rows of the audit trail, written in the change's transaction. */
    private final IotAuditRecorder iotAudit;

    @Transactional
    public IotRevocationResponse request(Long organizationId,
                                         String certificateXref,
                                         String idempotencyKey,
                                         Long actorUserId,
                                         CreateIotRevocationRequest request) {
        String key = requireIdempotencyKey(idempotencyKey);
        IotDeviceCertificate certificate = certificateRepository
                .findByOrganizationIdAndCertificateXrefForUpdate(organizationId, certificateXref)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Certificate not found: " + certificateXref));

        IotCertificateRevocation existing = revocationRepository
                .findByOrganizationIdAndIdempotencyKey(organizationId, key).orElse(null);
        if (existing != null) {
            verifySameRequest(existing, certificate, request);
            return response(existing, certificateXref);
        }
        validateCertificate(certificate);
        revocationRepository.findFirstByCertificateIdAndStatusInOrderByIdDesc(
                        certificate.getId(), ACTIVE)
                .ifPresent(active -> {
                    throw new ResponseStatusException(HttpStatus.CONFLICT,
                            "Certificate already has an active revocation operation: "
                                    + active.getOperationXref());
                });

        OffsetDateTime now = OffsetDateTime.now(clock);
        IotCertificateRevocation operation = IotCertificateRevocation.builder()
                .operationXref("iotrevoke_" + UUID.randomUUID())
                .organizationId(organizationId)
                .certificateId(certificate.getId())
                .deviceSourceId(certificate.getDeviceSourceId())
                .source(IotCertificateRevocationSource.UI)
                .idempotencyKey(key)
                .reason(request.reason())
                .operatorNote(trimToNull(request.operatorNote()))
                .requestedByUserId(actorUserId)
                .status(IotCertificateRevocationStatus.PENDING)
                .attemptCount(0)
                .nextAttemptAt(now)
                .createdAt(now)
                .updatedAt(now)
                .build();
        revocationRepository.save(operation);

        certificate.setStatus("REVOCATION_PENDING");
        certificate.setUpdatedAt(now);
        certificateRepository.save(certificate);
        iotAudit.certificateRevocationRequested(certificate, request.reason(), operation.getOperationXref());
        eventService.recordCertificate(certificate, DeviceEventType.CERTIFICATE_REVOCATION_REQUESTED,
                "PENDING", "Certificate revocation requested", ActorSource.UI, actorUserId,
                Map.of("operationXref", operation.getOperationXref(),
                        "reason", request.reason().name(),
                        "caProvider", certificate.getCaProvider()),
                MdcIds.correlationId(), operation.getOperationXref() + ":requested", now);
        // operation= is the key the dispatch and result stages carry; the operator's own corr= is
        // replaced downstream by the operation xref, so this line is where the two trails meet.
        log.info("IoT revocation requested: operation={} certificate={} reason={} caProvider={} "
                        + "actorUserId={}",
                operation.getOperationXref(), certificateXref, request.reason().name(),
                certificate.getCaProvider(), actorUserId);
        return response(operation, certificateXref);
    }

    private static void validateCertificate(IotDeviceCertificate certificate) {
        if (Boolean.TRUE.equals(certificate.getCertificateAuthority())) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                    "IoT CA certificates cannot be revoked through this endpoint");
        }
        if (!"EJBCA".equalsIgnoreCase(certificate.getCaProvider())
                && !"SMALLSTEP".equalsIgnoreCase(certificate.getCaProvider())) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                    "The certificate authority provider does not support IoT revocation");
        }
        if ("REVOKED".equals(certificate.getStatus())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Certificate is already revoked");
        }
        if (!List.of("ISSUED", "REVOCATION_FAILED", "REVOCATION_OUTCOME_UNKNOWN")
                .contains(certificate.getStatus())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Certificate cannot be revoked in state " + certificate.getStatus());
        }
    }

    private static void verifySameRequest(IotCertificateRevocation existing,
                                          IotDeviceCertificate certificate,
                                          CreateIotRevocationRequest request) {
        if (!Objects.equals(existing.getCertificateId(), certificate.getId())
                || existing.getReason() != request.reason()
                || !Objects.equals(existing.getOperatorNote(), trimToNull(request.operatorNote()))) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Idempotency-Key was already used for a different revocation request");
        }
    }

    private static String requireIdempotencyKey(String value) {
        if (value == null || value.isBlank() || value.length() > 100) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Idempotency-Key is required and must be at most 100 characters");
        }
        return value.trim();
    }

    private static String trimToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    static IotRevocationResponse response(
            IotCertificateRevocation operation, String certificateXref) {
        return new IotRevocationResponse(
                operation.getOperationXref(), certificateXref, operation.getStatus().name(),
                operation.getReason().name(), operation.getSource().name(),
                operation.getAttemptCount(), operation.getCreatedAt(), operation.getCompletedAt(),
                operation.getErrorCode(), operation.getErrorMessage());
    }
}
