// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import com.certmanagement.iot.alert.IotAlertPublisher;
import com.certmanagement.iot.certificate.IotDeviceCertificate;
import com.certmanagement.iot.certificate.IotDeviceCertificateRepository;
import com.certmanagement.iot.service.IotDeviceEventService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotRevocationResultServiceTest {
    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:00:00Z"), ZoneOffset.UTC);

    @Mock private IotCertificateRevocationRepository revocationRepository;
    @Mock private IotDeviceCertificateRepository certificateRepository;
    @Mock private IotDeviceEventService eventService;
    @Mock private IotAlertPublisher alertPublisher;
    private IotRevocationResultService service;

    @BeforeEach
    void setUp() {
        service = new IotRevocationResultService(
                revocationRepository, certificateRepository, eventService, alertPublisher, CLOCK);
    }

    @Test
    void staleFailureCannotOverwriteNewerAttempt() {
        IotCertificateRevocation operation = operation(IotCertificateRevocationStatus.DISPATCHED, 2);
        when(revocationRepository.findByOrganizationIdAndOperationXref(42L, "iotrevoke_1"))
                .thenReturn(Optional.of(operation));

        service.handle(result(1, "FAILED"));

        assertThat(operation.getStatus()).isEqualTo(IotCertificateRevocationStatus.DISPATCHED);
        verify(certificateRepository, never()).save(any());
    }

    @Test
    void authoritativeStaleConfirmationUpgradesUnknownOutcome() {
        IotCertificateRevocation operation = operation(
                IotCertificateRevocationStatus.OUTCOME_UNKNOWN, 2);
        IotDeviceCertificate certificate = certificate();
        when(revocationRepository.findByOrganizationIdAndOperationXref(42L, "iotrevoke_1"))
                .thenReturn(Optional.of(operation));
        when(certificateRepository.findByIdForUpdate(9L)).thenReturn(Optional.of(certificate));

        service.handle(result(1, "CONFIRMED"));

        assertThat(operation.getStatus()).isEqualTo(IotCertificateRevocationStatus.CONFIRMED);
        assertThat(certificate.getStatus()).isEqualTo("REVOKED");
        verify(eventService).recordCertificateUnderWorkflowLock(
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void unknownOutcomeIsDroppedWithoutPoisoningTheConsumer() {
        IotCertificateRevocation operation = operation(IotCertificateRevocationStatus.DISPATCHED, 1);
        when(revocationRepository.findByOrganizationIdAndOperationXref(42L, "iotrevoke_1"))
                .thenReturn(Optional.of(operation));

        service.handle(result(1, "FUTURE_OUTCOME"));

        assertThat(operation.getStatus()).isEqualTo(IotCertificateRevocationStatus.DISPATCHED);
        verify(certificateRepository, never()).findById(any());
    }

    @Test
    void failedOperationCannotRegressAnAlreadyRevokedCertificate() {
        IotCertificateRevocation operation = operation(IotCertificateRevocationStatus.DISPATCHED, 1);
        IotDeviceCertificate certificate = certificate();
        certificate.setStatus("REVOKED");
        when(revocationRepository.findByOrganizationIdAndOperationXref(42L, "iotrevoke_1"))
                .thenReturn(Optional.of(operation));
        when(certificateRepository.findByIdForUpdate(9L)).thenReturn(Optional.of(certificate));

        service.handle(result(1, "FAILED"));

        assertThat(certificate.getStatus()).isEqualTo("REVOKED");
    }

    private static IotCertificateRevocationResult result(int attempt, String outcome) {
        IotCertificateRevocationResult result = new IotCertificateRevocationResult();
        result.setRequestId("iotrevoke_1:" + attempt);
        result.setCorrelationId("iotrevoke_1");
        result.setOrganizationId("42");
        result.setOperationXref("iotrevoke_1");
        result.setDispatchAttempt(attempt);
        result.setCertificateXref("crt-1");
        result.setOutcome(outcome);
        result.setCaObservedReason("CESSATION_OF_OPERATION");
        return result;
    }

    private static IotCertificateRevocation operation(
            IotCertificateRevocationStatus status, int attempts) {
        OffsetDateTime now = OffsetDateTime.now(CLOCK);
        return IotCertificateRevocation.builder().id(1L).operationXref("iotrevoke_1")
                .organizationId(42L).certificateId(9L).deviceSourceId(3L)
                .source(IotCertificateRevocationSource.UI)
                .reason(IotRevocationReason.CESSATION_OF_OPERATION)
                .status(status).attemptCount(attempts).nextAttemptAt(now)
                .createdAt(now).updatedAt(now).build();
    }

    private static IotDeviceCertificate certificate() {
        return IotDeviceCertificate.builder().id(9L).organizationId(42L)
                .certificateXref("crt-1").deviceSourceId(3L).deviceId(4L)
                .enrollmentId(8L).status("REVOCATION_OUTCOME_UNKNOWN").build();
    }
}
