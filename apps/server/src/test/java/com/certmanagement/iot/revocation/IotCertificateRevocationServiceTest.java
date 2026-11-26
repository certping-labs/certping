// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import com.certmanagement.iot.certificate.IotDeviceCertificate;
import com.certmanagement.iot.certificate.IotDeviceCertificateRepository;
import com.certmanagement.iot.service.IotDeviceEventService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotCertificateRevocationServiceTest {

    private final com.certmanagement.service.audit.IotAuditRecorder iotAudit = org.mockito.Mockito.mock(com.certmanagement.service.audit.IotAuditRecorder.class);
    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:00:00Z"), ZoneOffset.UTC);

    @Mock private IotDeviceCertificateRepository certificateRepository;
    @Mock private IotCertificateRevocationRepository revocationRepository;
    @Mock private IotDeviceEventService eventService;
    private IotCertificateRevocationService service;

    @BeforeEach
    void setUp() {
        service = new IotCertificateRevocationService(
                certificateRepository, revocationRepository, eventService, CLOCK, iotAudit);
    }

    @Test
    void createsDurablePendingOperationAndUsesExistingCertificateStatus() {
        IotDeviceCertificate certificate = certificate("EJBCA", "ISSUED");
        when(certificateRepository.findByOrganizationIdAndCertificateXrefForUpdate(42L, "crt-1"))
                .thenReturn(Optional.of(certificate));
        when(revocationRepository.findByOrganizationIdAndIdempotencyKey(42L, "key-1"))
                .thenReturn(Optional.empty());
        when(revocationRepository.findFirstByCertificateIdAndStatusInOrderByIdDesc(
                any(), any())).thenReturn(Optional.empty());

        IotRevocationResponse response = service.request(42L, "crt-1", "key-1", 7L,
                new CreateIotRevocationRequest(IotRevocationReason.KEY_COMPROMISE, "lost"));

        ArgumentCaptor<IotCertificateRevocation> operation =
                ArgumentCaptor.forClass(IotCertificateRevocation.class);
        verify(revocationRepository).save(operation.capture());
        assertThat(operation.getValue().getStatus())
                .isEqualTo(IotCertificateRevocationStatus.PENDING);
        assertThat(certificate.getStatus()).isEqualTo("REVOCATION_PENDING");
        assertThat(response.status()).isEqualTo("PENDING");
        verify(eventService).recordCertificate(any(), any(), any(), any(), any(), any(),
                any(), any(), any(), any());
        // The operator's note ("lost") is never passed on to the audit row.
        verify(iotAudit).certificateRevocationRequested(certificate, IotRevocationReason.KEY_COMPROMISE,
                operation.getValue().getOperationXref());
    }

    @Test
    void smallstepCreatesTheSameDurableOperationAsEjbca() {
        IotDeviceCertificate certificate = certificate("SMALLSTEP", "ISSUED");
        when(certificateRepository.findByOrganizationIdAndCertificateXrefForUpdate(42L, "crt-1"))
                .thenReturn(Optional.of(certificate));
        when(revocationRepository.findByOrganizationIdAndIdempotencyKey(42L, "key-1"))
                .thenReturn(Optional.empty());
        when(revocationRepository.findFirstByCertificateIdAndStatusInOrderByIdDesc(
                any(), any())).thenReturn(Optional.empty());

        IotRevocationResponse response = service.request(42L, "crt-1", "key-1", 7L,
                new CreateIotRevocationRequest(IotRevocationReason.UNSPECIFIED, null));

        assertThat(response.status()).isEqualTo("PENDING");
        assertThat(certificate.getStatus()).isEqualTo("REVOCATION_PENDING");
        verify(revocationRepository).save(any());
    }

    private static IotDeviceCertificate certificate(String provider, String status) {
        return IotDeviceCertificate.builder()
                .id(9L).certificateXref("crt-1").enrollmentId(8L)
                .organizationId(42L).deviceSourceId(3L).deviceId(4L)
                .caProvider(provider).issuerDn("CN=Issuer").serialNumber("abc")
                .certificateAuthority(false).status(status).build();
    }
}
