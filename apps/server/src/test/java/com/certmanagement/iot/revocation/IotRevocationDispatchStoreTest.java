// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import com.certmanagement.iot.certificate.IotDeviceCertificate;
import com.certmanagement.iot.certificate.IotDeviceCertificateRepository;
import com.certmanagement.iot.config.IotRevocationProperties;
import com.certmanagement.iot.service.IotDeviceEventService;
import com.certmanagement.service.OrgTypeResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotRevocationDispatchStoreTest {
    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:00:00Z"), ZoneOffset.UTC);

    @Mock private IotCertificateRevocationRepository revocationRepository;
    @Mock private IotDeviceCertificateRepository certificateRepository;
    @Mock private IotDeviceEventService eventService;
    @Mock private OrgTypeResolver orgTypeResolver;
    private IotRevocationDispatchStore store;

    @BeforeEach
    void setUp() {
        IotRevocationProperties properties = new IotRevocationProperties();
        store = new IotRevocationDispatchStore(revocationRepository, certificateRepository,
                eventService, orgTypeResolver, properties, CLOCK);
    }

    @Test
    void claimsBoundedBatchAndCreatesAttemptSpecificMessageIdentity() {
        IotCertificateRevocation operation = operation();
        IotDeviceCertificate certificate = certificate();
        when(revocationRepository.claimDue(OffsetDateTime.now(CLOCK), 100))
                .thenReturn(List.of(operation));
        when(certificateRepository.lockAllByIdIn(List.of(9L))).thenReturn(List.of(certificate));
        when(orgTypeResolver.resolveAll(java.util.Set.of(42L)))
                .thenReturn(Map.of(42L, "B2B"));

        IotRevocationDispatchStore.ClaimBatch batch = store.claimBatch();

        assertThat(batch.foundRows()).isTrue();
        assertThat(batch.claims()).hasSize(1);
        IotCertificateRevocationCommand command = batch.claims().getFirst().command();
        assertThat(command.getRequestId()).isEqualTo("iotrevoke_1:1");
        assertThat(command.getDispatchAttempt()).isEqualTo(1);
        assertThat(operation.getNextAttemptAt()).isEqualTo(
                OffsetDateTime.now(CLOCK).plusMinutes(15));
        verify(revocationRepository).saveAll(List.of(operation));
    }

    @Test
    void intuneReofferCreatesANewMessageIdentityEvenWhenAttemptCounterRestarts() {
        IotCertificateRevocation operation = operation();
        operation.setSource(IotCertificateRevocationSource.INTUNE);
        operation.setIntuneTransactionId("tx-new");
        IotDeviceCertificate certificate = certificate();
        when(revocationRepository.claimDue(OffsetDateTime.now(CLOCK), 100))
                .thenReturn(List.of(operation));
        when(certificateRepository.lockAllByIdIn(List.of(9L))).thenReturn(List.of(certificate));
        when(orgTypeResolver.resolveAll(java.util.Set.of(42L))).thenReturn(Map.of(42L, "B2B"));

        IotCertificateRevocationCommand command = store.claimBatch()
                .claims().getFirst().command();

        assertThat(command.getRequestId()).isEqualTo("iotrevoke_1:tx-new:1");
    }

    private static IotCertificateRevocation operation() {
        OffsetDateTime now = OffsetDateTime.now(CLOCK);
        return IotCertificateRevocation.builder().id(1L).operationXref("iotrevoke_1")
                .organizationId(42L).certificateId(9L).deviceSourceId(3L)
                .source(IotCertificateRevocationSource.UI)
                .reason(IotRevocationReason.CESSATION_OF_OPERATION)
                .status(IotCertificateRevocationStatus.PENDING).attemptCount(0)
                .nextAttemptAt(now).createdAt(now).updatedAt(now).build();
    }

    private static IotDeviceCertificate certificate() {
        return IotDeviceCertificate.builder().id(9L).organizationId(42L)
                .certificateXref("crt-1").deviceSourceId(3L).deviceId(4L).enrollmentId(8L)
                .caProvider("EJBCA").issuerDn("CN=Issuer").serialNumber("abc")
                .status("REVOCATION_PENDING").build();
    }
}
