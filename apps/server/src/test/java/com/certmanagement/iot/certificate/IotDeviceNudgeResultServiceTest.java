// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.alert.IotAlertPublisher;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.messaging.IotDeviceSyncCommand;
import com.certmanagement.iot.messaging.IotDeviceSyncResult;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.service.IotDeviceEventService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotDeviceNudgeResultServiceTest {
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-08-28T12:00:00Z"), ZoneOffset.UTC);
    private static final long ORG = 42L;

    @Mock private IotDeviceCertificateRepository certificateRepository;
    @Mock private IotCertificateEnrollmentRepository enrollmentRepository;
    @Mock private IotDeviceRepository deviceRepository;
    @Mock private IotDeviceEventService eventService;
    @Mock private IotAlertPublisher alertPublisher;

    private IotDeviceNudgeResultService service() {
        return new IotDeviceNudgeResultService(certificateRepository, enrollmentRepository,
                deviceRepository, eventService, alertPublisher, CLOCK);
    }

    @BeforeEach
    void stubEnrollment() {
        lenient().when(enrollmentRepository.findById(99L)).thenReturn(Optional.of(enrollment()));
        lenient().when(deviceRepository.findByDeviceXrefAndOrganizationIdAndIsDeletedFalse("dev-1", ORG))
                .thenReturn(Optional.of(IotDevice.builder().id(7L).deviceXref("dev-1").build()));
    }

    @Test
    void nudgeSentPersistsOutcomeAndRecordsSentEventWithStableDedupeKey() {
        IotDeviceCertificate cert = certificate();
        when(certificateRepository.findAllByOrganizationIdAndCertificateXrefIn(ORG, List.of("crt-1")))
                .thenReturn(List.of(cert));

        service().handle(result("NUDGE_SENT"));

        assertThat(cert.getLastNudgeOutcome()).isEqualTo("NUDGE_SENT");
        assertThat(cert.getRenewalState()).isEqualTo("NUDGING");
        verify(certificateRepository).save(cert);
        ArgumentCaptor<String> dedupe = ArgumentCaptor.forClass(String.class);
        verify(eventService).recordEnrollment(any(), eq(DeviceEventType.CERTIFICATE_NUDGE_SENT),
                eq("NUDGING"), any(), any(), any(), dedupe.capture(), any());
        assertThat(dedupe.getValue()).isEqualTo("iot-device-sync-result:req-1:crt-1");
    }

    @Test
    void unsuccessfulOutcomeRecordsFailedEvent() {
        IotDeviceCertificate cert = certificate();
        when(certificateRepository.findAllByOrganizationIdAndCertificateXrefIn(ORG, List.of("crt-1")))
                .thenReturn(List.of(cert));

        service().handle(result("INTUNE_REJECTED"));

        assertThat(cert.getLastNudgeOutcome()).isEqualTo("INTUNE_REJECTED");
        verify(eventService).recordEnrollment(any(), eq(DeviceEventType.CERTIFICATE_NUDGE_FAILED),
                any(), any(), any(), any(), any(), any());
    }

    @Test
    void unknownCertificateIsIgnored() {
        when(certificateRepository.findAllByOrganizationIdAndCertificateXrefIn(ORG, List.of("crt-1")))
                .thenReturn(List.of());

        service().handle(result("NUDGE_SENT"));

        verify(certificateRepository, never()).save(any());
        verify(eventService, never()).recordEnrollment(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void missingRequestIdIsRejectedBeforeBuildingACollidingDedupeKey() {
        IotDeviceSyncResult result = result("NUDGE_SENT");
        result.setRequestId(null);

        service().handle(result);

        verify(certificateRepository, never())
                .findAllByOrganizationIdAndCertificateXrefIn(any(), any());
        verify(eventService, never()).recordEnrollment(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void certificateMustBelongToTheReportedDevice() {
        IotDeviceCertificate cert = certificate();
        cert.setDeviceId(999L);
        when(certificateRepository.findAllByOrganizationIdAndCertificateXrefIn(ORG, List.of("crt-1")))
                .thenReturn(List.of(cert));

        service().handle(result("NUDGE_SENT"));

        verify(certificateRepository, never()).save(any());
        verify(eventService, never()).recordEnrollment(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void publishFailureClearsCooldownSoTheOperatorCanRetry() {
        IotDeviceCertificate cert = certificate();
        cert.setLastNudgedAt(OffsetDateTime.now(CLOCK));
        when(certificateRepository.findAllByOrganizationIdAndCertificateXrefIn(ORG, List.of("crt-1")))
                .thenReturn(List.of(cert));

        service().recordPublishFailure(IotDeviceSyncCommand.builder()
                .requestId("req-1")
                .correlationId("corr-1")
                .organizationId(String.valueOf(ORG))
                .sourceXref("src-1")
                .deviceXref("dev-1")
                .managedDeviceId("11111111-1111-1111-1111-111111111111")
                .certificateXrefs(List.of("crt-1"))
                .build());

        assertThat(cert.getLastNudgedAt()).isNull();
        assertThat(cert.getLastNudgeOutcome()).isEqualTo("PUBLISH_FAILED");
    }

    @Test
    void staleResponseCannotOverwriteANewerRequest() {
        IotDeviceCertificate cert = certificate();
        cert.setLastNudgeRequestId("req-newer");
        when(certificateRepository.findAllByOrganizationIdAndCertificateXrefIn(ORG, List.of("crt-1")))
                .thenReturn(List.of(cert));

        service().handle(result("NUDGE_SENT"));

        verify(certificateRepository, never()).save(any());
        verify(eventService, never()).recordEnrollment(any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void agentCannotInjectTheInternalPublishFailureOutcome() {
        service().handle(result("PUBLISH_FAILED"));

        verify(certificateRepository, never())
                .findAllByOrganizationIdAndCertificateXrefIn(any(), any());
    }

    private static IotDeviceSyncResultWrapper result(String outcome) {
        return new IotDeviceSyncResultWrapper(outcome);
    }

    // Small builder around the no-args DTO to keep the tests terse.
    private static class IotDeviceSyncResultWrapper extends IotDeviceSyncResult {
        IotDeviceSyncResultWrapper(String outcome) {
            setRequestId("req-1");
            setCorrelationId("corr-1");
            setOrganizationId(String.valueOf(ORG));
            setCertificateXrefs(List.of("crt-1"));
            setDeviceXref("dev-1");
            setManagedDeviceId("managed-device-123");
            setOutcome(outcome);
            setHttpStatus("NUDGE_SENT".equals(outcome) ? 204 : 404);
            setRespondedAt("2026-08-28T12:00:00Z");
        }
    }

    private static IotDeviceCertificate certificate() {
        OffsetDateTime now = OffsetDateTime.now(CLOCK);
        return IotDeviceCertificate.builder()
                .id(500L).certificateXref("crt-1").enrollmentId(99L).organizationId(ORG)
                .deviceSourceId(3L).profileId(3L).deviceId(7L).caProvider("EJBCA")
                .validFrom(now.minusDays(180)).validTo(now.plusDays(10)).certificateAuthority(false)
                .status("ISSUED").renewalState("NUDGING").nudgeAttempts(1)
                .lastNudgeRequestId("req-1")
                .issuedAt(now.minusDays(180)).createdAt(now.minusDays(180)).updatedAt(now.minusDays(180))
                .build();
    }

    private static IotCertificateEnrollment enrollment() {
        OffsetDateTime now = OffsetDateTime.now(CLOCK);
        return IotCertificateEnrollment.builder()
                .id(99L).enrollmentXref("enr-99").organizationId(ORG).deviceSourceId(3L)
                .endpointId("default").transactionId("txn-1").enrollmentType("INITIAL")
                .deviceMatchStatus("MATCHED").profileResolutionStatus("MATCHED").status("ISSUED")
                .retryable(false).requestedAt(now).createdAt(now).updatedAt(now).build();
    }
}
