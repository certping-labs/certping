// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.service.IotDeviceEventService;
import com.certmanagement.util.MdcIds;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.util.Map;

/** Persists one certificate's participation in a device-wide Intune sync request. */
@Slf4j
@Component
@RequiredArgsConstructor
class IotDeviceSyncRequestRecorder {

    private final IotDeviceCertificateRepository certificateRepository;
    private final IotCertificateEnrollmentRepository enrollmentRepository;
    private final IotDeviceEventService eventService;

    void record(
            IntuneRenewalEligibilityPolicy.EligibleCertificate item,
            String requestId,
            OffsetDateTime now) {
        IotDeviceCertificate certificate = item.certificate();
        certificate.setRenewalState("NUDGING");
        certificate.setRenewalDueAt(item.eligibility().renewalDueAt());
        certificate.setLastNudgedAt(now);
        certificate.setLastNudgeRequestId(requestId);
        certificate.setLastNudgeOutcome("REQUESTED");
        certificate.setNudgeAttempts(value(certificate.getNudgeAttempts()) + 1);
        certificate.setUpdatedAt(now);
        certificateRepository.save(certificate);

        enrollmentRepository.findById(certificate.getEnrollmentId()).ifPresentOrElse(enrollment ->
                eventService.recordEnrollment(enrollment, DeviceEventType.CERTIFICATE_NUDGE_REQUESTED,
                        "NUDGING", "Intune device sync requested",
                        Map.of("certificateXref", certificate.getCertificateXref(),
                                "renewalThresholdPercentage",
                                item.eligibility().thresholdPercentage(),
                                "renewalDueAt", item.eligibility().renewalDueAt().toString(),
                                "nudgeAttempts", certificate.getNudgeAttempts(),
                                "trigger", "MANUAL"),
                        MdcIds.correlationId(),
                        "iot-device-sync-request:" + requestId + ":" + certificate.getCertificateXref(),
                        now),
                () -> log.error("Certificate {} references missing enrollment id={}",
                        certificate.getCertificateXref(), certificate.getEnrollmentId()));
    }

    private static int value(Integer number) {
        return number == null ? 0 : number;
    }
}
