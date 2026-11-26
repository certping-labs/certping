// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.service.IotDeviceEventService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/**
 * Marks a certificate superseded once a newer one exists for the same device and profile.
 *
 * <p>Keyed on the group rather than on an arriving certificate. Supersession needs both sides to
 * carry a device and a profile, and either side can gain one late: a certificate issued before its
 * device synced is linked by a later sync, and one issued against an unknown profile is linked when
 * profile correlation runs. Whichever side completes the pair, the question being asked is the same
 * — "is anything in this group now superseded?" — so every path that links a certificate calls this
 * with the group it just completed, and the rules live here only.
 *
 * <p>Anchored on the group's newest <b>usable</b> certificate. An expired one proves nothing worth
 * changing state over, and it matches the predicate {@code findCurrentForDeviceSync} applies to the
 * newer side, so the two agree about what counts as a replacement.
 *
 * <p>Idempotent twice over: a prior already marked is skipped, and the audit event carries a dedupe
 * key, so a redelivered sync completion writes nothing new.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IotCertificateSupersessionService {

    private final IotDeviceCertificateRepository certificateRepository;
    private final IotCertificateEnrollmentRepository enrollmentRepository;
    private final IotDeviceEventService eventService;
    private final Clock clock;

    /** Call after linking a certificate, with the device and profile it now belongs to. */
    public void reconcileGroup(Long organizationId, Long deviceId, Long profileId,
                               String correlationId) {
        if (organizationId == null || deviceId == null || profileId == null) {
            return;
        }
        List<IotDeviceCertificate> newest = certificateRepository.findNewestUsableInGroup(
                organizationId, deviceId, profileId, OffsetDateTime.now(clock),
                PageRequest.of(0, 1));
        if (newest.isEmpty()) {
            return;
        }
        IotDeviceCertificate current = newest.getFirst();
        List<Long> priorIds = certificateRepository.findSupersededMonitoredCertificates(
                        organizationId, deviceId, profileId, current.getId(), current.getIssuedAt())
                .stream().map(IotDeviceCertificate::getId).toList();
        if (priorIds.isEmpty()) {
            return;
        }

        OffsetDateTime now = OffsetDateTime.now(clock);
        // Locked in key order like every other multi-row certificate write here, and re-read under
        // the lock so a concurrent marker is not overwritten.
        for (IotDeviceCertificate prior : certificateRepository.lockAllByIdIn(priorIds)) {
            if (!"NONE".equals(prior.getRenewalState())
                    && !"NUDGING".equals(prior.getRenewalState())) {
                continue;
            }
            prior.setRenewalState("RENEWED");
            prior.setUpdatedAt(now);
            certificateRepository.save(prior);
            enrollmentRepository.findById(prior.getEnrollmentId()).ifPresentOrElse(
                    priorEnrollment -> eventService.recordEnrollment(priorEnrollment,
                            DeviceEventType.CERTIFICATE_RENEWED, "RENEWED",
                            "Certificate renewed by a newer enrollment for the same device and profile",
                            Map.of("renewedByCertificateXref", current.getCertificateXref(),
                                    "certificateXref", prior.getCertificateXref()),
                            // The fact recorded is the issuance that proved the renewal, not the
                            // moment CertPing noticed it.
                            correlationId, "cert-renewed:" + prior.getCertificateXref(),
                            current.getIssuedAt()),
                    () -> log.error("Cannot record renewal for certificate {}: missing enrollment id={}",
                            prior.getCertificateXref(), prior.getEnrollmentId()));
        }
    }
}
