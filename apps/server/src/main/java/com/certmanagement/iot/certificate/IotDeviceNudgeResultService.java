// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.alert.IotAlertPublisher;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.messaging.IotDeviceSyncCommand;
import com.certmanagement.iot.messaging.IotDeviceSyncResult;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.service.IotDeviceEventService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Stores the asynchronous outcome of an Intune device-sync request. */
@Slf4j
@Service
@RequiredArgsConstructor
public class IotDeviceNudgeResultService {

    private static final String OUTCOME_NUDGE_SENT = "NUDGE_SENT";
    private static final String OUTCOME_PUBLISH_FAILED = "PUBLISH_FAILED";
    private static final Set<String> AGENT_OUTCOMES = Set.of(
            OUTCOME_NUDGE_SENT, "INTUNE_REJECTED", "INTUNE_UNAVAILABLE", "SKIPPED_UNSUPPORTED");
    private static final int MAX_CERTIFICATES_PER_DEVICE = 100;

    private final IotDeviceCertificateRepository certificateRepository;
    private final IotCertificateEnrollmentRepository enrollmentRepository;
    private final IotDeviceRepository deviceRepository;
    private final IotDeviceEventService eventService;
    private final IotAlertPublisher alertPublisher;
    private final Clock clock;

    @Transactional
    public void handle(IotDeviceSyncResult result) {
        handle(result, false);
    }

    private void handle(IotDeviceSyncResult result, boolean internal) {
        if (result == null || (!internal && !AGENT_OUTCOMES.contains(result.getOutcome()))) {
            log.warn("Dropping IOT_DEVICE_SYNC_RESPONSE with an invalid outcome");
            return;
        }
        Long organizationId = parseOrganizationId(result.getOrganizationId());
        List<String> certificateXrefs = normalizedXrefs(result.getCertificateXrefs());
        if (organizationId == null || blank(result.getRequestId())
                || blank(result.getDeviceXref()) || certificateXrefs.isEmpty()) {
            log.warn("Dropping malformed IOT_DEVICE_SYNC_RESPONSE: requestId={} deviceXref={}",
                    result.getRequestId(), result.getDeviceXref());
            return;
        }
        IotDevice device = deviceRepository
                .findByDeviceXrefAndOrganizationIdAndIsDeletedFalse(
                        result.getDeviceXref(), organizationId)
                .orElse(null);
        if (device == null) {
            log.warn("IOT_DEVICE_SYNC_RESPONSE references unknown device={} org={}",
                    result.getDeviceXref(), organizationId);
            return;
        }
        List<IotDeviceCertificate> certificates = certificateRepository
                .findAllByOrganizationIdAndCertificateXrefIn(organizationId, certificateXrefs)
                .stream().filter(certificate -> Objects.equals(certificate.getDeviceId(), device.getId()))
                .filter(certificate -> result.getRequestId().equals(
                        certificate.getLastNudgeRequestId()))
                .toList();
        if (certificates.size() != certificateXrefs.size()) {
            // Applied to the ones that still correlate rather than dropped wholesale. A single
            // certificate rebound to a re-enrolled device between the request and its answer used
            // to discard the whole result, leaving its siblings showing REQUESTED forever even
            // though their outcome had arrived.
            log.warn("IOT_DEVICE_SYNC_RESPONSE correlation mismatch, applying the rows that still "
                            + "match: requestId={} expected={} matched={}",
                    result.getRequestId(), certificateXrefs.size(), certificates.size());
        }
        certificates.forEach(certificate -> apply(certificate, result));
        alertCheckInPermissionWithdrawn(organizationId, result);
        // One result message per device, so this is the natural unit for INFO.
        log.info("Device check-in result applied: request={} device={} outcome={} certificates={}",
                result.getRequestId(), result.getDeviceXref(), result.getOutcome(),
                certificates.size());
    }

    /**
     * Losing the syncDevice permission silently stops every renewal check-in for the connection, and
     * the per-certificate NUDGE_FAILED events read as ordinary noise until certificates start
     * expiring. Deduped per source per hour, so a fleet-wide 403 raises one alert, not one per device.
     */
    private void alertCheckInPermissionWithdrawn(Long organizationId, IotDeviceSyncResult result) {
        if (!"INTUNE_REJECTED".equals(result.getOutcome())
                || !"PERMISSION_DENIED".equals(result.getErrorCode())) {
            return;
        }
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("sourceXref", result.getSourceXref());
        facts.put("deviceXref", result.getDeviceXref());
        facts.put("httpStatus", result.getHttpStatus());
        facts.put("errorCode", result.getErrorCode());
        facts.put("requiredPermission", "DeviceManagementManagedDevices.PrivilegedOperations.All");
        alertPublisher.critical(organizationId, "CHECK_IN_PERMISSION_WITHDRAWN",
                "Intune is rejecting device check-in requests",
                "Intune refused CertPing's request to make a device check in, so renewal nudges are "
                        + "no longer reaching devices on this connection. Certificates will keep "
                        + "expiring until the syncDevice permission is granted again.",
                result.getSourceXref() + ":" + IotAlertPublisher.hourBucket(), null, facts);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordPublishFailure(IotDeviceSyncCommand command) {
        IotDeviceSyncResult result = new IotDeviceSyncResult();
        result.setRequestId(command.getRequestId());
        result.setCorrelationId(command.getCorrelationId());
        result.setOrganizationId(command.getOrganizationId());
        result.setSourceXref(command.getSourceXref());
        result.setDeviceXref(command.getDeviceXref());
        result.setCertificateXrefs(command.getCertificateXrefs());
        result.setManagedDeviceId(command.getManagedDeviceId());
        result.setOutcome(OUTCOME_PUBLISH_FAILED);
        result.setErrorCode("COMMAND_PUBLISH_FAILED");
        result.setErrorMessage("CertPing could not dispatch the Intune device sync command");
        result.setRespondedAt(OffsetDateTime.now(clock).toString());
        handle(result, true);
    }

    private void apply(IotDeviceCertificate certificate, IotDeviceSyncResult result) {
        OffsetDateTime now = OffsetDateTime.now(clock);
        certificate.setLastNudgeOutcome(truncate(result.getOutcome(), 40));
        if (OUTCOME_PUBLISH_FAILED.equals(result.getOutcome())) {
            certificate.setLastNudgedAt(null);
        }
        certificate.setUpdatedAt(now);
        certificateRepository.save(certificate);

        enrollmentRepository.findById(certificate.getEnrollmentId()).ifPresentOrElse(enrollment -> {
            boolean sent = OUTCOME_NUDGE_SENT.equals(result.getOutcome());
            eventService.recordEnrollment(enrollment,
                    sent ? DeviceEventType.CERTIFICATE_NUDGE_SENT
                            : DeviceEventType.CERTIFICATE_NUDGE_FAILED,
                    "NUDGING",
                    sent ? "Intune accepted the device sync request"
                            : "Intune device sync request failed",
                    details(certificate, result), result.getCorrelationId(),
                    "iot-device-sync-result:" + result.getRequestId() + ":"
                            + certificate.getCertificateXref(),
                    respondedAt(result.getRespondedAt()));
        }, () -> log.error("Certificate {} references missing enrollment id={}",
                certificate.getCertificateXref(), certificate.getEnrollmentId()));
    }

    private static Map<String, Object> details(
            IotDeviceCertificate certificate, IotDeviceSyncResult result) {
        Map<String, Object> detail = new HashMap<>();
        put(detail, "outcome", result.getOutcome());
        put(detail, "certificateXref", certificate.getCertificateXref());
        put(detail, "managedDeviceId", result.getManagedDeviceId());
        put(detail, "httpStatus", result.getHttpStatus());
        put(detail, "errorCode", result.getErrorCode());
        put(detail, "errorMessage", truncate(result.getErrorMessage(), 1000));
        return detail;
    }

    private OffsetDateTime respondedAt(String value) {
        if (blank(value)) {
            return OffsetDateTime.now(clock);
        }
        try {
            return OffsetDateTime.parse(value);
        } catch (RuntimeException exception) {
            return OffsetDateTime.now(clock);
        }
    }

    private static List<String> normalizedXrefs(List<String> values) {
        if (values == null || values.isEmpty() || values.size() > MAX_CERTIFICATES_PER_DEVICE) {
            return List.of();
        }
        LinkedHashSet<String> normalized = new LinkedHashSet<>();
        for (String value : values) {
            if (blank(value) || value.length() > 100) {
                return List.of();
            }
            normalized.add(value.trim());
        }
        return List.copyOf(normalized);
    }

    private static Long parseOrganizationId(String value) {
        if (blank(value)) {
            return null;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException exception) {
            return null;
        }
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static void put(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }

    private static String truncate(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }
}
