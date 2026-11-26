// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.certificate.IotDeviceCertificateRepository;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.enums.DeviceStatus;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.audit.IotAuditRecorder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.Map;

/**
 * Hides a device the source no longer reports, without deleting anything.
 *
 * <p>An orphaned device is kept rather than removed, because a device gone from its platform may
 * still hold a live certificate — that is the right default for a PKI and the wrong default for an
 * inventory screen, which fills up with rows an operator has already dealt with. Archiving
 * separates the two: the row, its certificates and its audit trail stay exactly where they are, and
 * only its place in the inventory goes away.
 *
 * <p>Two rules keep that from becoming a way to lose track of a credential. Only a device the
 * source has stopped reporting may be archived — a device still under management would simply come
 * back — and only once nothing usable is issued against it. A device that reappears under the same
 * source device id is un-archived by the sync itself, so this is reversible by the platform as well
 * as by hand.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IotDeviceArchiveService {

    private final IotDeviceRepository deviceRepository;
    private final IotDeviceCertificateRepository certificateRepository;
    private final IotDeviceEventService eventService;
    private final FeatureFlagService featureFlagService;
    private final Clock clock;
    /** The machine-identity rows of the audit trail, written in the change's transaction. */
    private final IotAuditRecorder iotAudit;

    /** Removes an orphaned device from the inventory, keeping the row and its history. */
    @Transactional
    public void archive(Long organizationId, String deviceXref, Long actorUserId) {
        featureFlagService.assertEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, organizationId);
        // FOR UPDATE, so a certificate being issued for this device right now has to commit
        // before the count below runs. Without that the count cannot see it and the device is
        // hidden holding a credential nobody can find.
        IotDevice device = deviceRepository
                .lockByDeviceXrefForArchive(deviceXref, organizationId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Device not found"));
        if (Boolean.TRUE.equals(device.getIsDeleted())) {
            return;
        }
        if (device.getStatus() != DeviceStatus.ORPHANED) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Only a device its source no longer reports can be archived; this one is "
                            + device.getStatus());
        }
        long usableCertificates = certificateRepository.countUsableForDevice(
                device.getId(), OffsetDateTime.now(clock));
        if (usableCertificates > 0) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Revoke or let expire " + usableCertificates
                            + " certificate(s) on this device before archiving it");
        }

        device.setIsDeleted(true);
        deviceRepository.save(device);
        iotAudit.deviceArchived(device);
        eventService.record(device, DeviceEventType.DEVICE_ARCHIVED, ActorSource.UI, actorUserId,
                Map.of("status", device.getStatus().name(),
                        "reason", "archived from the inventory by an operator"),
                null);
        log.info("IoT device archived: organizationId={} device={} status={} actorUserId={}",
                organizationId, device.getDeviceXref(), device.getStatus(), actorUserId);
    }

    /** Puts an archived device back in the inventory. */
    @Transactional
    public void restore(Long organizationId, String deviceXref, Long actorUserId) {
        featureFlagService.assertEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, organizationId);
        IotDevice device = deviceRepository
                .lockByDeviceXrefForRestore(deviceXref, organizationId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Device not found"));
        if (!Boolean.TRUE.equals(device.getIsDeleted())) {
            return;
        }
        device.setIsDeleted(false);
        deviceRepository.save(device);
        iotAudit.deviceRestored(device);
        eventService.record(device, DeviceEventType.DEVICE_RESTORED, ActorSource.UI, actorUserId,
                Map.of("status", device.getStatus().name(),
                        "reason", "returned to the inventory by an operator"),
                null);
        log.info("IoT device restored to the inventory: organizationId={} device={} actorUserId={}",
                organizationId, device.getDeviceXref(), actorUserId);
    }

}
