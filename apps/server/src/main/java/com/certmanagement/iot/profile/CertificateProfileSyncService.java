// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.config.IotDeviceProperties;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceSourceEventType;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.enums.DeviceSourceStatus;
import com.certmanagement.iot.repository.IotDeviceSourceEventRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.service.IotDeviceSourceEventService;
import com.certmanagement.service.FeatureFlagService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateProfileSyncService {
    private final IotDeviceSourceRepository sourceRepository;
    private final IotDeviceSourceEventRepository eventRepository;
    private final IotDeviceSourceEventService eventService;
    private final FeatureFlagService featureFlagService;
    private final CertificateProfileMessageDispatcher dispatcher;
    private final CertificateProfileJsonCodec jsonCodec;
    private final IotDeviceProperties properties;
    private final Clock clock;

    @Transactional
    public String request(Long organizationId, String sourceXref, Long actorUserId) {
        IotDeviceSource source = sourceRepository
                .lockBySourceXrefAndOrganizationId(sourceXref, organizationId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Device source not found"));
        validate(source);
        var openSync = eventRepository.findLatestOpenProfileSync(source.getId());
        if (openSync.isPresent()) {
            Object requestXref = jsonCodec.readObject(openSync.get().getDetailJson())
                    .get("requestXref");
            if (requestXref != null && !requestXref.toString().isBlank()) {
                String existingRequestXref = requestXref.toString();
                OffsetDateTime staleBefore = OffsetDateTime.now(clock)
                        .minus(properties.getProfileResponseTimeout());
                if (openSync.get().getOccurredAt() != null
                        && openSync.get().getOccurredAt().isBefore(staleBefore)) {
                    eventService.record(source, DeviceSourceEventType.PROFILE_SYNC_FAILED, "FAILED",
                            Map.of("requestXref", existingRequestXref,
                                    "errorCode", "PROFILE_SYNC_TIMEOUT"),
                            OffsetDateTime.now(clock), existingRequestXref,
                            existingRequestXref + ":failed");
                    return prepare(source, actorUserId, false);
                }
                if (!eventRepository.existsByDeviceSourceIdAndCorrelationIdAndEventType(
                        source.getId(), existingRequestXref,
                        DeviceSourceEventType.PROFILE_SYNC_STARTED)) {
                    afterCommit(() -> dispatcher.publishDiscovery(
                            source.getId(), existingRequestXref));
                }
                return existingRequestXref;
            }
        }
        return prepare(source, actorUserId, false);
    }

    @Transactional
    public void requestInitialIfNeeded(Long sourceId, Long actorUserId) {
        IotDeviceSource source = sourceRepository.findById(sourceId).orElse(null);
        if (source == null
                || source.getStatus() != DeviceSourceStatus.ACTIVE
                || source.getProvider() != DeviceSourceProvider.INTUNE
                || !featureFlagService.isEnabled(
                        FeatureFlags.IOT_DEVICE_MANAGEMENT, source.getOrganizationId())
                || !featureFlagService.isEnabled(
                        FeatureFlags.IOT_PROVIDER_INTUNE, source.getOrganizationId())
                || !featureFlagService.isEnabled(
                        FeatureFlags.IOT_CERTIFICATE_PROFILE_MANAGEMENT, source.getOrganizationId())
                || eventRepository.existsByDeviceSourceIdAndEventType(
                sourceId, DeviceSourceEventType.PROFILE_SYNC_REQUESTED)) {
            return;
        }
        prepare(source, actorUserId, true);
    }

    private String prepare(IotDeviceSource source, Long actorUserId, boolean initial) {
        String requestXref = xref("profile_sync_");
        OffsetDateTime now = OffsetDateTime.now(clock);
        eventService.record(source, DeviceSourceEventType.PROFILE_SYNC_REQUESTED, "PENDING",
                Map.of("requestXref", requestXref, "initial", initial,
                        "actorUserId", actorUserId == null ? "SYSTEM" : actorUserId),
                now, requestXref, requestXref + ":requested");
        afterCommit(() -> dispatcher.publishDiscovery(source.getId(), requestXref));
        return requestXref;
    }

    private void validate(IotDeviceSource source) {
        if (source.getStatus() != DeviceSourceStatus.ACTIVE) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Device source must be ACTIVE");
        }
        if (source.getProvider() != DeviceSourceProvider.INTUNE) {
            throw new ResponseStatusException(HttpStatus.NOT_IMPLEMENTED,
                    "Profile discovery is not implemented for " + source.getProvider());
        }
        featureFlagService.assertEnabled(
                FeatureFlags.IOT_DEVICE_MANAGEMENT, source.getOrganizationId());
        featureFlagService.assertEnabled(
                FeatureFlags.IOT_PROVIDER_INTUNE, source.getOrganizationId());
        if (!featureFlagService.isEnabled(
                FeatureFlags.IOT_CERTIFICATE_PROFILE_MANAGEMENT, source.getOrganizationId())) {
            throw new ResponseStatusException(HttpStatus.LOCKED,
                    "IoT certificate profile management is disabled");
        }
    }

    private static void afterCommit(Runnable runnable) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            runnable.run();
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    runnable.run();
                } catch (Exception exception) {
                    log.warn("Profile sync remains pending after publish failure: {}",
                            exception.getMessage());
                }
            }
        });
    }

    private static String xref(String prefix) {
        return prefix + UUID.randomUUID().toString().replace("-", "");
    }
}
