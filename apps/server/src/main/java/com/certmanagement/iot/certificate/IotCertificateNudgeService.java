// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.config.IotDeviceSyncProperties;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.enums.DeviceSourceStatus;
import com.certmanagement.iot.messaging.IotDeviceSyncCommand;
import com.certmanagement.iot.profile.CertificateProfileConfiguration;
import com.certmanagement.iot.profile.CertificateProfileConfigurationRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.service.OrgTypeResolver;
import com.certmanagement.util.MdcIds;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/** Validates and dispatches operator-requested Intune device check-ins. */
@Slf4j
@Service
@RequiredArgsConstructor
public class IotCertificateNudgeService {
    private final IotDeviceCertificateRepository certificateRepository;
    private final IotDeviceSourceRepository sourceRepository;
    private final CertificateProfileConfigurationRepository configurationRepository;
    private final IotDeviceSyncSelectionService selectionService;
    private final IntuneRenewalEligibilityPolicy eligibilityPolicy;
    private final IotDeviceSyncRequestRecorder requestRecorder;
    private final IotDeviceSyncCommandPublisher commandPublisher;
    private final OrgTypeResolver orgTypeResolver;
    private final IotDeviceSyncProperties properties;
    private final Clock clock;

    @Transactional
    public DeviceSyncResponse requestDeviceSync(
            Long organizationId, boolean all, DeviceSyncRequest request) {
        IotDeviceSyncSelectionService.Selection selection =
                selectionService.select(organizationId, all, request);
        List<DeviceSyncResponse.DeviceResult> results = new ArrayList<>(selection.initialResults());
        if (selection.devices().isEmpty()) {
            return response(selection.selectedCount(), results);
        }

        OffsetDateTime now = OffsetDateTime.now(clock);
        Map<Long, List<IotDeviceCertificate>> certificatesByDevice = certificateRepository
                .findCurrentForDeviceSync(organizationId,
                        selection.devices().stream().map(IotDevice::getId).toList(), now)
                .stream().collect(Collectors.groupingBy(IotDeviceCertificate::getDeviceId));
        Map<Long, CertificateProfileConfiguration> configurations = configurations(
                certificatesByDevice.values().stream().flatMap(List::stream).toList());
        Map<Long, IotDeviceSource> sources = sources(selection.devices());

        List<IotDeviceSyncCommand> commands = new ArrayList<>();
        for (IotDevice device : selection.devices()) {
            DevicePreparation preparation = prepare(
                    organizationId, device, sources.get(device.getDeviceSourceId()),
                    certificatesByDevice.getOrDefault(device.getId(), List.of()),
                    configurations, now);
            results.add(preparation.result());
            if (preparation.command() != null) {
                commands.add(preparation.command());
            }
        }
        commandPublisher.publishAfterCommit(commands);
        // One line per API call, not per device: `all=true` on a large tenant selects every device,
        // and the per-device decision is already in each DeviceResult and its audit event.
        log.info("Device check-in requested: selected={} queued={} skipped={}",
                selection.selectedCount(), commands.size(),
                results.size() - commands.size());
        return response(selection.selectedCount(), results);
    }

    private DevicePreparation prepare(
            Long organizationId,
            IotDevice device,
            IotDeviceSource source,
            List<IotDeviceCertificate> certificates,
            Map<Long, CertificateProfileConfiguration> configurations,
            OffsetDateTime now) {
        if (!usableIntuneSource(source, organizationId)) {
            return skipped(device, "UNSUPPORTED_OR_INACTIVE_SOURCE", certificates, null);
        }
        String managedDeviceId = canonicalDeviceId(device.getSourceDeviceId());
        if (managedDeviceId == null) {
            return skipped(device, "NO_MANAGED_DEVICE_ID", certificates, null);
        }
        if (certificates.isEmpty()) {
            return skipped(device, "NO_CURRENT_CERTIFICATE", certificates, null);
        }

        IntuneRenewalEligibilityPolicy.Assessment assessment =
                eligibilityPolicy.assess(certificates, configurations, now);
        if (assessment.eligible().isEmpty()) {
            String reason = assessment.hasThreshold()
                    ? "OUTSIDE_RENEWAL_THRESHOLD" : "PROFILE_THRESHOLD_UNAVAILABLE";
            return skipped(device, reason, certificates, assessment.earliestDueAt());
        }

        OffsetDateTime nextAllowedAt = latestNudge(assessment.eligible());
        if (nextAllowedAt != null) {
            nextAllowedAt = nextAllowedAt.plus(properties.getCooldown());
        }
        if (nextAllowedAt != null && now.isBefore(nextAllowedAt)) {
            return skipped(device, "COOLDOWN_ACTIVE", assessment.eligible().stream()
                    .map(IntuneRenewalEligibilityPolicy.EligibleCertificate::certificate).toList(),
                    nextAllowedAt);
        }

        IotDeviceSyncCommand command = command(
                organizationId, device, source, managedDeviceId, assessment, now);
        assessment.eligible().forEach(item ->
                requestRecorder.record(item, command.getRequestId(), now));
        return new DevicePreparation(command, result(
                device, "QUEUED", null, command.getCertificateXrefs(), null));
    }

    private IotDeviceSyncCommand command(
            Long organizationId,
            IotDevice device,
            IotDeviceSource source,
            String managedDeviceId,
            IntuneRenewalEligibilityPolicy.Assessment assessment,
            OffsetDateTime now) {
        return IotDeviceSyncCommand.builder()
                .requestId("req-iot-device-sync-" + UUID.randomUUID().toString().replace("-", ""))
                .correlationId(MdcIds.correlationId())
                .organizationId(String.valueOf(organizationId))
                .orgType(orgTypeResolver.resolve(organizationId))
                .sourceXref(source.getSourceXref())
                .provider(source.getProvider().name())
                .connectionProfileRef(source.getConnectionProfileRef())
                .managedDeviceId(managedDeviceId)
                .deviceXref(device.getDeviceXref())
                .certificateXrefs(certificates(assessment))
                .reason("MANUAL_RENEWAL_SYNC")
                .requestedAt(now.toString())
                .build();
    }

    private Map<Long, CertificateProfileConfiguration> configurations(
            List<IotDeviceCertificate> certificates) {
        List<Long> profileIds = certificates.stream().map(IotDeviceCertificate::getProfileId)
                .filter(Objects::nonNull).distinct().toList();
        return configurationRepository.findAllById(profileIds).stream().collect(Collectors.toMap(
                CertificateProfileConfiguration::getProfileId, Function.identity()));
    }

    private Map<Long, IotDeviceSource> sources(List<IotDevice> devices) {
        return sourceRepository.findAllById(devices.stream()
                        .map(IotDevice::getDeviceSourceId).distinct().toList())
                .stream().collect(Collectors.toMap(IotDeviceSource::getId, Function.identity()));
    }

    private static OffsetDateTime latestNudge(
            List<IntuneRenewalEligibilityPolicy.EligibleCertificate> certificates) {
        return certificates.stream().map(item -> item.certificate().getLastNudgedAt())
                .filter(Objects::nonNull).max(OffsetDateTime::compareTo).orElse(null);
    }

    private static List<String> certificates(IntuneRenewalEligibilityPolicy.Assessment assessment) {
        return assessment.eligible().stream()
                .map(item -> item.certificate().getCertificateXref()).toList();
    }

    private static boolean usableIntuneSource(IotDeviceSource source, Long organizationId) {
        return source != null && Objects.equals(source.getOrganizationId(), organizationId)
                && source.getProvider() == DeviceSourceProvider.INTUNE
                && source.getStatus() == DeviceSourceStatus.ACTIVE;
    }

    private static String canonicalDeviceId(String value) {
        try {
            return UUID.fromString(value == null ? "" : value.trim()).toString();
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    private static DevicePreparation skipped(
            IotDevice device, String reason, List<IotDeviceCertificate> certificates,
            OffsetDateTime nextAllowedAt) {
        return new DevicePreparation(null, result(device, "SKIPPED", reason,
                certificates.stream().map(IotDeviceCertificate::getCertificateXref).toList(),
                nextAllowedAt));
    }

    private static DeviceSyncResponse.DeviceResult result(
            IotDevice device, String status, String reason,
            List<String> certificateXrefs, OffsetDateTime nextAllowedAt) {
        return new DeviceSyncResponse.DeviceResult(
                device.getDeviceXref(), status, reason, certificateXrefs, nextAllowedAt);
    }

    private static DeviceSyncResponse response(
            int selectedDevices, List<DeviceSyncResponse.DeviceResult> results) {
        int queued = (int) results.stream().filter(result -> "QUEUED".equals(result.status())).count();
        return new DeviceSyncResponse(selectedDevices, queued, results.size() - queued, results);
    }

    private record DevicePreparation(
            IotDeviceSyncCommand command, DeviceSyncResponse.DeviceResult result) {}
}
