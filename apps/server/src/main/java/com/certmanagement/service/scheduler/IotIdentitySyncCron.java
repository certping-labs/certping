// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.adapter.PlatformAdapterFactory;
import com.certmanagement.iot.config.IotDeviceProperties;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.service.IotSyncOrchestrationService;
import com.certmanagement.service.FeatureFlagService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Server-side dispatcher. It drains retries frequently while limiting normal source syncs to hourly. */
@Slf4j
@Service
@CronJobFor("trigger-iot-identity-sync")
@RequiredArgsConstructor
public class IotIdentitySyncCron implements DrainableCron {
    private final IotDeviceSourceRepository sourceRepository;
    private final IotSyncOrchestrationService orchestrationService;
    private final PlatformAdapterFactory adapterFactory;
    private final FeatureFlagService featureFlagService;
    private final IotDeviceProperties properties;
    private final Clock clock;
    private final Set<Long> attemptedInCurrentDrain = ConcurrentHashMap.newKeySet();

    @Override
    @Transactional
    public boolean tryProcessOneEligible() {
        List<String> providers = adapterFactory.supported().stream().map(Enum::name).toList();
        if (providers.isEmpty()) {
            return false;
        }
        OffsetDateTime now = OffsetDateTime.now(clock);
        OffsetDateTime pendingBefore = now.minus(properties.getPendingSyncRetryAfter());
        OffsetDateTime runningBefore = now.minus(properties.getRunningSyncTimeout());
        OffsetDateTime dueBefore = now.minus(properties.getSyncInterval());
        OffsetDateTime healthFreshAfter = now.minus(properties.getHealthStaleAfter());
        List<Long> exclusions = attemptedInCurrentDrain.isEmpty()
                ? List.of(-1L) : List.copyOf(attemptedInCurrentDrain);
        Optional<IotDeviceSource> claimed = sourceRepository.claimOneForSync(
                pendingBefore, runningBefore, dueBefore, healthFreshAfter, providers, exclusions);
        if (claimed.isEmpty()) {
            attemptedInCurrentDrain.clear();
            return false;
        }
        IotDeviceSource source = claimed.get();
        attemptedInCurrentDrain.add(source.getId());
        if (!featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, source.getOrganizationId())) {
            return true;
        }
        try {
            orchestrationService.startScheduledSync(
                    source.getOrganizationId(), source.getSourceXref());
            log.info("[IotIdentitySyncCron] Dispatched sync: source={} org={}",
                    source.getSourceXref(), source.getOrganizationId());
        } catch (Exception exception) {
            log.error("[IotIdentitySyncCron] Failed for source={} org={}: {}",
                    source.getSourceXref(), source.getOrganizationId(), exception.getMessage(), exception);
        }
        return true;
    }
}
