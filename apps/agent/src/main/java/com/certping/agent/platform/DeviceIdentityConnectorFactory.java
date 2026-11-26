// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.DevicePlatformType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Resolves the {@link DeviceIdentityConnector} for a platform.
 *
 * <p>Connectors register themselves with {@link DeviceIdentityConnectorFor} — no switch here.
 * Mirrors {@code DiscoveryAdapterFactory}.
 */
@Slf4j
@Component
public class DeviceIdentityConnectorFactory {

    private final Map<DevicePlatformType, DeviceIdentityConnector> connectors;

    public DeviceIdentityConnectorFactory(List<DeviceIdentityConnector> connectorList) {
        connectors = new EnumMap<>(DevicePlatformType.class);
        for (DeviceIdentityConnector connector : connectorList) {
            DeviceIdentityConnectorFor annotation =
                    connector.getClass().getAnnotation(DeviceIdentityConnectorFor.class);
            if (annotation != null) {
                for (DevicePlatformType platform : annotation.value()) {
                    DeviceIdentityConnector existing = connectors.putIfAbsent(platform, connector);
                    if (existing != null) {
                        throw new IllegalStateException("Duplicate device identity connector for "
                                + platform + ": " + existing.getClass().getName() + " and "
                                + connector.getClass().getName());
                    }
                    log.debug("Registered device identity connector {} for platform={}",
                            connector.getClass().getSimpleName(), platform);
                }
            }
        }
        log.info("DeviceIdentityConnectorFactory initialised with {} platform mapping(s): {}",
                connectors.size(), connectors.keySet());
    }

    /**
     * @throws PermanentAgentException when nothing handles the platform. Permanent by design:
     *         retrying cannot make a connector appear, so the message is dead-lettered rather
     *         than churning the queue.
     */
    public DeviceIdentityConnector create(DevicePlatformType platform) {
        if (platform == null) {
            throw new PermanentAgentException("PLATFORM_NOT_CONFIGURED",
                    "Sync command carries no platformType");
        }
        DeviceIdentityConnector connector = connectors.get(platform);
        if (connector == null) {
            throw new PermanentAgentException("PLATFORM_NOT_SUPPORTED",
                    "No connector for platform " + platform + "; wired: " + connectors.keySet());
        }
        return connector;
    }
}
