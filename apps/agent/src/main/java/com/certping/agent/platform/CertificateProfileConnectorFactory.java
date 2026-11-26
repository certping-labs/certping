// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.DevicePlatformType;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

@Component
public class CertificateProfileConnectorFactory {
    private final Map<DevicePlatformType, CertificateProfileConnector> connectors;

    public CertificateProfileConnectorFactory(List<CertificateProfileConnector> candidates) {
        connectors = new EnumMap<>(DevicePlatformType.class);
        for (CertificateProfileConnector connector : candidates) {
            CertificateProfileConnectorFor annotation = connector.getClass()
                    .getAnnotation(CertificateProfileConnectorFor.class);
            if (annotation == null) {
                continue;
            }
            for (DevicePlatformType platform : annotation.value()) {
                if (connectors.putIfAbsent(platform, connector) != null) {
                    throw new IllegalStateException(
                            "Duplicate certificate-profile connector for " + platform);
                }
            }
        }
    }

    public CertificateProfileConnector create(DevicePlatformType platform) {
        CertificateProfileConnector connector = connectors.get(platform);
        if (connector == null) {
            throw new PermanentAgentException("PLATFORM_NOT_SUPPORTED",
                    "No certificate-profile connector for " + platform);
        }
        return connector;
    }
}
