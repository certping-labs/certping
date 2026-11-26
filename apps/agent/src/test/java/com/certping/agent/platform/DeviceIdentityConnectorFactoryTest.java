// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform;

import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.model.message.DeviceIdentityEntry;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DeviceIdentityConnectorFactoryTest {

    @Test
    void duplicatePlatformRegistrationFailsStartupDeterministically() {
        assertThatThrownBy(() -> new DeviceIdentityConnectorFactory(
                List.of(new FirstIntuneConnector(), new SecondIntuneConnector())))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Duplicate device identity connector for INTUNE")
                .hasMessageContaining(FirstIntuneConnector.class.getName())
                .hasMessageContaining(SecondIntuneConnector.class.getName());
    }

    @DeviceIdentityConnectorFor(DevicePlatformType.INTUNE)
    private static final class FirstIntuneConnector implements DeviceIdentityConnector {
        @Override public int testConnection(DeviceSourceProfile profile) { return 0; }
        @Override public void streamDevices(
                DeviceSourceProfile profile, Consumer<List<DeviceIdentityEntry>> pageConsumer) { }
    }

    @DeviceIdentityConnectorFor(DevicePlatformType.INTUNE)
    private static final class SecondIntuneConnector implements DeviceIdentityConnector {
        @Override public int testConnection(DeviceSourceProfile profile) { return 0; }
        @Override public void streamDevices(
                DeviceSourceProfile profile, Consumer<List<DeviceIdentityEntry>> pageConsumer) { }
    }
}
