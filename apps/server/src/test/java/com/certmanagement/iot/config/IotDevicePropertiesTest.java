// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.config;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IotDevicePropertiesTest {

    @Test
    void defaultsAreValid() {
        assertThatNoException().isThrownBy(new IotDeviceProperties()::validate);
    }

    @Test
    void zeroAndNegativeDurationsAreRejected() {
        assertInvalid(properties -> properties.setHealthStaleAfter(Duration.ZERO),
                "health-stale-after");
        assertInvalid(properties -> properties.setMaxAgentClockSkew(Duration.ofSeconds(-1)),
                "max-agent-clock-skew");
        assertInvalid(properties -> properties.setPendingSyncRetryAfter(Duration.ZERO),
                "pending-sync-retry-after");
        assertInvalid(properties -> properties.setRunningSyncTimeout(Duration.ZERO),
                "running-sync-timeout");
        assertInvalid(properties -> properties.setProfileResponseTimeout(Duration.ofMinutes(-1)),
                "profile-response-timeout");
        assertInvalid(properties -> properties.setSyncInterval(Duration.ZERO),
                "sync-interval");
    }

    private static void assertInvalid(
            java.util.function.Consumer<IotDeviceProperties> mutation, String propertyName) {
        IotDeviceProperties properties = new IotDeviceProperties();
        mutation.accept(properties);

        assertThatThrownBy(properties::validate)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("certping.iot." + propertyName)
                .hasMessageContaining("greater than zero");
    }
}
