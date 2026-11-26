// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.adapter;

import com.certmanagement.iot.adapter.intune.IntunePlatformAdapter;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.validation.DeviceFieldNormalizer;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PlatformAdapterFactoryTest {
    private final PlatformAdapterFactory factory = new PlatformAdapterFactory(
            List.of(new IntunePlatformAdapter(new DeviceFieldNormalizer())));

    @Test
    void resolvesOnlyRegisteredProviders() {
        assertThat(factory.getAdapter(DeviceSourceProvider.INTUNE))
                .isInstanceOf(IntunePlatformAdapter.class);
        assertThat(factory.isSupported(DeviceSourceProvider.INTUNE)).isTrue();
        assertThat(factory.isSupported(DeviceSourceProvider.JAMF)).isFalse();
        assertThat(factory.supported()).containsExactly(DeviceSourceProvider.INTUNE);
    }

    @Test
    void rejectsAnUnwiredProviderWithoutFallback() {
        assertThatThrownBy(() -> factory.getAdapter(DeviceSourceProvider.JAMF))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("No connector for provider JAMF")
                .hasMessageContaining("INTUNE");
    }
}
