// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.profile;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateProfileJsonCodecTest {
    private final CertificateProfileJsonCodec codec =
            new CertificateProfileJsonCodec(JsonMapper.builderWithJackson2Defaults().build());

    @Test
    void requestJsonRejectsSensitiveFieldsInsteadOfSilentlyDroppingThem() {
        assertThatThrownBy(() -> codec.writeRequest(Map.of(
                "provider", Map.of("clientSecret", "must-not-be-stored"))))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("forbidden sensitive field");
    }

    @Test
    void oversizedProviderSnapshotUsesABoundedMarker() {
        String stored = codec.writeProviderSnapshot(Map.of("payload", "x".repeat(70_000)));

        assertThat(codec.readObject(stored))
                .containsEntry("truncated", true)
                .containsKey("sanitizedBytes")
                .doesNotContainKey("payload");
        assertThat(stored.length()).isLessThan(256);
    }

    @Test
    void providerSnapshotRemovesSensitiveFields() {
        String stored = codec.writeProviderSnapshot(Map.of(
                "id", "native-1",
                "nested", Map.of("accessToken", "must-not-be-stored")));

        assertThat(codec.readObject(stored))
                .containsEntry("id", "native-1")
                .containsEntry("nested", Map.of());
    }
}
