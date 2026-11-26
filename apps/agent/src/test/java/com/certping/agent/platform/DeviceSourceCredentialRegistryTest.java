// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform;

import com.certping.agent.model.enums.DevicePlatformType;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DeviceSourceCredentialRegistryTest {

    @Test
    void isolatesCredentialsByProfileReference() {
        DeviceSourceProperties properties = properties(
                profile("intune-primary", credentials("tenant-one", "secret-one")),
                profile("intune-secondary", credentials("tenant-two", "secret-two")));
        DeviceSourceCredentialRegistry registry = registry(properties);

        assertThat(registry.requireCredentialsJson(
                "intune-secondary", DevicePlatformType.INTUNE))
                .contains("tenant-two", "secret-two")
                .doesNotContain("tenant-one", "secret-one");
    }

    @Test
    void rejectsMalformedCredentialsWithoutEchoingTheirValue() {
        DeviceSourceProperties properties = properties(
                profile("primary", "not-json-super-secret"));

        assertThatThrownBy(() -> registry(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not valid JSON")
                .hasMessageNotContaining("not-json-super-secret")
                .hasNoCause();
    }

    @Test
    void rejectsAProfileWithoutEnvironmentCredentials() {
        DeviceSourceProperties properties = properties(profile("primary", null));

        assertThatThrownBy(() -> registry(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("credentials-json is required");
    }

    @Test
    void rejectsMissingIntuneCredentialFieldsAtStartup() {
        DeviceSourceProperties properties = properties(
                profile("primary", "{\"tenantId\":\"tenant\"}"));

        assertThatThrownBy(() -> registry(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("clientId");
    }

    @Test
    void rejectsLegacyScepFieldsInCredentialJson() {
        DeviceSourceProperties properties = properties(profile(
                "primary",
                "{\"tenantId\":\"tenant\",\"clientId\":\"client\","
                        + "\"clientSecret\":\"secret\","
                        + "\"scepServerUrl\":\"https://scep.example.test\"}"));

        assertThatThrownBy(() -> registry(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("unsupported field scepServerUrl")
                .hasMessageNotContaining("https://scep.example.test");
    }

    @Test
    void rejectsOversizedCredentialJsonBeforeParsing() {
        DeviceSourceProperties properties = properties(profile(
                "primary",
                "x".repeat(DeviceSourceCredentialRegistry.MAX_CREDENTIALS_JSON_CHARACTERS + 1)));

        assertThatThrownBy(() -> registry(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("exceeds");
    }

    private static DeviceSourceCredentialRegistry registry(DeviceSourceProperties properties) {
        DeviceSourceProfileRegistry profiles = new DeviceSourceProfileRegistry(properties);
        profiles.validateProfiles();
        DeviceSourceCredentialRegistry credentials = new DeviceSourceCredentialRegistry(
                properties, JsonMapper.builderWithJackson2Defaults().build(), profiles);
        credentials.validateCredentials();
        return credentials;
    }

    private static DeviceSourceProperties properties(DeviceSourceProperties.Profile... profiles) {
        DeviceSourceProperties properties = new DeviceSourceProperties();
        properties.setProfiles(List.of(profiles));
        return properties;
    }

    private static DeviceSourceProperties.Profile profile(
            String reference, String credentialsJson) {
        DeviceSourceProperties.Profile profile = new DeviceSourceProperties.Profile();
        profile.setProfileRef(reference);
        profile.setProvider("INTUNE");
        profile.setSourceCategory("ENDPOINT_MANAGEMENT");
        profile.setDisplayName(reference);
        profile.setCredentialsJson(credentialsJson);
        return profile;
    }

    private static String credentials(String tenantId, String clientSecret) {
        return "{\"tenantId\":\"" + tenantId + "\",\"clientId\":\"client\","
                + "\"clientSecret\":\"" + clientSecret + "\"}";
    }
}
