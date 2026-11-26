// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DeviceSourcePropertiesBindingTest {

    @Test
    void bindsSafeMetadataFromIndexedProfileProperties() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new SystemEnvironmentPropertySource(
                StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                Map.of(
                        "AGENT_DEVICE_SOURCES_PROFILES_0_PROFILE_REF", "intune-primary",
                        "AGENT_DEVICE_SOURCES_PROFILES_0_PROVIDER", "INTUNE",
                        "AGENT_DEVICE_SOURCES_PROFILES_0_DISPLAY_NAME", "Intune Production",
                        "AGENT_DEVICE_SOURCES_PROFILES_0_CREDENTIALS_JSON",
                        "{\"tenantId\":\"tenant\",\"clientId\":\"client\","
                                + "\"clientSecret\":\"secret\"}",
                        "AGENT_DEVICE_SOURCES_PROFILES_0_METADATA_CLOUD", "public",
                        "AGENT_DEVICE_SOURCES_PROFILES_0_METADATA_ENVIRONMENT", "production",
                        "AGENT_DEVICE_SOURCES_PROFILES_0_METADATA_TENANT_LABEL", "Contoso Europe")));

        DeviceSourceProperties properties = Binder.get(environment)
                .bind("agent.device-sources", Bindable.of(DeviceSourceProperties.class))
                .orElseThrow(() -> new AssertionError("device-source properties were not bound"));

        assertThat(properties.getProfiles()).hasSize(1);
        assertThat(properties.getProfiles().getFirst().getCredentialsJson())
                .contains("\"tenantId\":\"tenant\"");
        DeviceSourceProperties.Metadata metadata = properties.getProfiles().getFirst().getMetadata();
        assertThat(metadata.getCloud()).isEqualTo("public");
        assertThat(metadata.getEnvironment()).isEqualTo("production");
        assertThat(metadata.getTenantLabel()).isEqualTo("Contoso Europe");
        assertThat(properties.toString()).doesNotContain("clientSecret", "secret");
    }
}
