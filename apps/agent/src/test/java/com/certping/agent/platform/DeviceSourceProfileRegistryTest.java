// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.DevicePlatformType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DeviceSourceProfileRegistryTest {

    @Test
    void validatesMultipleProfilesWithoutExposingCredentialsThroughSafeProfiles() {
        DeviceSourceProperties properties = new DeviceSourceProperties();
        properties.setProfiles(List.of(
                profile("intune-primary", "INTUNE", credentials("tenant-one", "secret-one")),
                profile("intune-secondary", "INTUNE", credentials("tenant-two", "secret-two"))));
        DeviceSourceProfileRegistry registry = registry(properties);

        registry.validateProfiles();

        assertThat(registry.all()).extracting(DeviceSourceProfile::profileRef)
                .containsExactly("intune-primary", "intune-secondary");
        assertThat(registry.all().toString()).doesNotContain("secret-one", "secret-two");
    }

    @Test
    void rejectsDuplicateProfileReferences() {
        DeviceSourceProperties properties = new DeviceSourceProperties();
        properties.setProfiles(List.of(
                profile("duplicate", "INTUNE", credentials("tenant-one", "secret-one")),
                profile("duplicate", "INTUNE", credentials("tenant-two", "secret-two"))));
        DeviceSourceProfileRegistry registry = registry(properties);

        assertThatThrownBy(registry::validateProfiles)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Duplicate");
    }

    @Test
    void rejectsACommandWhoseProviderDoesNotMatchTheLocalProfile() {
        DeviceSourceProperties properties = new DeviceSourceProperties();
        properties.setProfiles(List.of(profile(
                "primary", "INTUNE", credentials("tenant", "secret"))));
        DeviceSourceProfileRegistry registry = registry(properties);
        registry.validateProfiles();

        assertThatThrownBy(() -> registry.require("primary", DevicePlatformType.JAMF))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("does not match");
    }

    @Test
    void exposesOnlyConfiguredSafeMetadataLabels() {
        DeviceSourceProperties.Profile profile = profile(
                "primary", "INTUNE", credentials("tenant", "secret"));
        DeviceSourceProperties.Metadata metadata = new DeviceSourceProperties.Metadata();
        metadata.setCloud(" public ");
        metadata.setEnvironment("production");
        metadata.setTenantLabel("Contoso Europe");
        profile.setMetadata(metadata);
        DeviceSourceProperties properties = new DeviceSourceProperties();
        properties.setProfiles(List.of(profile));
        DeviceSourceProfileRegistry registry = registry(properties);

        registry.validateProfiles();

        assertThat(registry.all().getFirst().metadata()).containsExactlyInAnyOrderEntriesOf(
                java.util.Map.of(
                        "apiHost", "graph.microsoft.com",
                        "cloud", "AZURE_PUBLIC",
                        "environment", "production",
                        "tenantLabel", "Contoso Europe"));
    }

    @Test
    void intuneAlwaysAdvertisesTheEndpointItActuallyUses() {
        DeviceSourceProperties properties = new DeviceSourceProperties();
        properties.setProfiles(List.of(profile(
                "primary", "INTUNE", credentials("tenant", "secret"))));
        DeviceSourceProfileRegistry registry = registry(properties);

        registry.validateProfiles();

        assertThat(registry.all().getFirst().metadata()).containsExactlyInAnyOrderEntriesOf(
                java.util.Map.of(
                        "apiHost", "graph.microsoft.com",
                        "cloud", "AZURE_PUBLIC"));
    }

    @Test
    void intuneRejectsSovereignMetadataUntilEndpointRoutingExists() {
        DeviceSourceProperties.Profile profile = profile(
                "primary", "INTUNE", credentials("tenant", "secret"));
        profile.getMetadata().setCloud("AZURE_US_GOV");
        DeviceSourceProperties properties = new DeviceSourceProperties();
        properties.setProfiles(List.of(profile));

        assertThatThrownBy(() -> registry(properties).validateProfiles())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("must use cloud AZURE_PUBLIC");
    }

    private static DeviceSourceProperties.Profile profile(
            String reference, String provider, String credentialsJson) {
        DeviceSourceProperties.Profile profile = new DeviceSourceProperties.Profile();
        profile.setProfileRef(reference);
        profile.setProvider(provider);
        profile.setSourceCategory("ENDPOINT_MANAGEMENT");
        profile.setDisplayName(reference);
        profile.setCredentialsJson(credentialsJson);
        return profile;
    }

    private static DeviceSourceProfileRegistry registry(DeviceSourceProperties properties) {
        return new DeviceSourceProfileRegistry(properties);
    }

    private static String credentials(String tenantId, String clientSecret) {
        return "{\"tenantId\":\"" + tenantId + "\",\"clientId\":\"client\","
                + "\"clientSecret\":\"" + clientSecret + "\"}";
    }
}
