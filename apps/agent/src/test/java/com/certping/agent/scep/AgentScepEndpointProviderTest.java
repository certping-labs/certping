// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.platform.DeviceSourceProfile;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AgentScepEndpointProviderTest {

    private static final DeviceSourceProfile SOURCE = new DeviceSourceProfile(
            "intune-primary", DevicePlatformType.INTUNE, "ENDPOINT_MANAGEMENT",
            "Test Intune", null, Map.of());

    private static AgentProperties enabled(String publicBaseUrl) {
        AgentProperties props = new AgentProperties();
        props.getScep().setEnabled(true);
        props.getScep().setPublicBaseUrl(publicBaseUrl);
        return props;
    }

    @Test
    void advertisesTheSourceUrlUnderThePublicBase() {
        AgentScepEndpointProvider provider =
                new AgentScepEndpointProvider(enabled("https://agent.acme.example"));

        assertThat(provider.requireAdvertisedUrls(SOURCE))
                .containsExactly("https://agent.acme.example/scep/v1/intune-primary");
    }

    @Test
    void trailingSlashesOnTheBaseUrlAreNormalized() {
        AgentScepEndpointProvider provider =
                new AgentScepEndpointProvider(enabled("https://agent.acme.example//"));

        assertThat(provider.requireAdvertisedUrls(SOURCE))
                .containsExactly("https://agent.acme.example/scep/v1/intune-primary");
    }

    @Test
    void failsWhenScepIsDisabled() {
        AgentProperties props = enabled("https://agent.acme.example");
        props.getScep().setEnabled(false);

        assertThatThrownBy(() -> new AgentScepEndpointProvider(props).requireAdvertisedUrls(SOURCE))
                .isInstanceOfSatisfying(PermanentAgentException.class, error ->
                        assertThat(error.getErrorCode()).isEqualTo("SCEP_ENDPOINT_NOT_CONFIGURED"));
    }

    @Test
    void failsWhenNoPublicBaseUrlIsConfigured() {
        assertThatThrownBy(() -> new AgentScepEndpointProvider(enabled(" "))
                .requireAdvertisedUrls(SOURCE))
                .isInstanceOfSatisfying(PermanentAgentException.class, error ->
                        assertThat(error.getErrorCode()).isEqualTo("SCEP_ENDPOINT_NOT_CONFIGURED"));
    }

    @Test
    void failsWithoutASource() {
        assertThatThrownBy(() -> new AgentScepEndpointProvider(
                enabled("https://agent.acme.example")).requireAdvertisedUrls(null))
                .isInstanceOfSatisfying(PermanentAgentException.class, error ->
                        assertThat(error.getErrorCode()).isEqualTo("SCEP_ENDPOINT_NOT_CONFIGURED"));
    }
}
