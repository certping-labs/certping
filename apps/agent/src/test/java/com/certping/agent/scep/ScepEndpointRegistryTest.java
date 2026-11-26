// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.platform.DeviceSourceProfile;
import com.certping.agent.platform.DeviceSourceProfileRegistry;
import com.certping.agent.scep.ca.NoopScepCaBackend;
import com.certping.agent.scep.ca.ScepCaBackend;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Source-scoped endpoint registration and the fail-closed rules of the default alias. */
class ScepEndpointRegistryTest {

    private final ScepCaBackend backend = new NoopScepCaBackend();

    private static DeviceSourceProfile intuneSource(String profileRef) {
        return new DeviceSourceProfile(profileRef, DevicePlatformType.INTUNE,
                "ENDPOINT_MANAGEMENT", "Intune " + profileRef, null, Map.of());
    }

    private static DeviceSourceProfile awsSource(String profileRef) {
        return new DeviceSourceProfile(profileRef, DevicePlatformType.AWS_IOT,
                "IOT_REGISTRY", "AWS " + profileRef, null, Map.of());
    }

    private ScepEndpointRegistry registry(AgentProperties props, DeviceSourceProfile... sources) {
        DeviceSourceProfileRegistry sourceRegistry = Mockito.mock(DeviceSourceProfileRegistry.class);
        Mockito.when(sourceRegistry.all()).thenReturn(List.of(sources));
        ScepEndpointRegistry registry = new ScepEndpointRegistry(props, backend, sourceRegistry);
        registry.bootstrap();
        return registry;
    }

    private static AgentProperties properties() {
        AgentProperties props = new AgentProperties();
        props.setOrganizationId("42");
        return props;
    }

    @Test
    void registersOneEndpointPerIntuneSourceKeyedByProfileRef() {
        ScepEndpointRegistry registry = registry(properties(),
                intuneSource("intune-primary"), intuneSource("intune-emea"));

        ResolvedEndpoint primary = registry.resolve("intune-primary");
        assertThat(primary.connectionProfileRef()).isEqualTo("intune-primary");
        assertThat(primary.organizationId()).isEqualTo("42");
        assertThat(primary.provider()).isEqualTo(DevicePlatformType.INTUNE);
        assertThat(registry.resolve("intune-emea").connectionProfileRef()).isEqualTo("intune-emea");
    }

    @Test
    void nonIntuneSourcesDoNotGetScepEndpoints() {
        ScepEndpointRegistry registry = registry(properties(),
                intuneSource("intune-primary"), awsSource("aws-fleet"));

        assertThatThrownBy(() -> registry.resolve("aws-fleet"))
                .isInstanceOf(UnknownEndpointException.class);
    }

    @Test
    void defaultAliasResolvesToTheOnlyIntuneSource() {
        ScepEndpointRegistry registry = registry(properties(), intuneSource("intune-primary"));

        ResolvedEndpoint alias = registry.resolve("default");
        assertThat(alias.endpointId()).isEqualTo("default");
        // Messages published through the alias still carry the real source identity.
        assertThat(alias.connectionProfileRef()).isEqualTo("intune-primary");
    }

    @Test
    void defaultAliasIsNotCreatedWithSeveralIntuneSources() {
        // With more than one tenant the alias would have to guess which credential validates a
        // challenge — it must fail closed instead.
        ScepEndpointRegistry registry = registry(properties(),
                intuneSource("intune-primary"), intuneSource("intune-emea"));

        assertThatThrownBy(() -> registry.resolve("default"))
                .isInstanceOf(UnknownEndpointException.class);
    }

    @Test
    void defaultAliasCanBeDisabled() {
        AgentProperties props = properties();
        props.getScep().setDefaultCompatibilityAlias(false);
        ScepEndpointRegistry registry = registry(props, intuneSource("intune-primary"));

        assertThatThrownBy(() -> registry.resolve("default"))
                .isInstanceOf(UnknownEndpointException.class);
    }

    @Test
    void aliasNeverShadowsARealSourceNamedDefault() {
        ScepEndpointRegistry registry = registry(properties(), intuneSource("default"));

        assertThat(registry.resolve("default").connectionProfileRef()).isEqualTo("default");
    }

    @Test
    void noSourcesMeansEveryRouteIsRejected() {
        ScepEndpointRegistry registry = registry(properties());

        assertThatThrownBy(() -> registry.resolve("default"))
                .isInstanceOf(UnknownEndpointException.class);
        assertThatThrownBy(() -> registry.resolve("intune-primary"))
                .isInstanceOf(UnknownEndpointException.class);
    }
}
