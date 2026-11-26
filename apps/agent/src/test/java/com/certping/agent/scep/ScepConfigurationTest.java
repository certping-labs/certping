// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.platform.DeviceSourceCredentialRegistry;
import com.certping.agent.platform.DeviceSourceProfile;
import com.certping.agent.platform.DeviceSourceProfileRegistry;
import com.certping.agent.scep.ca.NoopScepCaBackend;
import com.certping.agent.scep.ca.ScepCaBackend;
import com.certping.agent.scep.intune.IntuneScepClient;
import com.certping.agent.scep.intune.IntuneScepValidator;
import com.certping.agent.scep.intune.MicrosoftIntuneScepValidator;
import com.certping.agent.scep.intune.NoopIntuneScepValidator;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.ssl.ejbca.EjbcaSigningService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.restclient.RestTemplateBuilder;

import java.time.Clock;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ScepConfigurationTest {

    private final ScepConfiguration config = new ScepConfiguration();

    @Test
    void buildsCoreBeans() {
        AgentProperties props = new AgentProperties();
        assertThat(config.pkiMessageCodec()).isNotNull();
        assertThat(config.scepTransactionStore(props)).isNotNull();
    }

    @Test
    void registryAndServiceWireTogether() {
        AgentProperties props = new AgentProperties();
        ScepCaBackend backend = new NoopScepCaBackend();
        DeviceSourceProfileRegistry sources = Mockito.mock(DeviceSourceProfileRegistry.class);
        Mockito.when(sources.all()).thenReturn(List.of(new DeviceSourceProfile(
                "intune-primary", DevicePlatformType.INTUNE, "ENDPOINT_MANAGEMENT",
                "Test Intune", null, Map.of())));
        ScepEndpointRegistry registry = config.scepEndpointRegistry(props, backend, sources);
        registry.bootstrap();
        ScepService service = config.scepService(registry, config.pkiMessageCodec(),
                new NoopIntuneScepValidator(), config.scepTransactionStore(props),
                Mockito.mock(AgentMessageSender.class), Clock.systemUTC(), ScepProfileHintResolver.NONE);
        assertThat(service.getCaCaps("intune-primary").body()).isNotEmpty();
    }

    @Test
    void disabledIntuneValidatorAlwaysFailsClosed() {
        AgentProperties props = new AgentProperties();
        assertThatThrownBy(() -> config.intuneScepValidator(props, intuneClient(),
                Mockito.mock(DeviceSourceCredentialRegistry.class), JsonMapper.builderWithJackson2Defaults().build()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("requires agent.scep.intune.enabled=true");
    }

    @Test
    void intuneValidatorIsMicrosoftWhenEnabledWithoutStaticTenantConfig() {
        // Tenant credentials come from the per-source credential registry at validation time, so
        // enabling the validator requires no static tenant/client/secret configuration.
        AgentProperties props = new AgentProperties();
        props.getScep().getIntune().setEnabled(true);

        IntuneScepValidator validator = config.intuneScepValidator(props, intuneClient(),
                Mockito.mock(DeviceSourceCredentialRegistry.class), JsonMapper.builderWithJackson2Defaults().build());

        assertThat(validator).isInstanceOf(MicrosoftIntuneScepValidator.class);
    }

    private IntuneScepClient intuneClient() {
        return new IntuneScepClient(new RestTemplateBuilder());
    }

    @Test
    void buildsEjbcaBackend() {
        AgentProperties properties = new AgentProperties();
        properties.getEjbca().setEnabled(true);
        ScepCaBackend backend = config.ejbcaScepCaBackend(
                Mockito.mock(EjbcaSigningService.class),
                Mockito.mock(com.certping.agent.ssl.ejbca.EjbcaRevocationService.class),
                Mockito.mock(SecretStore.class),
                properties, JsonMapper.builderWithJackson2Defaults().build());
        assertThat(backend).isNotNull();
    }

    @Test
    void rejectsDisabledEjbcaBackend() {
        assertThatThrownBy(() -> config.ejbcaScepCaBackend(
                Mockito.mock(EjbcaSigningService.class),
                Mockito.mock(com.certping.agent.ssl.ejbca.EjbcaRevocationService.class),
                Mockito.mock(SecretStore.class),
                new AgentProperties(), JsonMapper.builderWithJackson2Defaults().build()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("agent.ejbca.enabled=true");
    }
}
