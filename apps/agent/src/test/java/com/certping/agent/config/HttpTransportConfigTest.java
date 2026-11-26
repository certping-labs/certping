// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.config;

import com.certping.agent.listener.AgentMessageListener;
import com.certping.agent.transport.GatewayClient;
import com.certping.agent.transport.HttpMessageSender;
import com.certping.agent.transport.InboundConsumer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class HttpTransportConfigTest {

    private final ObjectMapper mapper = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void takesTheOrganizationFromTheTokenWhenNoneIsConfigured() throws Exception {
        GatewayClient client = mock(GatewayClient.class);
        when(client.whoami()).thenReturn(mapper.readTree("{\"organizationId\":\"42\"}"));
        AgentProperties properties = new AgentProperties();

        HttpTransportConfig.verifyOrganization(client, properties);

        assertThat(properties.getOrganizationId()).isEqualTo("42");
    }

    @Test
    void refusesATokenForAnotherOrganization() throws Exception {
        GatewayClient client = mock(GatewayClient.class);
        when(client.whoami()).thenReturn(mapper.readTree("{\"organizationId\":\"7\"}"));
        AgentProperties properties = new AgentProperties();
        properties.setOrganizationId("42");

        assertThatThrownBy(() -> HttpTransportConfig.verifyOrganization(client, properties))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("organization 7");
    }

    @Test
    void aRejectedTokenFailsStartupButAnUnreachableServerDoesNot() throws Exception {
        GatewayClient rejected = mock(GatewayClient.class);
        when(rejected.whoami()).thenThrow(new GatewayClient.GatewayException(401, "HTTP 401"));
        assertThatThrownBy(() -> HttpTransportConfig.verifyOrganization(rejected, new AgentProperties()))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("rejected");

        GatewayClient down = mock(GatewayClient.class);
        when(down.whoami()).thenThrow(new GatewayClient.GatewayException(0, "unreachable"));
        AgentProperties properties = new AgentProperties();
        properties.setOrganizationId("42");
        HttpTransportConfig.verifyOrganization(down, properties);
        assertThat(properties.getOrganizationId()).isEqualTo("42");

        GatewayClient matching = mock(GatewayClient.class);
        when(matching.whoami()).thenReturn(mapper.readTree("{\"organizationId\":\"42\"}"));
        HttpTransportConfig.verifyOrganization(matching, properties);
    }

    @Test
    void buildsTheHttpBeans() {
        HttpTransportConfig config = new HttpTransportConfig();
        GatewayClient client = mock(GatewayClient.class);
        AgentProperties properties = new AgentProperties();
        assertThat(config.outboundSender(client).getEntityPath()).isEqualTo("agent-gateway/outbound");
        assertThat(config.inboundSender(client)).isInstanceOf(HttpMessageSender.class);
        InboundConsumer consumer = config.inboundConsumer(client, properties, mock(AgentMessageListener.class));
        assertThat(consumer.isRunning()).isFalse();
        assertThatThrownBy(() -> config.gatewayClient(properties, mapper))
                .hasMessageContaining("CERTPING_SERVER_URL");
    }

    @Test
    void eightConcurrentJobsByDefault() throws Exception {
        assertThat(new AgentProperties().getTransport().getMaxConcurrentJobs()).isEqualTo(8);
        for (String file : new String[] {"application.yml"}) {
            try (var in = getClass().getClassLoader().getResourceAsStream(file)) {
                assertThat(new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8))
                        .as(file).contains("max-concurrent-jobs: ${CERTPING_AGENT_MAX_CONCURRENT_JOBS:8}");
            }
        }
    }
}
