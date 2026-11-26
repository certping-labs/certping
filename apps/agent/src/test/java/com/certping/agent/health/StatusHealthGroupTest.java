// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health;

import com.certping.agent.config.InboundConsumerLifecycle;
import com.certping.agent.transport.GatewayClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.health.autoconfigure.application.AvailabilityHealthContributorAutoConfiguration;
import org.springframework.boot.health.autoconfigure.actuate.endpoint.AvailabilityProbesAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.endpoint.EndpointAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.endpoint.web.WebEndpointAutoConfiguration;
import org.springframework.boot.health.autoconfigure.contributor.HealthContributorAutoConfiguration;
import org.springframework.boot.health.autoconfigure.registry.HealthContributorRegistryAutoConfiguration;
import org.springframework.boot.health.autoconfigure.actuate.endpoint.HealthEndpointAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.web.server.ManagementContextAutoConfiguration;
import org.springframework.boot.servlet.autoconfigure.actuate.web.ServletManagementContextAutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.availability.ApplicationAvailabilityAutoConfiguration;
import org.springframework.boot.http.converter.autoconfigure.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.health.actuate.endpoint.HealthEndpointGroups;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.webmvc.autoconfigure.DispatcherServletAutoConfiguration;
import org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Loads the real application.yml management settings over the actuator auto-configuration. */
@SpringBootTest(classes = StatusHealthGroupTest.Actuator.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class StatusHealthGroupTest {

    @SpringBootConfiguration
    @ImportAutoConfiguration({
            JacksonAutoConfiguration.class,
            HttpMessageConvertersAutoConfiguration.class,
            DispatcherServletAutoConfiguration.class,
            WebMvcAutoConfiguration.class,
            ApplicationAvailabilityAutoConfiguration.class,
            EndpointAutoConfiguration.class,
            WebEndpointAutoConfiguration.class,
            HealthContributorAutoConfiguration.class,
            HealthContributorRegistryAutoConfiguration.class,
            HealthEndpointAutoConfiguration.class,
            AvailabilityHealthContributorAutoConfiguration.class,
            AvailabilityProbesAutoConfiguration.class,
            ManagementContextAutoConfiguration.class,
            ServletManagementContextAutoConfiguration.class})
    static class Actuator {

        @Bean
        InboundConsumerLifecycle inboundConsumer() {
            return mock(InboundConsumerLifecycle.class);
        }

        @Bean
        AgentHealthIndicator agentHealthIndicator(InboundConsumerLifecycle inboundConsumer) {
            return new AgentHealthIndicator(inboundConsumer);
        }

        @Bean
        GatewayClient gatewayClient() {
            return mock(GatewayClient.class);
        }

        @Bean
        GatewayAuthHealthIndicator gatewayAuthHealthIndicator(GatewayClient gatewayClient) {
            return new GatewayAuthHealthIndicator(gatewayClient);
        }
    }

    @Autowired private MockMvc mvc;
    @Autowired private InboundConsumerLifecycle inboundConsumer;
    @Autowired private HealthEndpointGroups groups;
    @Autowired private GatewayClient gatewayClient;

    @BeforeEach
    void resetRegistry() {
        reset(inboundConsumer, gatewayClient);
        when(gatewayClient.tokenRejection()).thenReturn(Optional.empty());
    }

    @Test
    void rejectedTokenTakesReadinessDownButNotLiveness() throws Exception {
        when(inboundConsumer.isRunning()).thenReturn(true);
        when(inboundConsumer.states()).thenReturn(Map.of());
        mvc.perform(get("/actuator/health/readiness")).andExpect(status().isOk());

        when(gatewayClient.tokenRejection()).thenReturn(Optional.of("agent gateway returned HTTP 401"));

        mvc.perform(get("/actuator/health/readiness")).andExpect(status().isServiceUnavailable());
        mvc.perform(get("/actuator/health/liveness")).andExpect(status().isOk());
        mvc.perform(get("/actuator/health/status")).andExpect(status().isOk());
    }

    @Test
    void statusIsUpWithOnlyTheStatusWhileTheProcessorRuns() throws Exception {
        when(inboundConsumer.isRunning()).thenReturn(true);
        when(inboundConsumer.states()).thenReturn(Map.of("inboundConsumer", "RUNNING"));

        mvc.perform(get("/actuator/health/status"))
                .andExpect(status().isOk())
                .andExpect(content().json("{\"status\":\"UP\"}", true));
    }

    @Test
    void statusIsDownWithOnlyTheStatusWhenTheProcessorStopped() throws Exception {
        when(inboundConsumer.isRunning()).thenReturn(false);
        when(inboundConsumer.states()).thenReturn(Map.of("inboundConsumer", "STOPPED"));

        mvc.perform(get("/actuator/health/status"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(content().json("{\"status\":\"DOWN\"}", true));
    }

    @Test
    void statusIsDownWithoutTheErrorWhenTheRegistryThrows() throws Exception {
        when(inboundConsumer.isRunning()).thenThrow(new IllegalStateException("queue=agent-inbound-internal"));

        String body = mvc.perform(get("/actuator/health/status"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(content().json("{\"status\":\"DOWN\"}", true))
                .andReturn().getResponse().getContentAsString();

        assertThat(body).doesNotContain("agent-inbound-internal");
    }

    @Test
    void statusGroupHoldsOnlyTheAgentAndProbeGroupsStayAsTheyWere() {
        assertThat(groups.get("status").isMember("agent")).isTrue();
        assertThat(groups.get("status").isMember("livenessState")).isFalse();
        assertThat(groups.get("status").isMember("readinessState")).isFalse();
        assertThat(groups.get("liveness").isMember("agent")).isFalse();
        assertThat(groups.get("readiness").isMember("agent")).isFalse();
    }
}
