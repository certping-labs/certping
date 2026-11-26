// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.config;

import com.certping.agent.listener.AgentMessageListener;
import com.certping.agent.transport.GatewayClient;
import com.certping.agent.transport.HttpInboundConsumer;
import com.certping.agent.transport.HttpMessageSender;
import com.certping.agent.transport.InboundConsumer;
import com.certping.agent.transport.MessageSender;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;

/**
 * The agent connects to the CertPing server over outbound HTTPS with an
 * agent token. No message broker, no inbound port.
 */
@Slf4j
@Configuration
public class HttpTransportConfig {

    @Bean
    public GatewayClient gatewayClient(AgentProperties properties, ObjectMapper objectMapper) {
        AgentProperties.TransportProperties t = properties.getTransport();
        GatewayClient client = new GatewayClient(t.getServerUrl(), t.getToken(), t.getRequestTimeout(), objectMapper);
        verifyOrganization(client, properties);
        return client;
    }

    /**
     * Checks the token against the configured organization once at startup. A token for another
     * organization is a configuration mistake worth failing on; an unreachable server is not,
     * because the pollers keep retrying until it comes up.
     */
    static void verifyOrganization(GatewayClient client, AgentProperties properties) {
        try {
            JsonNode me = client.whoami();
            String tokenOrg = me == null ? "" : me.path("organizationId").asString("");
            String configured = properties.getOrganizationId();
            if (configured == null || configured.isBlank()) {
                properties.setOrganizationId(tokenOrg);
                log.info("Agent organization taken from its token: organizationId={}", tokenOrg);
            } else if (!tokenOrg.isEmpty() && !configured.trim().equals(tokenOrg)) {
                throw new IllegalStateException("CERTPING_AGENT_TOKEN belongs to organization " + tokenOrg
                        + " but AGENT_ORGANIZATION_ID is " + configured);
            }
            log.info("Connected to the CertPing agent gateway: organizationId={}", tokenOrg);
        } catch (GatewayClient.GatewayException e) {
            if (e.getStatus() == 401 || e.getStatus() == 403) {
                throw new IllegalStateException("The CertPing server rejected the agent token: " + e.getMessage(), e);
            }
            if (e.getStatus() == 503) {
                log.info("CertPing has no organization yet; the agent connects once one is created");
            } else {
                log.warn("CertPing server not reachable yet ({}); the agent will keep retrying", e.getMessage());
            }
        }
    }

    @Bean("outboundSender")
    public MessageSender outboundSender(GatewayClient gatewayClient) {
        return new HttpMessageSender(gatewayClient, "outbound");
    }

    @Bean("inboundSender")
    public MessageSender inboundSender(GatewayClient gatewayClient) {
        return new HttpMessageSender(gatewayClient, "inbound");
    }

    @Bean
    public InboundConsumer inboundConsumer(GatewayClient gatewayClient, AgentProperties properties,
                                           @Lazy AgentMessageListener messageListener) {
        AgentProperties.TransportProperties t = properties.getTransport();
        int concurrency = t.getMaxConcurrentJobs() > 0 ? t.getMaxConcurrentJobs() : 8;
        return new HttpInboundConsumer(gatewayClient, context -> {
            // The server was down at startup: learn the organization before handling its first command.
            if (properties.getOrganizationId() == null || properties.getOrganizationId().isBlank()) {
                verifyOrganization(gatewayClient, properties);
            }
            messageListener.onMessage(context);
        }, concurrency, t.getPollWait(), t.getMaxLockRenewal())
                .onConnected(() -> {
                    if (properties.getOrganizationId() == null || properties.getOrganizationId().isBlank()) {
                        verifyOrganization(gatewayClient, properties);
                    }
                });
    }
}
