// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.listener;

import com.certping.agent.config.AgentProperties;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AgentInboundMessageRoutingTest {

    @Test
    void matchesConfiguredOrganization_requiresExactOrganizationId() {
        AgentInboundMessageRouting routing = new AgentInboundMessageRouting(configuredProperties());

        assertThat(routing.matchesConfiguredOrganization("42")).isTrue();
        assertThat(routing.matchesConfiguredOrganization("99")).isFalse();
    }

    @Test
    void matchesConfiguredOrganization_rejectsNullOrBlank() {
        AgentInboundMessageRouting routing = new AgentInboundMessageRouting(configuredProperties());

        assertThat(routing.matchesConfiguredOrganization(null)).isFalse();
        assertThat(routing.matchesConfiguredOrganization("  ")).isFalse();
    }

    private static AgentProperties configuredProperties() {
        AgentProperties properties = new AgentProperties();
        properties.setOrganizationId("42");
        return properties;
    }
}
