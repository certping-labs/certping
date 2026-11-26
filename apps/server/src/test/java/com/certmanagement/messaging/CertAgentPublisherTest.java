// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.messaging.transport.InboundSenders;

import com.certmanagement.messaging.transport.TransportProperties;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Routing tests for {@link CertAgentPublisher#queueFor(String, String)}.
 *
 * <p>The publisher now reads {@code orgType} directly from the caller-supplied payload — no
 * database lookup, no security-context dependency, no cache. These tests cover the routing
 * decision purely as a function of inputs.
 */
@ExtendWith(MockitoExtension.class)
class CertAgentPublisherTest {

    @Mock private InboundSenders senderFactory;

    private TransportProperties transportProperties;
    private CertAgentPublisher    publisher;

    @BeforeEach
    void setUp() {
        transportProperties = new TransportProperties();
        transportProperties.setInboundQueuePattern("{orgId}-agent-inbound");

        publisher = new CertAgentPublisher(senderFactory, transportProperties, JsonMapper.builderWithJackson2Defaults().build());
    }

    @Test
    void queueFor_b2bOrg_returnsPerOrgQueue() {
        assertThat(publisher.queueFor("42", "B2B")).isEqualTo("42-agent-inbound");
    }

    @Test
    void queueFor_b2cOrg_returnsItsOwnPerOrgQueue() {
        assertThat(publisher.queueFor("99", "B2B")).isEqualTo("99-agent-inbound");
    }

    @Test
    void queueFor_anyOrgType_returnsPerOrgQueue() {
        // Routing ignores orgType: every organization reads only its own inbound queue.
        assertThat(publisher.queueFor("42", null)).isEqualTo("42-agent-inbound");
        assertThat(publisher.queueFor("42", ""  )).isEqualTo("42-agent-inbound");
        assertThat(publisher.queueFor("42", "B2B")).isEqualTo("42-agent-inbound");
        assertThat(publisher.queueFor("42", "UNKNOWN")).isEqualTo("42-agent-inbound");
    }
}
