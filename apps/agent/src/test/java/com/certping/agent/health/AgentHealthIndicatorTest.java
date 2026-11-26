// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health;

import com.certping.agent.config.InboundConsumerLifecycle;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.Map;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AgentHealthIndicatorTest {

    @Mock private InboundConsumerLifecycle inboundConsumer;

    private AgentHealthIndicator indicator;

    @BeforeEach
    void setUp() {
        indicator = new AgentHealthIndicator(inboundConsumer);
    }

    @Test
    void health_allRunning_returnsUp() {
        when(inboundConsumer.isRunning()).thenReturn(true);
        when(inboundConsumer.states()).thenReturn(Map.of(
                "asbIssuanceProcessor", "RUNNING",
                "asbRenewalProcessor", "RUNNING",
                "asbDeploymentProcessor", "RUNNING",
                "asbManualIssuanceProcessor", "RUNNING",
                "asbRevocationProcessor", "RUNNING",
                "asbCertSecretDeleteProcessor", "RUNNING"));

        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails()).containsEntry("asbIssuanceProcessor", "RUNNING");
        assertThat(health.getDetails()).containsEntry("asbRenewalProcessor", "RUNNING");
        assertThat(health.getDetails()).containsEntry("asbDeploymentProcessor", "RUNNING");
        assertThat(health.getDetails()).containsEntry("asbManualIssuanceProcessor", "RUNNING");
        assertThat(health.getDetails()).containsEntry("asbRevocationProcessor", "RUNNING");
    }

    @Test
    void health_issuanceStopped_returnsDown() {
        when(inboundConsumer.isRunning()).thenReturn(false);
        when(inboundConsumer.states()).thenReturn(Map.of(
                "asbIssuanceProcessor", "STOPPED",
                "asbRenewalProcessor", "RUNNING"));

        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("asbIssuanceProcessor", "STOPPED");
        assertThat(health.getDetails()).containsEntry("asbRenewalProcessor", "RUNNING");
    }

    @Test
    void health_renewalStopped_returnsDown() {
        when(inboundConsumer.isRunning()).thenReturn(false);
        when(inboundConsumer.states()).thenReturn(Map.of(
                "asbRenewalProcessor", "STOPPED"));

        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("asbRenewalProcessor", "STOPPED");
    }

    @Test
    void health_deploymentStopped_returnsDown() {
        when(inboundConsumer.isRunning()).thenReturn(false);
        when(inboundConsumer.states()).thenReturn(Map.of(
                "asbDeploymentProcessor", "STOPPED"));

        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("asbDeploymentProcessor", "STOPPED");
    }

    @Test
    void health_manualStopped_returnsDown() {
        when(inboundConsumer.isRunning()).thenReturn(false);
        when(inboundConsumer.states()).thenReturn(Map.of(
                "asbManualIssuanceProcessor", "STOPPED"));

        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("asbManualIssuanceProcessor", "STOPPED");
    }

    @Test
    void health_exceptionFromClient_returnsDown() {
        when(inboundConsumer.isRunning()).thenThrow(new RuntimeException("gateway client dead"));

        Health health = indicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    }
}
