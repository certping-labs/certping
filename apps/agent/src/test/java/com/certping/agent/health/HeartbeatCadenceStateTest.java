// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health;

import com.certping.agent.config.AgentProperties;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class HeartbeatCadenceStateTest {

    @Test
    void constructor_clampsIntervalBelowMinimum_toSixtySeconds() {
        AgentProperties properties = new AgentProperties();
        properties.getHealth().setHeartbeatIntervalMs(10_000L);
        HeartbeatCadenceState state = new HeartbeatCadenceState(properties);
        assertThat(state.getHeartbeatIntervalMs()).isEqualTo(60_000L);
    }

    @Test
    void constructor_clampsIntervalAboveMaximum_toOneHour() {
        AgentProperties properties = new AgentProperties();
        properties.getHealth().setHeartbeatIntervalMs(10_000_000L);
        HeartbeatCadenceState state = new HeartbeatCadenceState(properties);
        assertThat(state.getHeartbeatIntervalMs()).isEqualTo(3_600_000L);
    }

    @Test
    void updateFromMinutes_appliesSanitization() {
        AgentProperties properties = new AgentProperties();
        HeartbeatCadenceState state = new HeartbeatCadenceState(properties);
        state.updateFromMinutes(200);
        assertThat(state.getHeartbeatIntervalMs()).isEqualTo(3_600_000L);
    }
}
