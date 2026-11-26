// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health;

import com.certping.agent.config.InboundConsumerLifecycle;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class AgentHealthIndicator implements HealthIndicator {

    private final InboundConsumerLifecycle inboundConsumer;

    @Override
    public Health health() {
        try {
            Health.Builder healthBuilder = inboundConsumer.isRunning() ? Health.up() : Health.down();
            inboundConsumer.states().forEach(healthBuilder::withDetail);
            return healthBuilder.build();

        } catch (Exception e) {
            log.error("Health check failed: {}", e.getMessage());
            return Health.down(e).build();
        }
    }
}
