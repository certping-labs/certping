// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health;

import com.certping.agent.transport.GatewayClient;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * DOWN while the server rejects the agent token (revoked, expired or wrong). The pollers keep
 * retrying so a restored token recovers on its own, but container and Kubernetes probes see it.
 */
@Component
@RequiredArgsConstructor
public class GatewayAuthHealthIndicator implements HealthIndicator {

    private final GatewayClient gatewayClient;

    @Override
    public Health health() {
        return gatewayClient.tokenRejection()
                .map(reason -> Health.down().withDetail("reason", reason).build())
                .orElseGet(() -> Health.up().build());
    }
}
