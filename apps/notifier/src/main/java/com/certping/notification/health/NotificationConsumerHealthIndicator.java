// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.health;

import com.certping.notification.config.NotificationConsumers;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.health.contributor.AbstractHealthIndicator;
import org.springframework.boot.health.contributor.Health;
import org.springframework.stereotype.Component;

/**
 * Up while every notifications channel consumer is started. Registered even when no consumer bean
 * exists, so the status group always resolves and reports that nothing is consuming.
 */
@Component("notificationConsumerHealthIndicator")
public class NotificationConsumerHealthIndicator extends AbstractHealthIndicator {

    private final ObjectProvider<NotificationConsumers> consumers;

    public NotificationConsumerHealthIndicator(ObjectProvider<NotificationConsumers> consumers) {
        this.consumers = consumers;
    }

    @Override
    protected void doHealthCheck(Health.Builder builder) {
        NotificationConsumers started = consumers.getIfAvailable();
        if (started != null && started.allRunning()) {
            builder.up();
        } else {
            builder.down();
        }
    }
}
