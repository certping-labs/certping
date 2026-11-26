// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration for {@link com.certmanagement.service.scheduler.QueueDepthAlertService}.
 * Bound from {@code certping.alerts.queue-depth.*}.
 *
 * <p>The watch-list is intentionally empty by default: the poller no-ops until ops adds message
 * queue channels to it. Thresholds are per-entity with a global default fallback.
 */
@Data
@Component
@ConfigurationProperties(prefix = "certping.alerts.queue-depth")
public class QueueAlertProperties {

    /** Default active-message backlog threshold used when an entity doesn't set its own. */
    private long defaultActiveThreshold = 1000;

    /** Default dead-letter threshold — alert as soon as a single message is dead-lettered. */
    private long defaultDlqThreshold = 1;

    /** Minutes to suppress re-alerts while an entity/metric stays breached. */
    private int cooldownMinutes = 60;

    /** Ops dashboard link surfaced in the alert email. */
    private String dashboardUrl = "";

    /** Watched message queue channels. Empty = the poller is a no-op. */
    private List<Entity> entities = new ArrayList<>();

    @Data
    public static class Entity {
        /** Message queue channel, for example {@code cert-agent-outbound} or {@code notifications}. */
        private String name;

        /** Per-entity active threshold; falls back to {@code defaultActiveThreshold} when null. */
        private Long activeThreshold;

        /** Per-entity DLQ threshold; falls back to {@code defaultDlqThreshold} when null. */
        private Long dlqThreshold;

        /** Stable key for state rows and logging: the channel name. */
        public String entityKey() {
            return name;
        }
    }
}
