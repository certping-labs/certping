// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health.ca;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.message.CaConnectorHealth;
import com.certping.agent.model.message.CaHealthReport;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

/**
 * Publishes {@code AGENT_CA_HEALTH_REPORT} on a schedule.
 *
 * <p>Modelled on {@code AgentHeartbeatPublisher}, and complementary to it: the heartbeat says the
 * agent is alive, this says whether it can actually issue. An agent can be perfectly healthy and
 * completely unable to sign — a disabled REST protocol or an expired client certificate looks
 * identical to "fine" from the heartbeat alone.
 *
 * <p>Every {@link CaHealthProbe} bean is collected automatically, so a new CA connector appears
 * in the report by existing.
 *
 * <p>Requires a scheduler pool larger than one ({@code spring.task.scheduling.pool.size}).
 * {@code MessageSender.sendMessage} can wait on request timeouts and throttling retries while the
 * server is slow or unreachable, so on Spring's single-threaded default this task can starve
 * {@code AgentHeartbeatPublisher}.
 */
@Slf4j
@Component
public class CaHealthReportPublisher {

    /** Bumped when the payload changes shape, so the server can reject what it cannot parse. */
    private static final int REPORT_VERSION = 1;

    private final AgentProperties properties;
    private final AgentMessageSender sender;
    private final List<CaHealthProbe> probes;

    public CaHealthReportPublisher(AgentProperties properties,
                                   AgentMessageSender sender,
                                   List<CaHealthProbe> probes) {
        this.properties = properties;
        this.sender = sender;
        this.probes = probes;
        log.info("CA health reporting active for {} connector(s): {}",
                probes.size(), probes.stream().map(CaHealthProbe::caProvider).toList());
    }

    @Scheduled(
            initialDelayString = "${agent.health.ca-report-initial-delay-ms:30000}",
            fixedDelayString = "${agent.health.ca-report-interval-ms:300000}")
    public void publishCaHealthReport() {
        CaHealthReport report = buildReport();
        if (report.getConnectors().isEmpty()) {
            log.debug("No CA connectors configured — skipping CA health report");
            return;
        }
        try {
            sender.sendCaHealthReport(report);
            log.debug("Published AGENT_CA_HEALTH_REPORT organizationId={} connectors={}",
                    report.getOrganizationId(), report.getConnectors().size());
        } catch (Exception e) {
            // Losing a report must not kill the scheduler thread — the next tick should retry.
            log.warn("Failed to publish CA health report: {}", e.getMessage());
        }
    }

    /** Package-private so tests and the startup log can render a report without publishing it. */
    CaHealthReport buildReport() {
        List<CaConnectorHealth> connectors = new ArrayList<>();
        for (CaHealthProbe probe : probes) {
            try {
                CaConnectorHealth health = probe.probe();
                if (health != null) {
                    connectors.add(health);
                }
            } catch (Exception e) {
                // The contract says probes don't throw. If one does, drop that connector rather
                // than the whole report — the others still carry useful information.
                log.warn("CA health probe for {} threw, omitting it from the report: {}",
                        probe.caProvider(), e.getMessage());
            }
        }
        return CaHealthReport.builder()
                .reportVersion(REPORT_VERSION)
                .organizationId(properties.getOrganizationId())
                .respondedAt(OffsetDateTime.now(ZoneOffset.UTC).toString())
                .connectors(connectors)
                .build();
    }
}
