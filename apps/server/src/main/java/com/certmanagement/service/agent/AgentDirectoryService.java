// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.dto.agent.AgentView;
import com.certmanagement.messaging.model.AgentCaStatus;
import com.certmanagement.messaging.model.AgentInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The Agents page: every agent token of an organization with what its agent last reported.
 *
 * <p>Settings stay on the agent; this only shows what agents report, and only through the fixed,
 * sanitized fields of {@link AgentView}, so no secret is ever returned.
 *
 * <p>Status: ONLINE when the last heartbeat or gateway poll is within {@value #ONLINE_PERIODS}
 * heartbeat cadence periods (the organization's cadence, default 5 minutes); OFFLINE otherwise, and
 * always for a revoked or expired token; NEVER_SEEN when the agent has never connected.
 */
@Slf4j
@Service
public class AgentDirectoryService {

    static final int ONLINE_PERIODS = 3;
    static final int DEFAULT_CADENCE_MINUTES = 5;
    /** The bootstrap token the server registers for the bundled agent carries this creator. */
    static final String BOOTSTRAP_CREATOR = "bootstrap";

    private static final Map<String, Integer> STATUS_ORDER = Map.of("ONLINE", 0, "OFFLINE", 1, "NEVER_SEEN", 2);

    private final AgentInfoStore store;
    private final AgentHealthService agentHealthService;
    private final Clock clock;

    @org.springframework.beans.factory.annotation.Autowired
    public AgentDirectoryService(AgentInfoStore store, AgentHealthService agentHealthService) {
        this(store, agentHealthService, Clock.systemUTC());
    }

    AgentDirectoryService(AgentInfoStore store, AgentHealthService agentHealthService, Clock clock) {
        this.store = store;
        this.agentHealthService = agentHealthService;
        this.clock = clock;
    }

    public List<AgentView> list(long organizationId) {
        int cadence = cadenceMinutes(organizationId);
        OffsetDateTime now = OffsetDateTime.now(clock);
        return store.list(organizationId).stream()
                .map(row -> view(row, cadence, now))
                .sorted(Comparator.<AgentView>comparingInt(v -> STATUS_ORDER.getOrDefault(v.status(), 3))
                        .thenComparing(AgentView::revoked)
                        .thenComparing(v -> v.name() == null ? "" : v.name(), String.CASE_INSENSITIVE_ORDER)
                        .thenComparing(AgentView::agentId))
                .toList();
    }

    public Optional<AgentView> get(long organizationId, long agentId) {
        return store.find(organizationId, agentId)
                .map(row -> view(row, cadenceMinutes(organizationId), OffsetDateTime.now(clock)));
    }

    private int cadenceMinutes(long organizationId) {
        try {
            return agentHealthService.getHeartbeatCadenceMinutes(organizationId);
        } catch (RuntimeException e) {
            log.debug("No heartbeat cadence for organizationId={}: {}", organizationId, e.getMessage());
            return DEFAULT_CADENCE_MINUTES;
        }
    }

    static AgentView view(AgentInfoStore.AgentRow row, int cadenceMinutes, OffsetDateTime now) {
        boolean expired = row.tokenExpiresAt() != null && !row.tokenExpiresAt().isAfter(now);
        boolean revoked = row.revokedAt() != null || expired;
        OffsetDateTime lastSeen = latest(row.lastHeartbeatAt(), row.lastUsedAt());
        String status;
        if (revoked) {
            status = "OFFLINE";
        } else if (lastSeen == null) {
            status = "NEVER_SEEN";
        } else {
            Duration window = Duration.ofMinutes((long) Math.max(1, cadenceMinutes) * ONLINE_PERIODS);
            status = lastSeen.isAfter(now.minus(window)) ? "ONLINE" : "OFFLINE";
        }

        AgentInfo info = AgentInfoSanitizer.sanitize(row.agentInfo());
        AgentInfo.Capabilities caps = info == null ? null : info.getCapabilities();
        AgentCaStatus ca = row.caStatus();
        boolean bundled = BOOTSTRAP_CREATOR.equals(row.createdBy())
                || (info != null && Boolean.TRUE.equals(info.getBundled()));

        return new AgentView(
                String.valueOf(row.tokenId()),
                row.name(),
                row.tokenPrefix(),
                iso(row.tokenCreatedAt()),
                iso(row.tokenExpiresAt()),
                revoked,
                status,
                iso(lastSeen),
                info == null ? null : info.getVersion(),
                info == null ? null : info.getHostname(),
                info == null ? null : info.getOs(),
                info == null ? null : info.getJavaVersion(),
                info == null ? null : info.getSecretStore(),
                info == null ? null : info.getMaxConcurrentJobs(),
                info == null ? null : info.getProxyConfigured(),
                bundled,
                ca == null || ca.getAcme() == null ? null : new AgentView.Acme(
                        ca.getAcme().getDirectoryUrl(), ca.getAcme().getEnvironment(), ca.getAcme().getContactEmail()),
                ca == null || ca.getGlobalsign() == null ? null : ca.getGlobalsign().isConfigured(),
                new AgentView.Capabilities(
                        caps == null ? List.of() : caps.getDeploymentTargets(),
                        caps == null ? List.of() : caps.getDiscoveryTargets(),
                        caps == null ? List.of() : caps.getDnsProviders()));
    }

    private static OffsetDateTime latest(OffsetDateTime a, OffsetDateTime b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        return a.isAfter(b) ? a : b;
    }

    private static String iso(OffsetDateTime value) {
        return value == null ? null : value.withOffsetSameInstant(ZoneOffset.UTC).toString();
    }
}
