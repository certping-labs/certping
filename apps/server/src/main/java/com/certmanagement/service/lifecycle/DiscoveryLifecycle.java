// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.repository.lifecycle.AffectedOrganizations;
import com.certmanagement.repository.lifecycle.DiscoveryLifecycleRepository;
import com.certmanagement.repository.lifecycle.ImpactScope;
import com.certmanagement.repository.lifecycle.RecordImpact;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * {@code DISCOVERY}: blocked while a scan is running; cleared, and paused by the platform, by
 * cancelling the running scans (a cancelled scan is not resumed: the customer runs discovery again).
 * Saved configurations and discovered certificates are kept.
 */
@Component
@RequiredArgsConstructor
public class DiscoveryLifecycle implements PlatformPausableLifecycle {

    static final String CANCELLED_MESSAGE =
            "Discovery was stopped because certificate discovery is turned off for this organization.";
    private static final String LABEL = "Running discovery scans";
    private static final String ITEM_LABEL = "Discovery scans stopped";
    private static final String HREF = "/cert-manager/discovery";

    private final DiscoveryLifecycleRepository scans;

    @Override
    public String featureKey() {
        return FeatureFlags.DISCOVERY;
    }

    @Override
    public List<BlockerKind> kinds() {
        return List.of(BlockerKind.RUNNING_DISCOVERY_SCANS);
    }

    @Override
    public Set<ClearAction> supportedActions(BlockerKind kind) {
        return kind == BlockerKind.RUNNING_DISCOVERY_SCANS ? Set.of(ClearAction.CANCEL_ALL) : Set.of();
    }

    @Override
    public List<Blocker> blockers(long organizationId) {
        long running = scans.countRunning(organizationId);
        return running == 0 ? List.of() : List.of(new Blocker(BlockerKind.RUNNING_DISCOVERY_SCANS, LABEL, running,
                HREF, List.of(ClearAction.CANCEL_ALL)));
    }

    @Override
    public int clear(long organizationId, BlockerKind kind, ClearAction action) {
        if (!supportedActions(kind).contains(action)) {
            throw new UnsupportedClearException(featureKey(), kind, action);
        }
        return scans.cancelRunning(organizationId, CANCELLED_MESSAGE);
    }

    @Override
    public List<ImpactCount> impact(ImpactScope scope) {
        RecordImpact impact = scans.impact(scope);
        return List.of(new ImpactCount(BlockerKind.RUNNING_DISCOVERY_SCANS, LABEL, impact.records(),
                impact.organizations()));
    }

    @Override
    public Map<Long, List<AffectedItems>> activeItems(Collection<Long> organizationIds) {
        Map<Long, List<AffectedItems>> items = new HashMap<>();
        scans.countRunningByOrganization(organizationIds).forEach((organizationId, running) -> items.put(
                organizationId, List.of(new AffectedItems(BlockerKind.RUNNING_DISCOVERY_SCANS, ITEM_LABEL,
                        Math.toIntExact(running)))));
        return items;
    }

    @Override
    public List<AffectedOrganizations> affectedOrganizations(ImpactScope scope) {
        return List.of(scans.runningScanOrganizations(scope));
    }

    @Override
    public List<Long> organizationsWithActiveRecords(long afterOrganizationId, int limit) {
        return scans.organizationsWithRunningScans(afterOrganizationId, limit);
    }

    @Override
    public List<AffectedItems> platformPause(long organizationId) {
        int cancelled = scans.cancelRunning(organizationId, CANCELLED_MESSAGE);
        return cancelled == 0 ? List.of()
                : List.of(new AffectedItems(BlockerKind.RUNNING_DISCOVERY_SCANS, ITEM_LABEL, cancelled));
    }

    /** A cancelled scan is not restarted: the customer runs discovery again when they choose. */
    @Override
    public List<AffectedItems> platformResume(long organizationId) {
        return List.of();
    }
}
