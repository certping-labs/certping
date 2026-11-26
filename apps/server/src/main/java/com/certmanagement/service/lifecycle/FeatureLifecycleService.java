// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.FeatureInUseException;
import com.certmanagement.exception.ForbiddenException;
import com.certmanagement.security.CallerPermissions;
import com.certmanagement.service.audit.FeatureFlagChangeAudit;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Clear-first for organization admins: what keeps a feature in use, the bulk
 * actions that clear it, and the guard that refuses the switch-off while anything remains. The guard
 * and every clear hold the (organization, feature) lock of {@link FeatureLifecycleLock}, as do the
 * create paths, so nothing new can appear between the check and the switch.
 *
 * <p>A bulk clear also needs the permission the same change needs one record at a time
 * ({@link ClearPermissions}), and every blocker list shown to a caller offers only the actions that
 * caller may perform.
 */
@Service
@RequiredArgsConstructor
public class FeatureLifecycleService {

    private final FeatureLifecycleRegistry registry;
    private final FeatureLifecycleLock lock;
    private final FeatureFlagChangeAudit changeAudit;

    /** What keeps {@code featureKey} in use for the organization; empty when it can be switched off. */
    @Transactional(readOnly = true)
    public List<Blocker> blockers(long organizationId, String featureKey) {
        return registry.find(featureKey)
                .map(lifecycle -> lifecycle.blockers(organizationId))
                .orElse(List.of());
    }

    /**
     * {@link #blockers} as the caller sees them: each one's actions narrowed to those
     * {@code callerPermissions} allow ({@link ClearPermissions}).
     */
    @Transactional(readOnly = true)
    public List<Blocker> blockersFor(long organizationId, String featureKey, Set<String> callerPermissions) {
        return ClearPermissions.withPermittedActions(blockers(organizationId, featureKey), callerPermissions);
    }

    /**
     * Takes the (organization, feature) lock in the caller's transaction and refuses to continue while
     * anything blocks the feature. Called by the organization admin's switch-off just before it writes,
     * so the check and the write commit together.
     *
     * @throws FeatureInUseException when blockers remain; they offer only the actions the current
     *                               request's caller may perform
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public void lockAndAssertNothingInUse(long organizationId, String featureKey) {
        Optional<FeatureLifecycle> lifecycle = registry.find(featureKey);
        if (lifecycle.isEmpty()) {
            return;
        }
        lock.lock(organizationId, lifecycle.get().featureKey());
        List<Blocker> blockers = lifecycle.get().blockers(organizationId);
        if (!blockers.isEmpty()) {
            throw new FeatureInUseException(featureKey,
                    ClearPermissions.withPermittedActions(blockers, CallerPermissions.current()));
        }
    }

    /**
     * Applies a bulk clear to the organization's records of {@code kind} and audits it.
     *
     * @param callerPermissions the permissions of whoever asked; the clear needs the one the same change
     *                          needs one record at a time ({@link ClearPermissions})
     * @return records changed
     * @throws BadRequestException when the feature has no such kind, or the action does not clear it
     * @throws ForbiddenException  when the caller lacks the permission the action needs
     */
    @Transactional
    public int clear(long organizationId, String featureKey, BlockerKind kind, ClearAction action,
                     Set<String> callerPermissions) {
        FeatureLifecycle lifecycle = registry.find(featureKey)
                .filter(found -> found.kinds().contains(kind))
                .orElseThrow(() -> new BadRequestException(
                        "Feature '" + featureKey + "' has nothing of kind " + kind + " to clear."));
        if (!lifecycle.supportedActions(kind).contains(action)) {
            throw new UnsupportedClearException(featureKey, kind, action);
        }
        if (!ClearPermissions.permits(kind, action, callerPermissions)) {
            throw new ForbiddenException("Clearing " + kind + " with " + action + " needs the '"
                    + ClearPermissions.requiredPermission(kind, action).orElse("(none)") + "' permission.");
        }
        lock.lock(organizationId, lifecycle.featureKey());
        int affected = lifecycle.clear(organizationId, kind, action);
        changeAudit.recordClear(organizationId, featureKey, kind.name(), action.name(), affected);
        return affected;
    }
}
