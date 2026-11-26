// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.service.FeatureFlagStateChangedEvent;
import com.certmanagement.service.audit.FeatureFlagChangeAudit.OverrideState;
import com.certmanagement.service.lifecycle.ForcedTransition.Scope;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * Records a super admin's flag change (global switch, org-type default, or an override written or
 * removed for one organization) as a forced transition, in the flag write's transaction, and asks
 * for it to be applied after commit. Forced transitions always apply, whatever the
 * {@code FEATURE_LIFECYCLE_RECONCILE} ops switch says: the affected organizations' records pause,
 * their admins get one email.
 *
 * <p>Changes to features without platform-pausable records are not recorded: there is nothing to apply.
 *
 * <p>Each recorded change first takes the forced-transition write lock of the feature whose lifecycle it
 * pauses, so concurrent super admin writes that reach one lifecycle (the feature's own flag, or the flag
 * its automatic work requires) commit in id order. A caller recording several features in one
 * transaction must record them in sorted feature-key order, so two such callers never deadlock.
 */
@Component
@RequiredArgsConstructor
public class ForcedFlagChanges {

    private final FeatureLifecycleRegistry registry;
    private final ForcedTransitionStore transitions;
    private final ApplicationEventPublisher events;

    /** The global switch went from {@code before} to {@code after}. */
    @Transactional(propagation = Propagation.MANDATORY)
    public void recordGlobal(String featureKey, boolean before, boolean after, Integer actorUserId) {
        record(featureKey, Scope.GLOBAL, null, null, before, null, after, null, actorUserId);
    }

    /** An org-type default went from {@code before} to {@code after} ({@code null}: none). */
    @Transactional(propagation = Propagation.MANDATORY)
    public void recordOrgType(String featureKey, String orgType, Boolean before, Boolean after, Integer actorUserId) {
        record(featureKey, Scope.ORG_TYPE, orgType, null, before, null, after, null, actorUserId);
    }

    /** A super admin wrote or removed an organization's override ({@code null}: none). */
    @Transactional(propagation = Propagation.MANDATORY)
    public void recordOrganization(String featureKey, long organizationId, OverrideState before, OverrideState after,
                                   Integer actorUserId) {
        record(featureKey, Scope.ORGANIZATION, null, organizationId,
                before == null ? null : before.enabled(), before == null ? null : before.adminLocked(),
                after == null ? null : after.enabled(), after == null ? null : after.adminLocked(), actorUserId);
    }

    private void record(String featureKey, Scope scope, String orgType, Long organizationId, Boolean beforeEnabled,
                        Boolean beforeAdminLocked, Boolean afterEnabled, Boolean afterAdminLocked,
                        Integer actorUserId) {
        Optional<PlatformPausableLifecycle> lifecycle = registry.findPausable(featureKey);
        if (lifecycle.isEmpty()) {
            return;
        }
        transitions.lockFeatureForWrite(lifecycle.get().featureKey());
        long transitionId = transitions.insert(featureKey, scope, orgType, organizationId, beforeEnabled,
                beforeAdminLocked, afterEnabled, afterAdminLocked, actorUserId);
        events.publishEvent(new FeatureFlagStateChangedEvent(featureKey, organizationId, actorUserId, transitionId));
    }
}
