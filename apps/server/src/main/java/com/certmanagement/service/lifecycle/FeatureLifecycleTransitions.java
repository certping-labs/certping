// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.service.lifecycle.FeatureLifecycleState.Transition;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The rules that decide when an organization is told about a platform pause or resume: exactly one
 * PAUSED email per forced switch-off that affected records, none for a baseline pause, and a RESUMED
 * email exactly when the pause it ends was claimed for emailing. Pure functions over
 * {@link FeatureLifecycleState}; the reconciler applies them under the (organization, feature) lock.
 */
final class FeatureLifecycleTransitions {

    private FeatureLifecycleTransitions() {
    }

    /**
     * The state after a super admin's change switched the feature off and the platform paused
     * {@code paused}: a new PAUSED transition whose email lists them. Nothing paused: unchanged (an
     * organization without records is never emailed).
     */
    static FeatureLifecycleState afterForcedPause(FeatureLifecycleState current, List<AffectedItems> paused,
                                                  Instant now) {
        if (paused.isEmpty()) {
            return current;
        }
        long seq = current.transitionSeq() + 1;
        return new FeatureLifecycleState(current.organizationId(), current.featureKey(), true, seq,
                current.notifiedSeq(), Transition.PAUSED, paused, now, current.appliedTransitionId(),
                current.pausedClaimedSeq());
    }

    /**
     * The state after the baseline paused {@code paused} for an organization that had the feature off
     * already: paused, with nothing to tell (the customer had switched it off, or it never was on).
     */
    static FeatureLifecycleState afterBaselinePause(FeatureLifecycleState current, List<AffectedItems> paused) {
        if (paused.isEmpty()) {
            return current;
        }
        long seq = current.transitionSeq() + 1;
        return new FeatureLifecycleState(current.organizationId(), current.featureKey(), true, seq, seq,
                null, List.of(), null, current.appliedTransitionId(), current.pausedClaimedSeq());
    }

    /**
     * The state after records that slipped in while the organization was already paused were paused
     * too: they join the PAUSED email if it is still owed and not yet claimed; otherwise nothing
     * changes, so no second email ever goes out for one pause.
     */
    static FeatureLifecycleState afterLatePause(FeatureLifecycleState current, List<AffectedItems> paused) {
        boolean emailStillOpen = current.isNotificationOwed() && current.pendingTransition() == Transition.PAUSED
                && !current.isPauseNoticeClaimed();
        if (paused.isEmpty() || !emailStillOpen) {
            return current;
        }
        return new FeatureLifecycleState(current.organizationId(), current.featureKey(), true,
                current.transitionSeq(), current.notifiedSeq(), Transition.PAUSED,
                merge(current.pendingItems(), paused), current.pendingOccurredAt(), current.appliedTransitionId(),
                current.pausedClaimedSeq());
    }

    /**
     * The state after the platform resumed {@code resumed} records.
     *
     * <ul>
     *   <li>Not paused by the platform: unchanged.</li>
     *   <li>The pause's email was claimed (sent, or being sent): a RESUMED transition whose email lists
     *       what resumed, possibly nothing (a cancelled discovery scan is not restarted), so the
     *       customer hears the feature is back.</li>
     *   <li>Otherwise (a baseline pause, or a PAUSED email never claimed): closed silently, and an owed
     *       PAUSED email is withdrawn.</li>
     * </ul>
     */
    static FeatureLifecycleState afterResume(FeatureLifecycleState current, List<AffectedItems> resumed,
                                             Instant now) {
        if (!current.platformPaused()) {
            return current;
        }
        long seq = current.transitionSeq() + 1;
        if (current.isPauseNoticeClaimed()) {
            return new FeatureLifecycleState(current.organizationId(), current.featureKey(), false, seq,
                    current.notifiedSeq(), Transition.RESUMED, resumed, now, current.appliedTransitionId(),
                    current.pausedClaimedSeq());
        }
        return new FeatureLifecycleState(current.organizationId(), current.featureKey(), false, seq, seq,
                null, List.of(), null, current.appliedTransitionId(), current.pausedClaimedSeq());
    }

    private static List<AffectedItems> merge(List<AffectedItems> owed, List<AffectedItems> more) {
        Map<BlockerKind, AffectedItems> byKind = new LinkedHashMap<>();
        for (AffectedItems items : owed) {
            byKind.put(items.kind(), items);
        }
        for (AffectedItems items : more) {
            byKind.merge(items.kind(), items,
                    (a, b) -> new AffectedItems(a.kind(), a.label(), a.count() + b.count()));
        }
        return List.copyOf(byKind.values());
    }
}
