// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import java.time.Instant;
import java.util.List;

/**
 * Where one (organization, feature) stands with the platform: paused or not, how many transitions it
 * has had, the customer email still owed for the latest one, and which forced flag change it has
 * already applied (row of {@code feature_lifecycle_state}).
 *
 * @param transitionSeq       counts PLATFORM pause/resume transitions; part of the email idempotency key
 * @param notifiedSeq         the last transition whose email was published (or needs none)
 * @param pendingTransition   the transition whose email is owed, or null
 * @param pendingItems        what that email lists
 * @param appliedTransitionId the newest {@code feature_lifecycle_transition} applied (consumed) here
 * @param pausedClaimedSeq    the last PAUSED transition whose email was claimed for publishing; a resume
 *                            owes a RESUMED email exactly when the pause it ends was claimed
 */
public record FeatureLifecycleState(long organizationId, String featureKey, boolean platformPaused,
                                    long transitionSeq, long notifiedSeq, Transition pendingTransition,
                                    List<AffectedItems> pendingItems, Instant pendingOccurredAt,
                                    long appliedTransitionId, long pausedClaimedSeq) {

    /** A platform-driven change customers are told about. */
    public enum Transition { PAUSED, RESUMED }

    public FeatureLifecycleState {
        pendingItems = pendingItems == null ? List.of() : List.copyOf(pendingItems);
    }

    /** A row for an organization the platform has never touched for {@code featureKey}. */
    static FeatureLifecycleState initial(long organizationId, String featureKey) {
        return new FeatureLifecycleState(organizationId, featureKey, false, 0, 0, null, List.of(), null, 0, 0);
    }

    /** Whether an email is owed for the latest transition. */
    public boolean isNotificationOwed() {
        return notifiedSeq < transitionSeq && pendingTransition != null;
    }

    /** Whether the customer was (or is being) told about the pause that is current. */
    public boolean isPauseNoticeClaimed() {
        return platformPaused && pausedClaimedSeq >= transitionSeq;
    }

    /** The same state having applied forced transitions up to {@code transitionId}. */
    FeatureLifecycleState withAppliedTransition(long transitionId) {
        return new FeatureLifecycleState(organizationId, featureKey, platformPaused, transitionSeq, notifiedSeq,
                pendingTransition, pendingItems, pendingOccurredAt, Math.max(appliedTransitionId, transitionId),
                pausedClaimedSeq);
    }

    /**
     * The notifier's deliver-once key for the owed email, e.g. {@code 42:INTEGRATIONS:PAUSED:3}:
     * the same on every pod and retry, and only [A-Za-z0-9._:-] as the notifier requires.
     */
    public String idempotencyKey() {
        return organizationId + ":" + featureKey + ":" + pendingTransition + ":" + transitionSeq;
    }
}
