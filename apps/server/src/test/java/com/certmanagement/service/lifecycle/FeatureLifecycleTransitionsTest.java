// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.service.lifecycle.FeatureLifecycleState.Transition;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class FeatureLifecycleTransitionsTest {

    private static final long ORG = 42L;
    private static final String FEATURE = "DISCOVERY";
    private static final Instant NOW = Instant.parse("2026-10-06T09:15:00Z");
    private static final AffectedItems THREE = new AffectedItems(BlockerKind.RUNNING_DISCOVERY_SCANS, "Running discovery scans", 3);
    private static final AffectedItems ONE = new AffectedItems(BlockerKind.RUNNING_DISCOVERY_SCANS, "Running discovery scans", 1);
    private static final FeatureLifecycleState UNTOUCHED = FeatureLifecycleState.initial(ORG, FEATURE);

    @Test
    void aPauseThatTouchedNothingChangesNothingAndOwesNoEmail() {
        assertThat(FeatureLifecycleTransitions.afterForcedPause(UNTOUCHED, List.of(), NOW)).isEqualTo(UNTOUCHED);
        assertThat(FeatureLifecycleTransitions.afterBaselinePause(UNTOUCHED, List.of())).isEqualTo(UNTOUCHED);
    }

    @Test
    void theFirstForcedPauseOwesOnePausedEmailUnderAStableKey() {
        FeatureLifecycleState state = pausedOnce();

        assertThat(state.platformPaused()).isTrue();
        assertThat(state.isNotificationOwed()).isTrue();
        assertThat(state.pendingTransition()).isEqualTo(Transition.PAUSED);
        assertThat(state.pendingItems()).containsExactly(THREE);
        assertThat(state.idempotencyKey()).isEqualTo("42:DISCOVERY:PAUSED:1")
                .matches("[A-Za-z0-9._:-]{1,128}");
    }

    @Test
    void aBaselinePauseIsPausedButOwesNothing() {
        FeatureLifecycleState state = FeatureLifecycleTransitions.afterBaselinePause(UNTOUCHED, List.of(THREE));

        assertThat(state.platformPaused()).isTrue();
        assertThat(state.isNotificationOwed()).isFalse();
        assertThat(state.isPauseNoticeClaimed()).isFalse();
    }

    @Test
    void lateRecordsJoinAPausedEmailNotYetClaimed() {
        FeatureLifecycleState merged = FeatureLifecycleTransitions.afterLatePause(pausedOnce(), List.of(ONE));

        assertThat(merged.transitionSeq()).isEqualTo(1);
        assertThat(merged.pendingItems()).extracting(AffectedItems::count).containsExactly(4);
        assertThat(merged.pendingOccurredAt()).isEqualTo(NOW);
    }

    @Test
    void lateRecordsAfterTheEmailWasClaimedOrSentSendNoSecondEmail() {
        FeatureLifecycleState claimed = claimed(pausedOnce());
        FeatureLifecycleState told = notified(claimed);

        assertThat(FeatureLifecycleTransitions.afterLatePause(claimed, List.of(ONE))).isEqualTo(claimed);
        assertThat(FeatureLifecycleTransitions.afterLatePause(told, List.of(ONE))).isEqualTo(told);
    }

    @Test
    void aResumeAfterAToldPauseOwesOneResumedEmailUnderTheNextSequence() {
        FeatureLifecycleState resumed = FeatureLifecycleTransitions
                .afterResume(notified(claimed(pausedOnce())), List.of(THREE), NOW);

        assertThat(resumed.platformPaused()).isFalse();
        assertThat(resumed.isNotificationOwed()).isTrue();
        assertThat(resumed.pendingTransition()).isEqualTo(Transition.RESUMED);
        assertThat(resumed.idempotencyKey()).isEqualTo("42:DISCOVERY:RESUMED:2");
    }

    @Test
    void aResumeWhileThePausedEmailIsInFlightStillOwesTheResumedEmail() {
        FeatureLifecycleState resumed = FeatureLifecycleTransitions
                .afterResume(claimed(pausedOnce()), List.of(THREE), NOW);

        assertThat(resumed.pendingTransition()).isEqualTo(Transition.RESUMED);
        assertThat(resumed.isNotificationOwed()).isTrue();
    }

    @Test
    void aResumeWithNothingLeftToResumeStillTellsACustomerWhoWasTold() {
        FeatureLifecycleState resumed = FeatureLifecycleTransitions
                .afterResume(notified(claimed(pausedOnce())), List.of(), NOW);

        assertThat(resumed.platformPaused()).isFalse();
        assertThat(resumed.pendingTransition()).isEqualTo(Transition.RESUMED);
        assertThat(resumed.pendingItems()).isEmpty();
        assertThat(resumed.isNotificationOwed()).isTrue();
    }

    @Test
    void aResumeBeforeThePausedEmailWasClaimedWithdrawsItSilently() {
        FeatureLifecycleState resumed = FeatureLifecycleTransitions.afterResume(pausedOnce(), List.of(THREE), NOW);

        assertThat(resumed.platformPaused()).isFalse();
        assertThat(resumed.isNotificationOwed()).isFalse();
        assertThat(resumed.notifiedSeq()).isEqualTo(resumed.transitionSeq());
    }

    @Test
    void aBaselinePauseIsResumedSilently() {
        FeatureLifecycleState resumed = FeatureLifecycleTransitions.afterResume(
                FeatureLifecycleTransitions.afterBaselinePause(UNTOUCHED, List.of(THREE)), List.of(THREE), NOW);

        assertThat(resumed.platformPaused()).isFalse();
        assertThat(resumed.isNotificationOwed()).isFalse();
    }

    @Test
    void aResumeOfAnOrganizationThePlatformNeverPausedChangesNothing() {
        assertThat(FeatureLifecycleTransitions.afterResume(UNTOUCHED, List.of(THREE), NOW)).isEqualTo(UNTOUCHED);
    }

    @Test
    void aSecondPauseAfterAResumeOwesANewEmail() {
        FeatureLifecycleState resumed = notified(FeatureLifecycleTransitions
                .afterResume(notified(claimed(pausedOnce())), List.of(THREE), NOW));

        FeatureLifecycleState pausedAgain = FeatureLifecycleTransitions.afterForcedPause(resumed, List.of(ONE), NOW);

        assertThat(pausedAgain.idempotencyKey()).isEqualTo("42:DISCOVERY:PAUSED:3");
        assertThat(pausedAgain.isNotificationOwed()).isTrue();
        assertThat(pausedAgain.isPauseNoticeClaimed()).as("the old claim is for an older pause").isFalse();
    }

    private static FeatureLifecycleState pausedOnce() {
        return FeatureLifecycleTransitions.afterForcedPause(UNTOUCHED, List.of(THREE), NOW);
    }

    private static FeatureLifecycleState claimed(FeatureLifecycleState state) {
        return new FeatureLifecycleState(state.organizationId(), state.featureKey(), state.platformPaused(),
                state.transitionSeq(), state.notifiedSeq(), state.pendingTransition(), state.pendingItems(),
                state.pendingOccurredAt(), state.appliedTransitionId(), state.transitionSeq());
    }

    private static FeatureLifecycleState notified(FeatureLifecycleState state) {
        return new FeatureLifecycleState(state.organizationId(), state.featureKey(), state.platformPaused(),
                state.transitionSeq(), state.transitionSeq(), null, List.of(), null, state.appliedTransitionId(),
                state.pausedClaimedSeq());
    }
}
