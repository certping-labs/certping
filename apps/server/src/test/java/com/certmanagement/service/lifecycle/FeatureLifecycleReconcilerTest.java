// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.service.FeatureFlagDecision.GlobalRow;
import com.certmanagement.service.FeatureFlagDecision.OrgOverride;
import com.certmanagement.service.FeatureFlagInputs;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.audit.FeatureFlagChangeAudit;
import com.certmanagement.testing.Transactions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The per-organization NET effect: forced pause with one email, baseline pause in silence and only
 * with the ops switch, consumption of pending forced changes, and resumes.
 */
@ExtendWith(MockitoExtension.class)
class FeatureLifecycleReconcilerTest {

    private static final String FEATURE = "DISCOVERY";
    private static final String REQUIRED = "DNS_CREDENTIALS";
    private static final long ORG = 7L;
    private static final Instant NOW = Instant.parse("2026-10-06T09:15:00Z");
    private static final AffectedItems THREE = new AffectedItems(BlockerKind.RUNNING_DISCOVERY_SCANS, "Running discovery scans", 3);

    @Mock private FeatureLifecycleRegistry registry;
    @Mock private FeatureFlagResolver resolver;
    @Mock private FeatureLifecycleLock lock;
    @Mock private FeatureLifecycleStateStore states;
    @Mock private ForcedTransitionStore transitions;
    @Mock private FeatureLifecycleNotifier notifier;
    @Mock private FeatureFlagChangeAudit changeAudit;
    @Mock private PlatformPausableLifecycle lifecycle;

    private FeatureLifecycleReconciler reconciler;

    @BeforeEach
    void setUp() {
        reconciler = new FeatureLifecycleReconciler(registry, resolver, lock, states, transitions, notifier,
                changeAudit, Transactions.inline(), Clock.fixed(NOW, ZoneOffset.UTC));
        lenient().when(lifecycle.featureKey()).thenReturn(FEATURE);
        lenient().when(registry.findPausable(FEATURE)).thenReturn(Optional.of(lifecycle));
    }

    @Test
    void aForcedGlobalSwitchOffPausesUnderTheLockAuditsAsTheActorAndOwesOneEmail() {
        when(states.findForUpdate(ORG, FEATURE)).thenReturn(Optional.empty());
        when(transitions.pendingCovering(List.of(FEATURE), ORG, 0)).thenReturn(List.of(global(11, true, 99)));
        when(resolver.loadInputsUncached(FEATURE, ORG)).thenReturn(inputs(false, null, null));
        when(lifecycle.platformPause(ORG)).thenReturn(List.of(THREE));

        reconciler.reconcileSafely(lifecycle, ORG, false);

        InOrder order = inOrder(lock, states, transitions, resolver, lifecycle, changeAudit, notifier);
        order.verify(lock).lock(ORG, FEATURE);
        order.verify(states).findForUpdate(ORG, FEATURE);
        order.verify(transitions).pendingCovering(List.of(FEATURE), ORG, 0);
        order.verify(resolver).loadInputsUncached(FEATURE, ORG);
        order.verify(lifecycle).platformPause(ORG);
        order.verify(changeAudit).recordForcedPause(eq(ORG), eq(FEATURE), isNull(), any(), eq(99));
        ArgumentCaptor<FeatureLifecycleState> saved = ArgumentCaptor.forClass(FeatureLifecycleState.class);
        order.verify(states).save(saved.capture());
        order.verify(notifier).sendOwed(saved.getValue());
        assertThat(saved.getValue().idempotencyKey()).isEqualTo("7:DISCOVERY:PAUSED:1");
        assertThat(saved.getValue().isNotificationOwed()).isTrue();
        assertThat(saved.getValue().appliedTransitionId()).isEqualTo(11);
        assertThat(saved.getValue().pendingOccurredAt()).isEqualTo(NOW);
    }

    @Test
    void anOrganizationAlreadyOffBeforeTheForcedChangeIsBaselineAndLeftAloneWhileTheSwitchIsOff() {
        when(states.findForUpdate(ORG, FEATURE)).thenReturn(Optional.empty());
        when(transitions.pendingCovering(List.of(FEATURE), ORG, 0)).thenReturn(List.of(global(11, true, 99)));
        // The org admin had switched it off themselves: off before the global switch-off too.
        when(resolver.loadInputsUncached(FEATURE, ORG)).thenReturn(inputs(false, new OrgOverride(false, false), null));

        reconciler.reconcileSafely(lifecycle, ORG, false);

        verify(lifecycle, never()).platformPause(anyLong());
        ArgumentCaptor<FeatureLifecycleState> saved = ArgumentCaptor.forClass(FeatureLifecycleState.class);
        verify(states).save(saved.capture());
        assertThat(saved.getValue().appliedTransitionId()).as("consumed: never emailed later").isEqualTo(11);
        assertThat(saved.getValue().isNotificationOwed()).isFalse();
    }

    @Test
    void aBaselinePauseIsSilentAndAuditedWithItsCauseWhenTheSwitchIsOn() {
        when(states.findForUpdate(ORG, FEATURE)).thenReturn(Optional.empty());
        when(transitions.pendingCovering(List.of(FEATURE), ORG, 0)).thenReturn(List.of());
        when(resolver.loadInputsUncached(FEATURE, ORG)).thenReturn(inputs(true, null, false));
        when(lifecycle.platformPause(ORG)).thenReturn(List.of(THREE));

        reconciler.reconcileSafely(lifecycle, ORG, true);

        verify(changeAudit).recordBaselinePause(eq(ORG), eq(FEATURE), eq("ORG_TYPE"), any());
        verify(changeAudit, never()).recordForcedPause(anyLong(), anyString(), any(), any(), any());
        ArgumentCaptor<FeatureLifecycleState> saved = ArgumentCaptor.forClass(FeatureLifecycleState.class);
        verify(states).save(saved.capture());
        assertThat(saved.getValue().platformPaused()).isTrue();
        assertThat(saved.getValue().isNotificationOwed()).as("baseline: no email").isFalse();
    }

    @Test
    void withoutThePendingRowOrTheSwitchNothingIsPaused() {
        when(states.findForUpdate(ORG, FEATURE)).thenReturn(Optional.empty());
        when(transitions.pendingCovering(List.of(FEATURE), ORG, 0)).thenReturn(List.of());
        when(resolver.loadInputsUncached(FEATURE, ORG)).thenReturn(inputs(false, null, null));

        reconciler.reconcileSafely(lifecycle, ORG, false);

        verify(lifecycle, never()).platformPause(anyLong());
        verify(states, never()).save(any());
    }

    @Test
    void aSwitchOffUndoneBeforeItWasAppliedNetsToNothing() {
        when(states.findForUpdate(ORG, FEATURE)).thenReturn(Optional.empty());
        // Only the newest change of the scope is pending (the off was superseded by the on).
        when(transitions.pendingCovering(List.of(FEATURE), ORG, 0)).thenReturn(List.of(global(12, false, 99)));
        when(resolver.loadInputsUncached(FEATURE, ORG)).thenReturn(inputs(true, null, null));

        reconciler.reconcileSafely(lifecycle, ORG, true);

        verify(lifecycle, never()).platformPause(anyLong());
        verify(lifecycle, never()).platformResume(anyLong());
        ArgumentCaptor<FeatureLifecycleState> saved = ArgumentCaptor.forClass(FeatureLifecycleState.class);
        verify(states).save(saved.capture());
        assertThat(saved.getValue().appliedTransitionId()).isEqualTo(12);
        assertThat(saved.getValue().isNotificationOwed()).isFalse();
    }

    @Test
    void aForcedPauseByTheRequirementIsAuditedWithItAsTheCause() {
        FeatureFlagInputs requirementOff = new FeatureFlagInputs(REQUIRED, new GlobalRow(REQUIRED, false, "ORG",
                "PLATFORM"), ORG, "B2B", null, null, null);
        when(states.findForUpdate(ORG, FEATURE)).thenReturn(Optional.empty());
        when(transitions.pendingCovering(List.of(FEATURE), ORG, 0)).thenReturn(List.of(new ForcedTransition(15,
                REQUIRED, ForcedTransition.Scope.GLOBAL, null, null, true, null, 99, SweepCursor.Pass.PAUSE, 0)));
        when(resolver.loadInputsUncached(FEATURE, ORG))
                .thenReturn(inputs(true, null, null).withRequirement(requirementOff));
        when(lifecycle.platformPause(ORG)).thenReturn(List.of(THREE));

        reconciler.reconcileSafely(lifecycle, ORG, false);

        verify(changeAudit).recordForcedPause(eq(ORG), eq(FEATURE), eq(REQUIRED), any(), eq(99));
    }

    @Test
    void aForcedSwitchOffOfTheRequirementIsAForcedPause_andAnOwnLayerChangeOverItIsNot() {
        FeatureFlagInputs requirementOff = new FeatureFlagInputs(REQUIRED, new GlobalRow(REQUIRED, false, "ORG",
                "PLATFORM"), ORG, "B2B", null, null, null);
        FeatureFlagInputs now = inputs(true, null, null).withRequirement(requirementOff);
        ForcedTransition requirementChange = new ForcedTransition(15, REQUIRED, ForcedTransition.Scope.GLOBAL, null,
                null, true, null, 99, SweepCursor.Pass.PAUSE, 0);

        assertThat(FeatureLifecycleReconciler.switchedOffBy(List.of(requirementChange), now)).isTrue();
        assertThat(FeatureLifecycleReconciler.switchedOffBy(List.of(global(16, true, 99)), now))
                .as("the requirement was off already: baseline").isFalse();
    }

    @Test
    void twoPendingLayersSwitchedOffTogetherAreRolledBackTogether() {
        ForcedTransition orgType = new ForcedTransition(13, FEATURE, ForcedTransition.Scope.ORG_TYPE, "B2B", null,
                null, null, 99, SweepCursor.Pass.PAUSE, 0);

        assertThat(FeatureLifecycleReconciler.switchedOffBy(List.of(global(12, true, 99), orgType),
                inputs(false, null, false))).isTrue();
        assertThat(FeatureLifecycleReconciler.switchedOffBy(List.of(orgType), inputs(false, null, false)))
                .as("the global switch was off before the org-type change: baseline").isFalse();
    }

    @Test
    void lateRecordsOfAPausedOrganizationArePausedWithoutASecondEmail() {
        FeatureLifecycleState told = new FeatureLifecycleState(ORG, FEATURE, true, 1, 1, null, List.of(), null, 11, 1);
        when(states.findForUpdate(ORG, FEATURE)).thenReturn(Optional.of(told));
        when(transitions.pendingCovering(List.of(FEATURE), ORG, 11)).thenReturn(List.of());
        when(resolver.loadInputsUncached(FEATURE, ORG)).thenReturn(inputs(false, null, null));
        when(lifecycle.platformPause(ORG)).thenReturn(List.of(THREE));

        reconciler.reconcileSafely(lifecycle, ORG, false);

        verify(states, never()).save(any());
        verify(changeAudit).recordBaselinePause(eq(ORG), eq(FEATURE), eq("GLOBAL"), any());
        verify(notifier).sendOwed(told);
    }

    @Test
    void aClaimedPauseIsResumedWithARESUMEDEmail() {
        FeatureLifecycleState told = new FeatureLifecycleState(ORG, FEATURE, true, 1, 1, null, List.of(), null, 11, 1);
        when(states.findForUpdate(ORG, FEATURE)).thenReturn(Optional.of(told));
        when(transitions.pendingCovering(List.of(FEATURE), ORG, 11)).thenReturn(List.of(global(14, false, 98)));
        when(resolver.loadInputsUncached(FEATURE, ORG)).thenReturn(inputs(true, null, null));
        when(lifecycle.platformResume(ORG)).thenReturn(List.of(THREE));

        reconciler.reconcileSafely(lifecycle, ORG, false);

        ArgumentCaptor<FeatureLifecycleState> saved = ArgumentCaptor.forClass(FeatureLifecycleState.class);
        verify(states).save(saved.capture());
        assertThat(saved.getValue().idempotencyKey()).isEqualTo("7:DISCOVERY:RESUMED:2");
        assertThat(saved.getValue().appliedTransitionId()).isEqualTo(14);
        verify(changeAudit).recordPlatformTransition(eq(ORG), eq(FEATURE), eq(false), any(), eq(98));
    }

    @Test
    void anOrganizationThePlatformNeverPausedIsNeverResumed() {
        when(states.findForUpdate(ORG, FEATURE)).thenReturn(Optional.empty());
        when(transitions.pendingCovering(List.of(FEATURE), ORG, 0)).thenReturn(List.of());
        when(resolver.loadInputsUncached(FEATURE, ORG)).thenReturn(inputs(true, null, null));

        reconciler.reconcileSafely(lifecycle, ORG, true);

        verify(lifecycle, never()).platformResume(anyLong());
        verify(lifecycle, never()).platformPause(anyLong());
    }

    @Test
    void anOrgAdminsChangeUsesTheOpsSwitchForTheBaseline() {
        when(resolver.resolve(FeatureFlags.FEATURE_LIFECYCLE_RECONCILE, null)).thenReturn(false);
        when(states.findForUpdate(ORG, FEATURE)).thenReturn(Optional.empty());
        when(transitions.pendingCovering(List.of(FEATURE), ORG, 0)).thenReturn(List.of());
        when(resolver.loadInputsUncached(FEATURE, ORG)).thenReturn(inputs(true, new OrgOverride(false, false), null));

        reconciler.reconcileOrganization(FEATURE, ORG);

        verify(lifecycle, never()).platformPause(anyLong());
    }

    @Test
    void aFeatureWithoutPausableRecordsIsANoOp() {
        when(registry.findPausable("CERTIFICATE_RENEWAL")).thenReturn(Optional.empty());

        reconciler.reconcileOrganization("CERTIFICATE_RENEWAL", ORG);

        verify(lock, never()).lock(anyLong(), anyString());
    }

    @Test
    void aFailureIsReportedNotThrown() {
        when(states.findForUpdate(ORG, FEATURE)).thenThrow(new IllegalStateException("boom"));

        assertThat(reconciler.reconcileSafely(lifecycle, ORG, true)).isFalse();
    }

    @Test
    void owedEmailsAreResent() {
        FeatureLifecycleState owed = new FeatureLifecycleState(ORG, FEATURE, true, 1, 0,
                FeatureLifecycleState.Transition.PAUSED, List.of(THREE), NOW, 0, 0);
        when(states.findNotificationOwed(50)).thenReturn(List.of(owed));

        assertThat(reconciler.sendOwedNotifications(50)).isOne();
        verify(notifier).sendOwed(owed);
    }

    private static ForcedTransition global(long id, boolean beforeEnabled, Integer actor) {
        return new ForcedTransition(id, FEATURE, ForcedTransition.Scope.GLOBAL, null, null, beforeEnabled, null,
                actor, SweepCursor.Pass.PAUSE, 0);
    }

    /** B2B organization {@link #ORG}, ORG-scope PLATFORM-category flag. */
    private static FeatureFlagInputs inputs(boolean globalEnabled, OrgOverride override, Boolean orgTypeEnabled) {
        return new FeatureFlagInputs(FEATURE, new GlobalRow(FEATURE, globalEnabled, "ORG", "PLATFORM"), ORG,
                "B2B", override, orgTypeEnabled, null);
    }
}
