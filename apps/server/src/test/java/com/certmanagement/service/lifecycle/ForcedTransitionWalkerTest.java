// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.service.FeatureFlagDecision.GlobalRow;
import com.certmanagement.service.FeatureFlagInputs;
import com.certmanagement.service.FeatureFlagResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ForcedTransitionWalkerTest {

    private static final String FEATURE = "DISCOVERY";
    private static final int PAGE = FeatureLifecycleSweeper.PAGE_SIZE;

    @Mock private FeatureLifecycleRegistry registry;
    @Mock private FeatureLifecycleReconciler reconciler;
    @Mock private ForcedTransitionStore transitions;
    @Mock private FeatureLifecycleStateStore states;
    @Mock private FeatureFlagResolver resolver;
    @Mock private PlatformPausableLifecycle lifecycle;

    private ForcedTransitionWalker walker;

    @BeforeEach
    void setUp() {
        walker = new ForcedTransitionWalker(registry, reconciler, transitions, states, resolver);
        lenient().when(lifecycle.featureKey()).thenReturn(FEATURE);
        lenient().when(registry.findPausable(FEATURE)).thenReturn(Optional.of(lifecycle));
        lenient().when(reconciler.isBaselineEnabled()).thenReturn(false);
    }

    @Test
    void anOrgTypeChangeReconcilesOnlyOrganizationsOfThatTypeWhoseStateCallsForIt() {
        ForcedTransition orgType = transition(ForcedTransition.Scope.ORG_TYPE, "B2B", null);
        when(lifecycle.organizationsWithActiveRecords(0L, PAGE)).thenReturn(List.of(1L, 2L, 3L));
        when(resolver.loadInputs(FEATURE, List.of(1L, 2L, 3L))).thenReturn(Map.of(
                1L, inputs(1L, "B2B", false), 2L, inputs(2L, null, false), 3L, inputs(3L, "B2B", true)));
        when(lifecycle.organizationsWithActiveRecords(3L, PAGE)).thenReturn(List.of());
        when(states.platformPausedOrganizations(FEATURE, 0L, PAGE)).thenReturn(List.of());
        when(transitions.saveCursor(eq(orgType.id()), any(), anyLong())).thenReturn(true);

        walker.apply(orgType, SweepBudget.of(100, Duration.ofMinutes(1)));

        verify(reconciler).reconcileSafely(lifecycle, 1L, false);
        verify(reconciler, never()).reconcileSafely(eq(lifecycle), eq(2L), anyBoolean());
        verify(reconciler, never()).reconcileSafely(eq(lifecycle), eq(3L), anyBoolean());
        verify(transitions).markComplete(orgType.id());
    }

    @Test
    void aRowSupersededMidWalkStopsWalking() {
        ForcedTransition global = transition(ForcedTransition.Scope.GLOBAL, null, null);
        when(lifecycle.organizationsWithActiveRecords(0L, PAGE)).thenReturn(List.of(1L));
        when(resolver.loadInputs(FEATURE, List.of(1L))).thenReturn(Map.of(1L, inputs(1L, "B2B", false)));
        when(transitions.saveCursor(global.id(), SweepCursor.Pass.PAUSE, 1L)).thenReturn(false);

        walker.apply(global, SweepBudget.of(100, Duration.ofMinutes(1)));

        verify(lifecycle, never()).organizationsWithActiveRecords(1L, PAGE);
        verify(transitions, never()).markComplete(anyLong());
    }

    @Test
    void anOrganizationRowIsCompletedOnlyWhenItsReconcileCommitted() {
        ForcedTransition organization = transition(ForcedTransition.Scope.ORGANIZATION, null, 7L);
        when(reconciler.reconcileSafely(lifecycle, 7L, false)).thenReturn(false, true);

        walker.apply(organization, SweepBudget.of(100, Duration.ofMinutes(1)));
        verify(transitions, never()).markComplete(anyLong());

        walker.apply(organization, SweepBudget.of(100, Duration.ofMinutes(1)));
        verify(transitions).markComplete(organization.id());
    }

    @Test
    void aCompletedOrSupersededRowIsANoOp() {
        when(transitions.findPending(5L)).thenReturn(Optional.empty());

        assertThat(walker.apply(5L, SweepBudget.of(100, Duration.ofMinutes(1)))).isZero();
        verify(reconciler, never()).reconcileSafely(any(), anyLong(), anyBoolean());
    }

    private static ForcedTransition transition(ForcedTransition.Scope scope, String orgType, Long organizationId) {
        return new ForcedTransition(5, FEATURE, scope, orgType, organizationId, true, null, 9,
                SweepCursor.Pass.PAUSE, 0);
    }

    private static FeatureFlagInputs inputs(long organizationId, String orgType, boolean enabled) {
        return new FeatureFlagInputs(FEATURE, new GlobalRow(FEATURE, enabled, "ORG", "PLATFORM"), organizationId,
                orgType, null, null, null);
    }
}
