// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.service.FeatureFlagDecision.GlobalRow;
import com.certmanagement.service.FeatureFlagDecision.OffCause;
import com.certmanagement.service.FeatureFlagInputs;
import com.certmanagement.service.FeatureFlagResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.LongStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FeatureLifecycleSweeperTest {

    private static final String FEATURE = "DISCOVERY";
    private static final int PAGE = FeatureLifecycleSweeper.PAGE_SIZE;

    @Mock private FeatureLifecycleReconciler reconciler;
    @Mock private BaselineClassifier classifier;
    @Mock private FeatureFlagResolver resolver;
    @Mock private FeatureLifecycleStateStore states;
    @Mock private PlatformPausableLifecycle lifecycle;

    private FeatureLifecycleSweeper sweeper;

    @BeforeEach
    void setUp() {
        sweeper = new FeatureLifecycleSweeper(reconciler, classifier, resolver, states);
        lenient().when(lifecycle.featureKey()).thenReturn(FEATURE);
        lenient().when(reconciler.reconcileSafely(any(), anyLong(), eq(true))).thenReturn(true);
    }

    @Test
    void theSweepReconcilesTheBaselineCandidatesAndTheResumableOrganizationsOnly() {
        when(lifecycle.organizationsWithActiveRecords(0L, PAGE)).thenReturn(List.of(1L, 2L, 3L));
        when(lifecycle.organizationsWithActiveRecords(3L, PAGE)).thenReturn(List.of());
        when(classifier.baselineCandidates(FEATURE, List.of(1L, 2L, 3L))).thenReturn(Map.of(2L, OffCause.ORG_TYPE));
        when(states.platformPausedOrganizations(FEATURE, 0L, PAGE)).thenReturn(List.of(5L, 6L));
        when(states.platformPausedOrganizations(FEATURE, 6L, PAGE)).thenReturn(List.of());
        when(resolver.loadInputs(FEATURE, List.of(5L, 6L)))
                .thenReturn(Map.of(5L, inputs(5L, false), 6L, inputs(6L, true)));

        int reconciled = sweeper.sweep(lifecycle, SweepBudget.of(10, Duration.ofMinutes(1)), SweepCursor.fromStart());

        assertThat(reconciled).isEqualTo(2);
        verify(reconciler).reconcileSafely(lifecycle, 2L, true);
        verify(reconciler).reconcileSafely(lifecycle, 6L, true);
        verify(reconciler, times(2)).reconcileSafely(any(), anyLong(), eq(true));
    }

    @Test
    void aCappedSweepContinuesWhereItStoppedOnTheNextRun() {
        List<Long> page = LongStream.rangeClosed(1, 5).boxed().toList();
        AtomicLong lastReconciled = new AtomicLong();
        when(lifecycle.organizationsWithActiveRecords(anyLong(), anyInt())).thenAnswer(call -> {
            long after = call.getArgument(0);
            return page.stream().filter(id -> id > after).toList();
        });
        when(classifier.baselineCandidates(eq(FEATURE), any())).thenAnswer(call -> {
            Map<Long, OffCause> all = new LinkedHashMap<>();
            List<Long> ids = call.getArgument(1);
            ids.forEach(id -> all.put(id, OffCause.GLOBAL));
            return all;
        });
        when(reconciler.reconcileSafely(eq(lifecycle), anyLong(), eq(true))).thenAnswer(call -> {
            lastReconciled.set(call.getArgument(1));
            return true;
        });
        SweepCursor cursor = SweepCursor.fromStart();

        assertThat(sweeper.sweep(lifecycle, SweepBudget.of(2, Duration.ofMinutes(1)), cursor)).isEqualTo(2);
        assertThat(lastReconciled).hasValue(2);
        assertThat(sweeper.sweep(lifecycle, SweepBudget.of(2, Duration.ofMinutes(1)), cursor)).isEqualTo(2);
        assertThat(lastReconciled).hasValue(4);
        assertThat(sweeper.sweep(lifecycle, SweepBudget.of(2, Duration.ofMinutes(1)), cursor)).isEqualTo(1);
        assertThat(lastReconciled).hasValue(5);
        // The pass finished, so the next run starts over from the first organization.
        assertThat(cursor.position(FEATURE, SweepCursor.Pass.PAUSE)).isZero();
    }

    @Test
    void anExpiredTimeBudgetStopsBeforeTheFirstOrganization() {
        AtomicLong nanos = new AtomicLong();
        SweepBudget budget = new SweepBudget(100, Duration.ofSeconds(1), nanos::get);
        nanos.set(Duration.ofSeconds(2).toNanos());

        assertThat(sweeper.sweep(lifecycle, budget, SweepCursor.fromStart())).isZero();
        verify(lifecycle, never()).organizationsWithActiveRecords(anyLong(), anyInt());
    }

    private static FeatureFlagInputs inputs(long organizationId, boolean enabled) {
        return new FeatureFlagInputs(FEATURE, new GlobalRow(FEATURE, enabled, "ORG", "PLATFORM"), organizationId,
                "B2B", null, null, null);
    }
}
