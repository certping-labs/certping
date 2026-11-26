// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.service.FeatureFlagInputs;
import com.certmanagement.service.FeatureFlagResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The BASELINE and backstop sweep of one feature, run by {@link FeatureLifecycleBackstopJob} only
 * while the {@code FEATURE_LIFECYCLE_RECONCILE} ops switch is on. Its pause pass pages the
 * organizations holding active records and pauses, silently, those {@link BaselineClassifier} picks
 * (the feature's automatic work is off for them and no forced change is pending); its resume pass pages
 * the platform-paused organizations and resumes those whose automatic work may run again. Each organization is
 * then reconciled under its lock by {@link FeatureLifecycleReconciler}.
 */
@Service
@RequiredArgsConstructor
public class FeatureLifecycleSweeper {

    static final int PAGE_SIZE = 200;

    private final FeatureLifecycleReconciler reconciler;
    private final BaselineClassifier classifier;
    private final FeatureFlagResolver resolver;
    private final FeatureLifecycleStateStore states;

    /**
     * Sweeps {@code lifecycle} from the cursor's positions until done or the budget runs out; the
     * cursor then holds where to continue.
     *
     * @return organizations reconciled
     */
    public int sweep(PlatformPausableLifecycle lifecycle, SweepBudget budget, SweepCursor cursor) {
        String featureKey = lifecycle.featureKey();
        int reconciled = sweepPass(lifecycle, budget, cursor, SweepCursor.Pass.PAUSE,
                lifecycle::organizationsWithActiveRecords,
                page -> classifier.baselineCandidates(featureKey, page).keySet());
        if (!budget.isExhausted()) {
            reconciled += sweepPass(lifecycle, budget, cursor, SweepCursor.Pass.RESUME,
                    (after, limit) -> states.platformPausedOrganizations(featureKey, after, limit),
                    page -> automaticWorkEnabled(resolver.loadInputs(featureKey, page)));
        }
        return reconciled;
    }

    private int sweepPass(PlatformPausableLifecycle lifecycle, SweepBudget budget, SweepCursor cursor,
                          SweepCursor.Pass pass, BiFunction<Long, Integer, List<Long>> page,
                          Function<List<Long>, Set<Long>> select) {
        String featureKey = lifecycle.featureKey();
        int reconciled = 0;
        while (!budget.isExhausted()) {
            List<Long> organizationIds = page.apply(cursor.position(featureKey, pass), PAGE_SIZE);
            if (organizationIds.isEmpty()) {
                cursor.finish(featureKey, pass);
                return reconciled;
            }
            Set<Long> selected = select.apply(organizationIds);
            for (Long organizationId : organizationIds) {
                if (budget.isExhausted()) {
                    return reconciled;
                }
                if (selected.contains(organizationId)) {
                    reconciler.reconcileSafely(lifecycle, organizationId, true);
                    budget.consume();
                    reconciled++;
                }
                cursor.advance(featureKey, pass, organizationId);
            }
        }
        return reconciled;
    }

    private static Set<Long> automaticWorkEnabled(Map<Long, FeatureFlagInputs> inputs) {
        return inputs.entrySet().stream().filter(entry -> entry.getValue().automaticWorkEnabled())
                .map(Map.Entry::getKey).collect(Collectors.toSet());
    }
}
