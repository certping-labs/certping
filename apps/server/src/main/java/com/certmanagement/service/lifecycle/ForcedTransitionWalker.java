// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.service.FeatureFlagInputs;
import com.certmanagement.service.FeatureFlagResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Applies one forced transition (a super admin's flag change) everywhere it reaches, whatever the
 * {@code FEATURE_LIFECYCLE_RECONCILE} ops switch says. An organization override is one organization;
 * a global or org-type change walks organizations in pages: first those holding active records (a
 * switch-off pauses them), then the platform-paused ones (a switch-on resumes them), screening each
 * page with one batch flag load and reconciling only organizations it covers whose state calls for a
 * change. The walk saves its cursor on the row after every page, so a restarted pod continues it;
 * walking a page twice is harmless (each organization consumes the transition once). The row is
 * marked COMPLETE when the walk ends, and a superseded row stops walking.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ForcedTransitionWalker {

    private final FeatureLifecycleRegistry registry;
    private final FeatureLifecycleReconciler reconciler;
    private final ForcedTransitionStore transitions;
    private final FeatureLifecycleStateStore states;
    private final FeatureFlagResolver resolver;

    /** Applies the pending transition {@code transitionId}; a completed or superseded one is a no-op. */
    public int apply(long transitionId, SweepBudget budget) {
        return transitions.findPending(transitionId).map(transition -> apply(transition, budget)).orElse(0);
    }

    /**
     * Applies {@code transition} from where its walk stands until done or the budget runs out.
     *
     * @return organizations reconciled
     */
    int apply(ForcedTransition transition, SweepBudget budget) {
        Optional<PlatformPausableLifecycle> lifecycle = registry.findPausable(transition.featureKey());
        if (lifecycle.isEmpty()) {
            transitions.markComplete(transition.id());
            return 0;
        }
        boolean baselineAllowed = reconciler.isBaselineEnabled();
        if (transition.scope() == ForcedTransition.Scope.ORGANIZATION) {
            if (reconciler.reconcileSafely(lifecycle.get(), transition.organizationId(), baselineAllowed)) {
                transitions.markComplete(transition.id());
            }
            budget.consume();
            return 1;
        }
        return walk(lifecycle.get(), transition, budget, baselineAllowed);
    }

    private int walk(PlatformPausableLifecycle lifecycle, ForcedTransition transition, SweepBudget budget,
                     boolean baselineAllowed) {
        SweepCursor.Pass phase = transition.cursorPhase();
        long after = transition.cursorOrganizationId();
        int reconciled = 0;
        while (!budget.isExhausted()) {
            List<Long> page = page(lifecycle, phase, after);
            if (page.isEmpty()) {
                if (phase == SweepCursor.Pass.RESUME) {
                    transitions.markComplete(transition.id());
                    log.info("[FeatureLifecycle] forced change {} of {} applied everywhere", transition.id(),
                            transition.featureKey());
                    return reconciled;
                }
                phase = SweepCursor.Pass.RESUME;
                after = 0;
            } else {
                Map<Long, FeatureFlagInputs> inputs = resolver.loadInputs(lifecycle.featureKey(), page);
                for (Long organizationId : page) {
                    if (budget.isExhausted()) {
                        break;
                    }
                    if (needsChange(transition, phase, inputs.get(organizationId))) {
                        reconciler.reconcileSafely(lifecycle, organizationId, baselineAllowed);
                        budget.consume();
                        reconciled++;
                    }
                    after = organizationId;
                }
            }
            if (!transitions.saveCursor(transition.id(), phase, after)) {
                return reconciled;
            }
        }
        return reconciled;
    }

    private List<Long> page(PlatformPausableLifecycle lifecycle, SweepCursor.Pass phase, long after) {
        return phase == SweepCursor.Pass.PAUSE
                ? lifecycle.organizationsWithActiveRecords(after, FeatureLifecycleSweeper.PAGE_SIZE)
                : states.platformPausedOrganizations(lifecycle.featureKey(), after, FeatureLifecycleSweeper.PAGE_SIZE);
    }

    /** Covered, and off where the pass pauses or on where it resumes. */
    private static boolean needsChange(ForcedTransition transition, SweepCursor.Pass phase, FeatureFlagInputs inputs) {
        if (inputs == null || !transition.covers(inputs.organizationId(), inputs.orgType())) {
            return false;
        }
        boolean pausePass = phase == SweepCursor.Pass.PAUSE;
        return pausePass != inputs.automaticWorkEnabled();
    }
}
