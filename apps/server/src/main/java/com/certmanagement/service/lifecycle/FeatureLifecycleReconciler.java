// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.service.FeatureFlagInputs;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.audit.FeatureFlagChangeAudit;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Applies the NET effect of the feature flags to one (organization, feature), the source of truth for
 * platform pauses. Under the (organization, feature) lock it compares whether the
 * feature's automatic work may run now (uncached: the feature and the flag that work requires,
 * {@link FeatureFlags#AUTOMATIC_WORK_REQUIRES}) with what was last applied there:
 *
 * <ul>
 *   <li>On, and platform-paused: resume the PLATFORM-paused records (RESUMED email only if the pause's
 *       email was claimed).</li>
 *   <li>Off, not paused, and a pending forced transition switched it off here (the answer with that
 *       change rolled back is "on"): a FORCED pause and one PAUSED email.</li>
 *   <li>Off, not paused, and it was off before any pending change (an org admin, org-type default,
 *       category or global switch from before): a BASELINE pause, silent and audited, only while the
 *       {@code FEATURE_LIFECYCLE_RECONCILE} ops switch allows it.</li>
 *   <li>Off and already paused: records that slipped in are paused too, without a second email.</li>
 * </ul>
 *
 * <p>Every pending transition seen is then consumed for the organization (its id recorded in
 * {@code feature_lifecycle_state}), so a re-walk, a second pod or a backstop find never applies or
 * emails it again; a switch-off undone before it was applied nets to nothing. The email goes out
 * after commit.
 */
@Slf4j
@Service
public class FeatureLifecycleReconciler {

    private final FeatureLifecycleRegistry registry;
    private final FeatureFlagResolver resolver;
    private final FeatureLifecycleLock lock;
    private final FeatureLifecycleStateStore states;
    private final ForcedTransitionStore transitions;
    private final FeatureLifecycleNotifier notifier;
    private final FeatureFlagChangeAudit changeAudit;
    private final TransactionTemplate transactionTemplate;
    private final Clock clock;

    public FeatureLifecycleReconciler(FeatureLifecycleRegistry registry, FeatureFlagResolver resolver,
                                      FeatureLifecycleLock lock, FeatureLifecycleStateStore states,
                                      ForcedTransitionStore transitions, FeatureLifecycleNotifier notifier,
                                      FeatureFlagChangeAudit changeAudit, TransactionTemplate transactionTemplate,
                                      Clock clock) {
        this.registry = registry;
        this.resolver = resolver;
        this.lock = lock;
        this.states = states;
        this.transitions = transitions;
        this.notifier = notifier;
        this.changeAudit = changeAudit;
        this.transactionTemplate = transactionTemplate;
        this.clock = clock;
    }

    /**
     * Reconciles one organization after its admin changed {@code featureKey}; a feature without
     * pausable records is a no-op.
     */
    public void reconcileOrganization(String featureKey, long organizationId) {
        registry.findPausable(featureKey).ifPresent(lifecycle ->
                reconcileSafely(lifecycle, organizationId, isBaselineEnabled()));
    }

    /** Whether the ops switch lets baseline pauses happen (cached, like every flag read). */
    public boolean isBaselineEnabled() {
        return resolver.resolve(FeatureFlags.FEATURE_LIFECYCLE_RECONCILE, null);
    }

    /** Sends emails still owed (a crash or a notifier outage after a transition committed). */
    public int sendOwedNotifications(int limit) {
        List<FeatureLifecycleState> owed = states.findNotificationOwed(limit);
        owed.forEach(notifier::sendOwed);
        return owed.size();
    }

    /**
     * {@link #reconcile} plus the email after commit; never throws, the backstop retries a failure.
     *
     * @return whether the reconcile committed
     */
    boolean reconcileSafely(PlatformPausableLifecycle lifecycle, long organizationId, boolean baselineAllowed) {
        try {
            reconcile(lifecycle, organizationId, baselineAllowed).ifPresent(notifier::sendOwed);
            return true;
        } catch (RuntimeException e) {
            log.error("[FeatureLifecycle] reconcile failed for {} org={}; the backstop retries it",
                    lifecycle.featureKey(), organizationId, e);
            return false;
        }
    }

    /** One organization in one transaction; returns the committed state so its email can go out. */
    Optional<FeatureLifecycleState> reconcile(PlatformPausableLifecycle lifecycle, long organizationId,
                                              boolean baselineAllowed) {
        String featureKey = lifecycle.featureKey();
        return transactionTemplate.execute(status -> {
            lock.lock(organizationId, featureKey);
            Optional<FeatureLifecycleState> stored = states.findForUpdate(organizationId, featureKey);
            FeatureLifecycleState current = stored.orElseGet(() -> FeatureLifecycleState.initial(organizationId,
                    featureKey));
            List<ForcedTransition> pending = transitions.pendingCovering(FeatureFlags.automaticWorkKeys(featureKey),
                    organizationId, current.appliedTransitionId());
            FeatureFlagInputs now = resolver.loadInputsUncached(featureKey, organizationId);
            FeatureLifecycleState next = apply(lifecycle, current, pending, now, baselineAllowed);
            if (!pending.isEmpty()) {
                long newest = pending.get(pending.size() - 1).id();
                next = next.withAppliedTransition(newest);
            }
            if (stored.isEmpty() ? !next.equals(current) : !next.equals(stored.get())) {
                states.save(next);
            }
            return Optional.of(next);
        });
    }

    private FeatureLifecycleState apply(PlatformPausableLifecycle lifecycle, FeatureLifecycleState current,
                                        List<ForcedTransition> pending, FeatureFlagInputs now,
                                        boolean baselineAllowed) {
        long organizationId = current.organizationId();
        Integer actor = pending.isEmpty() ? null : pending.get(pending.size() - 1).actorUserId();
        if (now.automaticWorkEnabled()) {
            if (!current.platformPaused()) {
                return current;
            }
            List<AffectedItems> resumed = lifecycle.platformResume(organizationId);
            changeAudit.recordPlatformTransition(organizationId, lifecycle.featureKey(), false, auditItems(resumed),
                    actor);
            log.info("[FeatureLifecycle] resumed {} for org={}: {}", lifecycle.featureKey(), organizationId, resumed);
            return FeatureLifecycleTransitions.afterResume(current, resumed, now());
        }
        if (current.platformPaused()) {
            List<AffectedItems> late = lifecycle.platformPause(organizationId);
            if (!late.isEmpty()) {
                auditBaseline(lifecycle, organizationId, now, late);
            }
            return FeatureLifecycleTransitions.afterLatePause(current, late);
        }
        if (switchedOffBy(pending, now)) {
            List<AffectedItems> paused = lifecycle.platformPause(organizationId);
            if (!paused.isEmpty()) {
                changeAudit.recordForcedPause(organizationId, lifecycle.featureKey(), causeOf(now),
                        auditItems(paused), actor);
                log.info("[FeatureLifecycle] paused {} for org={}: {}", lifecycle.featureKey(), organizationId, paused);
            }
            return FeatureLifecycleTransitions.afterForcedPause(current, paused, now());
        }
        if (!baselineAllowed) {
            return current;
        }
        List<AffectedItems> paused = lifecycle.platformPause(organizationId);
        if (!paused.isEmpty()) {
            auditBaseline(lifecycle, organizationId, now, paused);
        }
        return FeatureLifecycleTransitions.afterBaselinePause(current, paused);
    }

    /**
     * Whether the pending forced changes switched the feature off here: with each changed layer put
     * back to its value before the change, the answer would be "on". Several pending layers (say a
     * global and an org-type switch-off) are rolled back together.
     */
    static boolean switchedOffBy(List<ForcedTransition> pending, FeatureFlagInputs now) {
        if (pending.isEmpty()) {
            return false;
        }
        FeatureFlagInputs before = now;
        for (ForcedTransition transition : pending) {
            if (transition.covers(now.organizationId(), now.orgType())) {
                before = transition.rollBack(before);
            }
        }
        return before.automaticWorkEnabled();
    }

    /** The required flag that stops the automatic work while the feature itself is on, else null. */
    private static String causeOf(FeatureFlagInputs now) {
        return now.enabled() && now.requirement() != null ? now.requirement().featureKey() : null;
    }

    private void auditBaseline(PlatformPausableLifecycle lifecycle, long organizationId, FeatureFlagInputs now,
                               List<AffectedItems> paused) {
        String cause = now.automaticWorkOffCause() == null ? "UNKNOWN" : now.automaticWorkOffCause().name();
        changeAudit.recordBaselinePause(organizationId, lifecycle.featureKey(), cause, auditItems(paused));
        log.info("[FeatureLifecycle] baseline paused {} for org={} (cause {}): {}", lifecycle.featureKey(),
                organizationId, cause, paused);
    }

    private Instant now() {
        return clock.instant().truncatedTo(ChronoUnit.SECONDS);
    }

    private static List<Map<String, Object>> auditItems(List<AffectedItems> changed) {
        return changed.stream()
                .map(item -> Map.<String, Object>of("kind", item.kind().name(), "label", item.label(),
                        "count", item.count()))
                .toList();
    }
}
