// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.service.FeatureFlagStateChangedEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.task.TaskDecorator;
import org.springframework.core.task.TaskExecutor;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.time.Duration;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * Applies a committed flag write: a super admin's change is a forced transition walked by
 * {@link ForcedTransitionWalker} (one organization, or every organization for a global or org-type
 * write); an organization admin's own change reconciles that organization. Runs on a small dedicated
 * executor so the administrator's request returns at once; when that executor is full or the pod
 * stops, the transition stays pending and {@link FeatureLifecycleBackstopJob} applies it. The executor is owned here rather than declared as a bean, so it never
 * displaces the application's default task executor.
 */
@Slf4j
@Component
public class FeatureFlagStateChangeListener implements DisposableBean {

    /** Flag writes are rare; a short queue bounds memory, and an overflow is left to the backstop. */
    private static final int QUEUE_CAPACITY = 100;

    private final FeatureLifecycleRegistry registry;
    private final FeatureLifecycleReconciler reconciler;
    private final ForcedTransitionWalker walker;
    private final TaskExecutor executor;
    private final int maxOrganizations;
    private final Duration maxDuration;

    @Autowired
    public FeatureFlagStateChangeListener(
            FeatureLifecycleRegistry registry, FeatureLifecycleReconciler reconciler, ForcedTransitionWalker walker,
            TaskDecorator mdcTaskDecorator,
            @Value("${certping.feature-lifecycle.after-change.max-organizations:5000}") int maxOrganizations,
            @Value("${certping.feature-lifecycle.after-change.max-duration:PT10M}") Duration maxDuration) {
        this(registry, reconciler, walker, newExecutor(mdcTaskDecorator), maxOrganizations, maxDuration);
    }

    FeatureFlagStateChangeListener(FeatureLifecycleRegistry registry, FeatureLifecycleReconciler reconciler,
                                   ForcedTransitionWalker walker, TaskExecutor executor, int maxOrganizations,
                                   Duration maxDuration) {
        this.registry = registry;
        this.reconciler = reconciler;
        this.walker = walker;
        this.executor = executor;
        this.maxOrganizations = maxOrganizations;
        this.maxDuration = maxDuration;
    }

    private static ThreadPoolTaskExecutor newExecutor(TaskDecorator mdcTaskDecorator) {
        ThreadPoolTaskExecutor pool = new ThreadPoolTaskExecutor();
        pool.setCorePoolSize(1);
        pool.setMaxPoolSize(2);
        pool.setQueueCapacity(QUEUE_CAPACITY);
        pool.setThreadNamePrefix("feature-lifecycle-");
        pool.setTaskDecorator(mdcTaskDecorator);
        pool.setRejectedExecutionHandler(new ThreadPoolExecutor.AbortPolicy());
        pool.setWaitForTasksToCompleteOnShutdown(true);
        pool.setAwaitTerminationSeconds(30);
        pool.initialize();
        return pool;
    }

    @Override
    public void destroy() {
        if (executor instanceof ThreadPoolTaskExecutor pool) {
            pool.shutdown();
        }
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onFlagStateChanged(FeatureFlagStateChangedEvent event) {
        if (registry.findPausable(event.featureKey()).isEmpty()) {
            return;
        }
        try {
            executor.execute(() -> apply(event));
        } catch (TaskRejectedException e) {
            log.warn("[FeatureLifecycle] reconcile of {} not queued ({}); the backstop picks it up",
                    event.featureKey(), e.getMessage());
        }
    }

    private void apply(FeatureFlagStateChangedEvent event) {
        if (event.transitionId() != null) {
            int reconciled = walker.apply(event.transitionId(), SweepBudget.of(maxOrganizations, maxDuration));
            log.info("[FeatureLifecycle] {} changed: reconciled {} organization(s)", event.featureKey(), reconciled);
        } else if (event.organizationId() != null) {
            reconciler.reconcileOrganization(event.featureKey(), event.organizationId());
        }
    }
}
