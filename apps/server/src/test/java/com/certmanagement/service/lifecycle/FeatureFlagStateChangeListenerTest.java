// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.service.FeatureFlagStateChangedEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.task.SyncTaskExecutor;
import org.springframework.core.task.TaskExecutor;
import org.springframework.core.task.TaskRejectedException;

import java.time.Duration;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FeatureFlagStateChangeListenerTest {

    @Mock private FeatureLifecycleRegistry registry;
    @Mock private FeatureLifecycleReconciler reconciler;
    @Mock private ForcedTransitionWalker walker;
    @Mock private PlatformPausableLifecycle lifecycle;

    @Test
    void anOrgAdminsOwnWriteReconcilesThatOrganizationOnly() {
        when(registry.findPausable("DISCOVERY")).thenReturn(Optional.of(lifecycle));

        listener(new SyncTaskExecutor())
                .onFlagStateChanged(new FeatureFlagStateChangedEvent("DISCOVERY", 7L, 3, null));

        verify(reconciler).reconcileOrganization("DISCOVERY", 7L);
        verifyNoInteractions(walker);
    }

    @Test
    void aSuperAdminsChangeWalksItsForcedTransition() {
        when(registry.findPausable("DISCOVERY")).thenReturn(Optional.of(lifecycle));

        listener(new SyncTaskExecutor())
                .onFlagStateChanged(new FeatureFlagStateChangedEvent("DISCOVERY", null, 3, 41L));

        verify(walker).apply(eq(41L), any(SweepBudget.class));
        verifyNoInteractions(reconciler);
    }

    @Test
    void aFeatureWithoutPausableRecordsQueuesNothing() {
        when(registry.findPausable("ALERTS")).thenReturn(Optional.empty());

        listener(task -> { throw new AssertionError("nothing to queue"); })
                .onFlagStateChanged(new FeatureFlagStateChangedEvent("ALERTS", null, 3, 5L));
    }

    @Test
    void aFullQueueIsLeftToTheBackstopWithoutFailingTheWrite() {
        when(registry.findPausable("DISCOVERY")).thenReturn(Optional.of(lifecycle));

        listener(task -> { throw new TaskRejectedException("full"); })
                .onFlagStateChanged(new FeatureFlagStateChangedEvent("DISCOVERY", 7L, 3, 9L));

        verifyNoInteractions(reconciler, walker);
    }

    private FeatureFlagStateChangeListener listener(TaskExecutor executor) {
        return new FeatureFlagStateChangeListener(registry, reconciler, walker, executor, 10, Duration.ofMinutes(1));
    }
}
