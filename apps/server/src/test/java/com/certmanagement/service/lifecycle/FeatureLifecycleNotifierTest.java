// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.messaging.OrgAdminNotificationPublisher;
import com.certmanagement.repository.GlobalFeatureFlagRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.lifecycle.FeatureLifecycleState.Transition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FeatureLifecycleNotifierTest {

    private static final String FEATURE = "DISCOVERY";
    private static final FeatureLifecycleState OWED_PAUSE = new FeatureLifecycleState(42L, FEATURE, true, 3, 2,
            Transition.PAUSED, List.of(new AffectedItems(BlockerKind.RUNNING_DISCOVERY_SCANS, "Running discovery scans", 3)),
            Instant.parse("2026-10-06T09:15:00Z"), 0, 0);

    @Mock private ObjectProvider<OrgAdminNotificationPublisher> publisherProvider;
    @Mock private OrgAdminNotificationPublisher publisher;
    @Mock private GlobalFeatureFlagRepository globalFlags;
    @Mock private OrganizationRepository organizations;
    @Mock private FeatureLifecycleStateStore states;

    private FeatureLifecycleNotifier notifier;

    @BeforeEach
    void setUp() {
        notifier = new FeatureLifecycleNotifier(publisherProvider, globalFlags, organizations, states);
        lenient().when(publisherProvider.getIfAvailable()).thenReturn(publisher);
        lenient().when(organizations.findNameById(42L)).thenReturn(Optional.of("Acme Ltd"));
        lenient().when(states.claimPausedNotice(42L, FEATURE, 3)).thenReturn(true);
        lenient().when(globalFlags.findByFeatureKey(FEATURE)).thenReturn(Optional.of(
                GlobalFeatureFlag.builder().featureKey(FEATURE).displayName("Certificate Discovery").build()));
    }

    @Test
    void theOwedEmailIsClaimedThenGoesOutDeliverOnceToOrgAdminsWithTheContractFieldsThenIsMarkedSent() {
        notifier.sendOwed(OWED_PAUSE);

        org.mockito.InOrder order = org.mockito.Mockito.inOrder(states, publisher);
        order.verify(states).claimPausedNotice(42L, FEATURE, 3);
        order.verify(publisher).publishOnceToOrgAdmins(anyString(), anyString(), anyString(), any(), anyString());
        order.verify(states).markNotified(42L, FEATURE, 3);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> fields = ArgumentCaptor.forClass(Map.class);
        verify(publisher).publishOnceToOrgAdmins(eq("FEATURE_PAUSED"), eq("42"), eq("certping-cert-manager"),
                fields.capture(), eq("42:DISCOVERY:PAUSED:3"));
        assertThat(fields.getValue())
                .containsEntry("organizationId", 42L)
                .containsEntry("organizationName", "Acme Ltd")
                .containsEntry("featureKey", FEATURE)
                .containsEntry("featureName", "Certificate Discovery")
                .containsEntry("items", List.of(Map.of("label", "Running discovery scans", "count", 3)))
                .containsEntry("occurredAt", "2026-10-06T09:15:00Z")
                .containsEntry("idempotencyKey", "42:DISCOVERY:PAUSED:3");
        verify(states).markNotified(42L, FEATURE, 3);
    }

    @Test
    void aResumeUsesTheResumedAction() {
        FeatureLifecycleState resumed = new FeatureLifecycleState(42L, FEATURE, false, 4, 3, Transition.RESUMED,
                OWED_PAUSE.pendingItems(), OWED_PAUSE.pendingOccurredAt(), 0, 3);

        notifier.sendOwed(resumed);

        verify(publisher).publishOnceToOrgAdmins(eq("FEATURE_RESUMED"), eq("42"), anyString(), any(),
                eq("42:DISCOVERY:RESUMED:4"));
        verify(states, never()).claimPausedNotice(anyLong(), anyString(), anyLong());
    }

    @Test
    void aResumedEmailWithNothingResumedStillGoesOutWithEmptyItems() {
        FeatureLifecycleState resumed = new FeatureLifecycleState(42L, FEATURE, false, 4, 3, Transition.RESUMED,
                List.of(), OWED_PAUSE.pendingOccurredAt(), 0, 3);

        notifier.sendOwed(resumed);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> fields = ArgumentCaptor.forClass(Map.class);
        verify(publisher).publishOnceToOrgAdmins(eq("FEATURE_RESUMED"), eq("42"), anyString(), fields.capture(),
                anyString());
        assertThat(fields.getValue()).containsEntry("items", List.of());
    }

    @Test
    void aPausedEmailAResumeWithdrewIsNeverPublished() {
        when(states.claimPausedNotice(42L, FEATURE, 3)).thenReturn(false);

        notifier.sendOwed(OWED_PAUSE);

        verifyNoInteractions(publisher);
        verify(states, never()).markNotified(anyLong(), anyString(), anyLong());
    }

    @Test
    void nothingOwedSendsNothing() {
        notifier.sendOwed(new FeatureLifecycleState(42L, FEATURE, true, 3, 3, null, List.of(), null, 0, 0));

        verifyNoInteractions(publisher, states);
    }

    @Test
    void aFailedPublishLeavesTheEmailOwedForTheBackstop() {
        doThrow(new IllegalStateException("queue down")).when(publisher)
                .publishOnceToOrgAdmins(anyString(), anyString(), anyString(), any(), anyString());

        notifier.sendOwed(OWED_PAUSE);

        verify(states, never()).markNotified(anyLong(), anyString(), anyLong());
    }

    @Test
    void withoutASenderTheTransitionIsStillClosed() {
        when(publisherProvider.getIfAvailable()).thenReturn(null);

        notifier.sendOwed(OWED_PAUSE);

        verify(states).markNotified(42L, FEATURE, 3);
    }
}
