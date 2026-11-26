// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.service.FeatureFlagStateChangedEvent;
import com.certmanagement.service.audit.FeatureFlagChangeAudit.OverrideState;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ForcedFlagChangesTest {

    @Mock private FeatureLifecycleRegistry registry;
    @Mock private ForcedTransitionStore transitions;
    @Mock private ApplicationEventPublisher events;
    @Mock private PlatformPausableLifecycle lifecycle;
    @InjectMocks private ForcedFlagChanges forcedChanges;

    @Test
    void aSuperAdminOverrideIsRecordedWithItsValueBeforeAndAnnouncedWithItsId() {
        when(registry.findPausable("CERTIFICATE_DEPLOYMENT")).thenReturn(Optional.of(lifecycle));
        when(transitions.insert("CERTIFICATE_DEPLOYMENT", ForcedTransition.Scope.ORGANIZATION, null, 7L, true, false, false,
                true, 9)).thenReturn(31L);

        forcedChanges.recordOrganization("CERTIFICATE_DEPLOYMENT", 7L, new OverrideState(true, false),
                new OverrideState(false, true), 9);

        verify(events).publishEvent(new FeatureFlagStateChangedEvent("CERTIFICATE_DEPLOYMENT", 7L, 9, 31L));
    }

    @Test
    void aGlobalChangeCoversEveryOrganization() {
        when(registry.findPausable("DISCOVERY")).thenReturn(Optional.of(lifecycle));
        when(transitions.insert("DISCOVERY", ForcedTransition.Scope.GLOBAL, null, null, true, null, false, null, 9))
                .thenReturn(32L);

        forcedChanges.recordGlobal("DISCOVERY", true, false, 9);

        verify(events).publishEvent(new FeatureFlagStateChangedEvent("DISCOVERY", null, 9, 32L));
    }

    @Test
    void aRequiredFlagsChangeTakesTheWriteLockOfTheLifecycleItPauses() {
        when(registry.findPausable("DNS_CREDENTIALS")).thenReturn(Optional.of(lifecycle));
        when(lifecycle.featureKey()).thenReturn("CERTIFICATE_RENEWAL");

        forcedChanges.recordGlobal("DNS_CREDENTIALS", true, false, 9);

        var order = inOrder(transitions);
        order.verify(transitions).lockFeatureForWrite("CERTIFICATE_RENEWAL");
        order.verify(transitions).insert("DNS_CREDENTIALS", ForcedTransition.Scope.GLOBAL, null, null, true, null,
                false, null, 9);
    }

    @Test
    void aFeatureWithNothingToPauseRecordsNothing() {
        when(registry.findPausable("CERTIFICATE_RENEWAL")).thenReturn(Optional.empty());

        forcedChanges.recordOrgType("CERTIFICATE_RENEWAL", "B2B", null, false, 9);

        verifyNoInteractions(transitions, events);
    }

    @Test
    void theFeatureWriteLockIsTakenBeforeTheTransitionRowIsWritten() {
        when(registry.findPausable("DISCOVERY")).thenReturn(Optional.of(lifecycle));
        when(lifecycle.featureKey()).thenReturn("DISCOVERY");

        forcedChanges.recordGlobal("DISCOVERY", true, false, 9);

        var order = inOrder(transitions);
        order.verify(transitions).lockFeatureForWrite("DISCOVERY");
        order.verify(transitions).insert("DISCOVERY", ForcedTransition.Scope.GLOBAL, null, null, true, null, false,
                null, 9);
    }

    @Test
    void theWriteLockKeyIsPerFeatureAndApartFromTheLifecycleLocks() {
        long key = ForcedTransitionStore.writeLockKey("DISCOVERY");

        assertThat(ForcedTransitionStore.writeLockKey("DISCOVERY")).isEqualTo(key);
        assertThat(ForcedTransitionStore.writeLockKey("CERTIFICATE_DEPLOYMENT")).isNotEqualTo(key);
        assertThat(key).isEqualTo(AdvisoryLockKeys.keyOf("certping:forced-transition:DISCOVERY"))
                .isNotEqualTo(FeatureLifecycleLock.lockKey(1L, "DISCOVERY"));
    }
}
