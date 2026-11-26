// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.FeatureInUseException;
import com.certmanagement.exception.ForbiddenException;
import com.certmanagement.security.Permissions;
import com.certmanagement.service.audit.FeatureFlagChangeAudit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FeatureLifecycleServiceTest {

    private static final long ORG = 7L;
    private static final String FEATURE = "CERT_DISCOVERY";
    private static final Blocker SCANS = new Blocker(BlockerKind.RUNNING_DISCOVERY_SCANS, "Running discovery scans", 3,
            "/discovery", List.of(ClearAction.CANCEL_ALL));
    private static final Set<String> MANAGE_SCANS = Set.of(Permissions.FEATURE_FLAGS_MANAGE,
            Permissions.CERTIFICATE_DEPLOY);

    @Mock private FeatureLifecycleRegistry registry;
    @Mock private FeatureLifecycleLock lock;
    @Mock private FeatureFlagChangeAudit changeAudit;
    @Mock private FeatureLifecycle lifecycle;

    private FeatureLifecycleService service;

    @BeforeEach
    void setUp() {
        service = new FeatureLifecycleService(registry, lock, changeAudit);
        lenient().when(registry.find(FEATURE)).thenReturn(Optional.of(lifecycle));
        lenient().when(lifecycle.featureKey()).thenReturn(FEATURE);
        lenient().when(lifecycle.kinds()).thenReturn(List.of(BlockerKind.RUNNING_DISCOVERY_SCANS));
        lenient().when(lifecycle.supportedActions(BlockerKind.RUNNING_DISCOVERY_SCANS))
                .thenReturn(Set.of(ClearAction.CANCEL_ALL));
    }

    @Test
    void aFeatureWithoutALifecycleHasNoBlockersAndNeedsNoLock() {
        when(registry.find("ALERTS")).thenReturn(Optional.empty());

        assertThat(service.blockers(ORG, "ALERTS")).isEmpty();
        service.lockAndAssertNothingInUse(ORG, "ALERTS");

        verifyNoInteractions(lock);
    }

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    private static void callerHolds(String... authorities) {
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("admin", null, authorities));
    }

    @Test
    void theSwitchOffIsRefusedWithTheBlockersAfterTakingTheLock() {
        callerHolds(Permissions.FEATURE_FLAGS_MANAGE, Permissions.CERTIFICATE_DEPLOY, "ROLE_ORGANIZATION_ADMIN");
        when(lifecycle.blockers(ORG)).thenReturn(List.of(SCANS));

        assertThatThrownBy(() -> service.lockAndAssertNothingInUse(ORG, FEATURE))
                .isInstanceOfSatisfying(FeatureInUseException.class, e -> {
                    assertThat(e.getFeatureKey()).isEqualTo(FEATURE);
                    assertThat(e.getBlockers()).containsExactly(SCANS);
                });
        InOrder order = inOrder(lock, lifecycle);
        order.verify(lock).lock(ORG, FEATURE);
        order.verify(lifecycle).blockers(ORG);
    }

    @Test
    void aClearFeatureMaySwitchOff() {
        when(lifecycle.blockers(ORG)).thenReturn(List.of());

        service.lockAndAssertNothingInUse(ORG, FEATURE);

        verify(lock).lock(ORG, FEATURE);
    }

    @Test
    void clearLocksAppliesAndAudits() {
        when(lifecycle.clear(ORG, BlockerKind.RUNNING_DISCOVERY_SCANS, ClearAction.CANCEL_ALL)).thenReturn(3);

        assertThat(service.clear(ORG, FEATURE, BlockerKind.RUNNING_DISCOVERY_SCANS, ClearAction.CANCEL_ALL, MANAGE_SCANS))
                .isEqualTo(3);

        InOrder order = inOrder(lock, lifecycle, changeAudit);
        order.verify(lock).lock(ORG, FEATURE);
        order.verify(lifecycle).clear(ORG, BlockerKind.RUNNING_DISCOVERY_SCANS, ClearAction.CANCEL_ALL);
        order.verify(changeAudit).recordClear(ORG, FEATURE, "RUNNING_DISCOVERY_SCANS", "CANCEL_ALL", 3);
    }

    @Test
    void aKindTheFeatureDoesNotHaveIsABadRequest() {
        assertThatThrownBy(() -> service.clear(ORG, FEATURE, BlockerKind.DEPLOYMENT_TARGETS, ClearAction.CLEAR_TARGETS,
                MANAGE_SCANS))
                .isInstanceOf(BadRequestException.class);
        when(registry.find("ALERTS")).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.clear(ORG, "ALERTS", BlockerKind.RUNNING_DISCOVERY_SCANS, ClearAction.PAUSE_ALL,
                MANAGE_SCANS))
                .isInstanceOf(BadRequestException.class);
        verifyNoInteractions(lock, changeAudit);
    }

    @Test
    void anUnsupportedActionIsRefusedBeforeAnythingChanges() {
        assertThatThrownBy(() -> service.clear(ORG, FEATURE, BlockerKind.RUNNING_DISCOVERY_SCANS, ClearAction.PAUSE_ALL,
                MANAGE_SCANS))
                .isInstanceOf(UnsupportedClearException.class);
        verify(lifecycle, never()).clear(anyLong(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
        verify(changeAudit, never()).recordClear(anyLong(), anyString(), anyString(), anyString(),
                org.mockito.ArgumentMatchers.anyInt());
    }

    @Test
    void theRefusedSwitchOffOffersOnlyTheActionsTheCallerMayPerform() {
        callerHolds(Permissions.FEATURE_FLAGS_MANAGE);
        when(lifecycle.blockers(ORG)).thenReturn(List.of(SCANS));

        assertThatThrownBy(() -> service.lockAndAssertNothingInUse(ORG, FEATURE))
                .isInstanceOfSatisfying(FeatureInUseException.class, e ->
                        assertThat(e.getBlockers()).singleElement().satisfies(blocker -> {
                            assertThat(blocker.count()).isEqualTo(3);
                            assertThat(blocker.actions()).isEmpty();
                        }));
    }

    @Test
    void blockersForTheCallerKeepTheCountsAndFilterTheActions() {
        when(lifecycle.blockers(ORG)).thenReturn(List.of(SCANS));

        assertThat(service.blockersFor(ORG, FEATURE, Set.of(Permissions.FEATURE_FLAGS_MANAGE)))
                .singleElement().satisfies(blocker -> {
                    assertThat(blocker.count()).isEqualTo(3);
                    assertThat(blocker.actions()).isEmpty();
                });
        assertThat(service.blockersFor(ORG, FEATURE, MANAGE_SCANS)).containsExactly(SCANS);
    }

    @Test
    void aClearWithoutTheRecordPermissionIsForbiddenBeforeAnythingChanges() {
        assertThatThrownBy(() -> service.clear(ORG, FEATURE, BlockerKind.RUNNING_DISCOVERY_SCANS, ClearAction.CANCEL_ALL,
                Set.of(Permissions.FEATURE_FLAGS_MANAGE)))
                .isInstanceOf(ForbiddenException.class)
                .hasMessageContaining(Permissions.CERTIFICATE_DEPLOY);
        verifyNoInteractions(lock, changeAudit);
        verify(lifecycle, never()).clear(anyLong(), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
    }
}
