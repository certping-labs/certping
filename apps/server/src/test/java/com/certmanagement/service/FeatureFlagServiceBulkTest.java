// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.entity.OrgTypeFeatureFlag;
import com.certmanagement.repository.GlobalFeatureFlagRepository;
import com.certmanagement.repository.OrganizationFeatureFlagRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.OrgTypeFeatureFlagRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.audit.FeatureFlagChangeAudit;
import com.certmanagement.service.lifecycle.FeatureLifecycleService;
import com.certmanagement.service.lifecycle.ForcedFlagChanges;
import com.certmanagement.testing.BeanProviders;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.springframework.context.ApplicationEventPublisher;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link FeatureFlagService#bulkSetOrgTypeOverrides(String, boolean)}.
 */
@ExtendWith(MockitoExtension.class)
class FeatureFlagServiceBulkTest {

    @Mock private GlobalFeatureFlagRepository       globalRepo;
    @Mock private OrganizationFeatureFlagRepository orgRepo;
    @Mock private OrgTypeFeatureFlagRepository      orgTypeRepo;
    @Mock private OrganizationRepository            organizationRepo;
    @Mock private FeatureFlagResolver               resolver;

    @Mock private ApplicationEventPublisher events;
    @Mock private FeatureFlagChangeAudit changeAudit;
    @Mock private FeatureLifecycleService lifecycleService;
    @Mock private ForcedFlagChanges forcedChanges;
    private FeatureFlagService service;

    @BeforeEach
    void stubMasterSwitches() {
        service = new FeatureFlagService(globalRepo, orgRepo, orgTypeRepo, organizationRepo, resolver,
                events, changeAudit, BeanProviders.of(FeatureLifecycleService.class, lifecycleService),
                BeanProviders.of(ForcedFlagChanges.class, forcedChanges));
        // Master switches are ON by default. These stubs are lenient because not every test
        // exercises a code path that reads flagProperties (e.g. bulkSetOrgTypeOverrides
        // does not call isEnabled/listEffective, so the stubs would otherwise be flagged
        // as unnecessary by Mockito's strict stubbing mode).
    }

    @AfterEach
    void clearContext() {
        GatewayRequestContext.clear();
    }

    // ── helpers ───────────────────────────────────────────────────────────

    /** Builds a GlobalFeatureFlag with the given scope, category, and enabled state. */
    private GlobalFeatureFlag global(String key, String scope, String category, boolean enabled) {
        return GlobalFeatureFlag.builder()
                .featureKey(key)
                .displayName(key)
                .scope(scope)
                .category(category)
                .enabled(enabled)
                .build();
    }

    // ── bulk tests ────────────────────────────────────────────────────────

    @Test
    void bulkSet_createsNewOverrideForEveryEligibleFlag() {
        GatewayRequestContext.set(42, "1", "req-1", "admin@example.com");

        GlobalFeatureFlag a = global("feat.a", "ORG", "B2B", true);
        GlobalFeatureFlag b = global("feat.b", "ORG", "B2B", true);

        when(globalRepo.findAll()).thenReturn(List.of(a, b));
        when(globalRepo.findByFeatureKey("feat.a")).thenReturn(Optional.of(a));
        when(globalRepo.findByFeatureKey("feat.b")).thenReturn(Optional.of(b));
        when(orgTypeRepo.findByOrgTypeAndFeatureKey(anyString(), anyString())).thenReturn(Optional.empty());
        when(orgTypeRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        List<OrgTypeFeatureFlag> result = service.bulkSetOrgTypeOverrides("B2B", true, null);

        assertThat(result).hasSize(2);
        assertThat(result).extracting(OrgTypeFeatureFlag::getFeatureKey)
                .containsExactlyInAnyOrder("feat.a", "feat.b");
        assertThat(result).allMatch(f -> Boolean.TRUE.equals(f.getEnabled()));
        assertThat(result).allMatch(f -> "B2B".equals(f.getOrgType()));
        verify(orgTypeRepo, times(2)).save(any(OrgTypeFeatureFlag.class));
    }

    @Test
    void bulkSet_disablesAllEligibleFlags() {
        GatewayRequestContext.set(7, "1", "req-2", "admin@example.com");

        GlobalFeatureFlag a = global("feat.a", "ORG", "B2B", true);

        when(globalRepo.findAll()).thenReturn(List.of(a));
        when(globalRepo.findByFeatureKey("feat.a")).thenReturn(Optional.of(a));
        when(orgTypeRepo.findByOrgTypeAndFeatureKey("B2B", "feat.a")).thenReturn(Optional.empty());
        when(orgTypeRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        List<OrgTypeFeatureFlag> result = service.bulkSetOrgTypeOverrides("B2B", false, null);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getEnabled()).isFalse();
    }

    @Test
    void bulkSet_updatesExistingOverrideInsteadOfCreatingNew() {
        GatewayRequestContext.set(99, "1", "req-3", "admin@example.com");

        GlobalFeatureFlag a = global("feat.a", "ORG", "B2B", true);
        OrgTypeFeatureFlag existing = OrgTypeFeatureFlag.builder()
                .id(10L).orgType("B2B").featureKey("feat.a").enabled(true).build();

        when(globalRepo.findAll()).thenReturn(List.of(a));
        when(globalRepo.findByFeatureKey("feat.a")).thenReturn(Optional.of(a));
        when(orgTypeRepo.findByOrgTypeAndFeatureKey("B2B", "feat.a")).thenReturn(Optional.of(existing));
        when(orgTypeRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        List<OrgTypeFeatureFlag> result = service.bulkSetOrgTypeOverrides("B2B", false, null);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getEnabled()).isFalse();
        verify(orgTypeRepo).save(existing);
    }

    @Test
    void bulkSet_skipsGloballyDisabledOrgScopedFlags() {
        GlobalFeatureFlag disabled = global("feat.x", "ORG", "B2B", false);
        when(globalRepo.findAll()).thenReturn(List.of(disabled));

        List<OrgTypeFeatureFlag> result = service.bulkSetOrgTypeOverrides("B2B", true, null);

        assertThat(result).isEmpty();
        verifyNoInteractions(orgTypeRepo);
    }

    @Test
    void bulkSet_skipsPlatformScopeFlags() {
        // PLATFORM-scope flags (formerly PLATFORM_ONLY and SUPER_ADMIN_ONLY) have no org-level
        // overrides and must never be touched by a bulk org-type operation.
        GlobalFeatureFlag platformScheduler = global("feat.y", "PLATFORM", "PLATFORM", true);
        GlobalFeatureFlag platformAdmin     = global("feat.z", "PLATFORM", "PLATFORM", true);
        when(globalRepo.findAll()).thenReturn(List.of(platformScheduler, platformAdmin));

        List<OrgTypeFeatureFlag> result = service.bulkSetOrgTypeOverrides("B2B", true, null);

        assertThat(result).isEmpty();
        verifyNoInteractions(orgTypeRepo);
    }

    @Test
    void bulkSet_skipsDisabledFlagsAndProcessesEnabledOnes() {
        GatewayRequestContext.set(1, "1", "req-4", "admin@example.com");

        GlobalFeatureFlag enabled  = global("feat.enabled",  "ORG", "B2B", true);
        GlobalFeatureFlag disabled = global("feat.disabled", "ORG", "B2B", false);
        GlobalFeatureFlag platform = global("feat.platform", "PLATFORM", "PLATFORM", true);

        when(globalRepo.findAll()).thenReturn(List.of(enabled, disabled, platform));
        when(globalRepo.findByFeatureKey("feat.enabled")).thenReturn(Optional.of(enabled));
        when(orgTypeRepo.findByOrgTypeAndFeatureKey("B2B", "feat.enabled")).thenReturn(Optional.empty());
        when(orgTypeRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        List<OrgTypeFeatureFlag> result = service.bulkSetOrgTypeOverrides("B2B", true, null);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getFeatureKey()).isEqualTo("feat.enabled");
        verify(orgTypeRepo, times(1)).save(any());
    }

    @Test
    void bulkSet_returnsEmptyWhenNoFlagsExist() {
        when(globalRepo.findAll()).thenReturn(List.of());

        List<OrgTypeFeatureFlag> result = service.bulkSetOrgTypeOverrides("B2B", true, null);

        assertThat(result).isEmpty();
        verifyNoInteractions(orgTypeRepo);
    }

    @Test
    void bulkSet_recordsForcedChangesInSortedKeyOrderSoConcurrentBulkWritesCannotDeadlock() {
        GatewayRequestContext.set(1, "1", "req-6", "admin@example.com");
        List<GlobalFeatureFlag> unsorted = List.of(global("feat.c", "ORG", "B2B", true),
                global("feat.a", "ORG", "B2B", true), global("feat.b", "ORG", "B2B", true));
        when(globalRepo.findAll()).thenReturn(unsorted);
        unsorted.forEach(g -> when(globalRepo.findByFeatureKey(g.getFeatureKey())).thenReturn(Optional.of(g)));
        when(orgTypeRepo.findByOrgTypeAndFeatureKey(anyString(), anyString())).thenReturn(Optional.empty());
        when(orgTypeRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        service.bulkSetOrgTypeOverrides("B2B", false, null);

        // Each forced record takes its feature's lock first, so recording order is locking order.
        var order = inOrder(forcedChanges);
        order.verify(forcedChanges).recordOrgType("feat.a", "B2B", null, false, 1);
        order.verify(forcedChanges).recordOrgType("feat.b", "B2B", null, false, 1);
        order.verify(forcedChanges).recordOrgType("feat.c", "B2B", null, false, 1);
    }
}
