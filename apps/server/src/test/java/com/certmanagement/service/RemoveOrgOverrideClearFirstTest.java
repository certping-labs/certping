// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.entity.OrgTypeFeatureFlag;
import com.certmanagement.entity.OrganizationFeatureFlag;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.FeatureInUseException;
import com.certmanagement.repository.GlobalFeatureFlagRepository;
import com.certmanagement.repository.OrgTypeFeatureFlagRepository;
import com.certmanagement.repository.OrganizationFeatureFlagRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.audit.FeatureFlagChangeAudit;
import com.certmanagement.service.lifecycle.FeatureLifecycleService;
import com.certmanagement.service.lifecycle.ForcedFlagChanges;
import com.certmanagement.testing.BeanProviders;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The org admin's DELETE of an override runs clear-first when it would switch the feature off, in the
 * same transaction and before the row is removed; any other removal runs no guard.
 */
@ExtendWith(MockitoExtension.class)
class RemoveOrgOverrideClearFirstTest {

    private static final long ORG_ID = 1L;
    private static final String KEY = "INTEGRATIONS";

    @Mock private GlobalFeatureFlagRepository globalRepo;
    @Mock private OrganizationFeatureFlagRepository orgRepo;
    @Mock private OrgTypeFeatureFlagRepository orgTypeRepo;
    @Mock private OrganizationRepository organizationRepo;
    @Mock private FeatureFlagResolver resolver;
    @Mock private ApplicationEventPublisher events;
    @Mock private FeatureFlagChangeAudit changeAudit;
    @Mock private FeatureLifecycleService lifecycleService;
    @Mock private ForcedFlagChanges forcedChanges;
    private FeatureFlagService service;

    @BeforeEach
    void setUp() {
        service = new FeatureFlagService(globalRepo, orgRepo, orgTypeRepo, organizationRepo, resolver,
                events, changeAudit, BeanProviders.of(FeatureLifecycleService.class, lifecycleService),
                BeanProviders.of(ForcedFlagChanges.class, forcedChanges));
        lenient().when(globalRepo.findByFeatureKey(KEY)).thenReturn(Optional.of(GlobalFeatureFlag.builder()
                .featureKey(KEY).scope("ORG").category("PLATFORM").enabled(true).build()));
        lenient().when(organizationRepo.findOrgTypeById(ORG_ID)).thenReturn(Optional.of("B2B"));
        lenient().when(orgRepo.softDeleteUnlockedByOrganizationIdAndFeatureKey(ORG_ID, KEY)).thenReturn(1);
    }

    /**
     * Today's precedence never lets an unlocked override's removal switch a feature off (the tests
     * below pin that), so the state change is stubbed to exercise the guard's wiring.
     */
    @Test
    void onToOff_withBlockers_is409_andTheOverrideStays() {
        holdOverride(true, false);
        FeatureFlagService switchingOff = removalThatSwitchesOff();
        doThrow(new FeatureInUseException(KEY, List.of()))
                .when(lifecycleService).lockAndAssertNothingInUse(ORG_ID, KEY);

        assertThatThrownBy(() -> switchingOff.removeOrgOverride(ORG_ID, KEY, null))
                .isInstanceOf(FeatureInUseException.class);

        verify(orgRepo, never()).softDeleteUnlockedByOrganizationIdAndFeatureKey(any(), any());
        verifyNoInteractions(changeAudit);
    }

    @Test
    void onToOff_withNothingInUse_runsTheGuardBeforeTheDelete() {
        holdOverride(true, false);

        assertThat(removalThatSwitchesOff().removeOrgOverride(ORG_ID, KEY, null)).isTrue();

        InOrder order = inOrder(lifecycleService, orgRepo);
        order.verify(lifecycleService).lockAndAssertNothingInUse(ORG_ID, KEY);
        order.verify(orgRepo).softDeleteUnlockedByOrganizationIdAndFeatureKey(ORG_ID, KEY);
    }

    @Test
    void offToOn_runsNoGuard() {
        OrganizationFeatureFlag override = holdOverride(false, false);

        assertThat(service.removalSwitchesOff(ORG_ID, KEY, override)).isFalse();
        assertThat(service.removeOrgOverride(ORG_ID, KEY, null)).isTrue();

        verifyNoInteractions(lifecycleService);
    }

    @Test
    void onStaysOn_runsNoGuard() {
        OrganizationFeatureFlag override = holdOverride(true, false);

        assertThat(service.removalSwitchesOff(ORG_ID, KEY, override)).isFalse();
        assertThat(service.removeOrgOverride(ORG_ID, KEY, null)).isTrue();

        verifyNoInteractions(lifecycleService);
    }

    @Test
    void offStaysOffUnderAnOrgTypeOff_runsNoGuard() {
        OrganizationFeatureFlag override = holdOverride(true, false);
        when(orgTypeRepo.findByOrgTypeAndFeatureKey("B2B", KEY)).thenReturn(Optional.of(
                OrgTypeFeatureFlag.builder().orgType("B2B").featureKey(KEY).enabled(false).build()));

        assertThat(service.removalSwitchesOff(ORG_ID, KEY, override)).isFalse();
        assertThat(service.removeOrgOverride(ORG_ID, KEY, null)).isTrue();

        verifyNoInteractions(lifecycleService);
    }

    @Test
    void adminLocked_isStill400_withNoGuardAndNoDelete() {
        holdOverride(true, true);

        assertThatThrownBy(() -> service.removeOrgOverride(ORG_ID, KEY, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("only a platform administrator can remove it");

        verifyNoInteractions(lifecycleService, changeAudit);
        verify(orgRepo, never()).softDeleteUnlockedByOrganizationIdAndFeatureKey(any(), any());
    }

    private OrganizationFeatureFlag holdOverride(boolean enabled, boolean adminLocked) {
        OrganizationFeatureFlag override = OrganizationFeatureFlag.builder().id(4L).organizationId(ORG_ID)
                .featureKey(KEY).enabled(enabled).adminLocked(adminLocked).build();
        when(orgRepo.findByOrganizationIdAndFeatureKey(ORG_ID, KEY)).thenReturn(Optional.of(override));
        return override;
    }

    private FeatureFlagService removalThatSwitchesOff() {
        FeatureFlagService switchingOff = spy(service);
        doReturn(true).when(switchingOff).removalSwitchesOff(eq(ORG_ID), eq(KEY), any());
        return switchingOff;
    }
}
