// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.entity.OrgTypeFeatureFlag;
import com.certmanagement.entity.OrganizationFeatureFlag;
import com.certmanagement.repository.GlobalFeatureFlagRepository;
import com.certmanagement.repository.OrgTypeFeatureFlagRepository;
import com.certmanagement.repository.OrganizationFeatureFlagRepository;
import com.certmanagement.repository.OrganizationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The page resolution the feature lifecycle reconciler screens organizations with gives, for every
 * organization, exactly what the single cached resolution would.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class FeatureFlagResolverBatchTest {

    private static final String KEY = "INTEGRATIONS";

    @Mock private GlobalFeatureFlagRepository globalRepo;
    @Mock private OrganizationFeatureFlagRepository orgRepo;
    @Mock private OrgTypeFeatureFlagRepository orgTypeRepo;
    @Mock private OrganizationRepository organizationRepo;

    private FeatureFlagResolver resolver;

    @BeforeEach
    void setUp() {
        resolver = new FeatureFlagResolver(globalRepo, orgRepo, orgTypeRepo, organizationRepo);
        global(true);
        // 1: org admin opted out; 2: B2B whose type default is off; 3: no org type; 4: super admin locked on
        // over a B2B "off" type default.
        when(organizationRepo.findOrgTypesByIdIn(List.of(1L, 2L, 3L, 4L))).thenReturn(List.of(
                orgType(1L, null), orgType(2L, "B2B"), orgType(3L, null), orgType(4L, "B2B")));
        when(orgRepo.findAllByFeatureKeyAndOrganizationIdIn(KEY, List.of(1L, 2L, 3L, 4L))).thenReturn(List.of(
                override(1L, false, false), override(4L, true, true)));
        when(orgTypeRepo.findAllByFeatureKey(KEY)).thenReturn(List.of(
                OrgTypeFeatureFlag.builder().orgType("B2B").featureKey(KEY).enabled(false).build()));
        for (long id = 1; id <= 4; id++) {
            String type = id % 2 == 0 ? "B2B" : null;
            when(organizationRepo.findOrgTypeById(id)).thenReturn(Optional.ofNullable(type));
        }
        when(orgRepo.findOverrideViewByOrganizationIdAndFeatureKey(1L, KEY)).thenReturn(Optional.of(view(false, false)));
        when(orgRepo.findOverrideViewByOrganizationIdAndFeatureKey(4L, KEY)).thenReturn(Optional.of(view(true, true)));
        when(orgTypeRepo.findEnabledByOrgTypeAndFeatureKey("B2B", KEY)).thenReturn(Optional.of(() -> false));
    }

    @Test
    void aPageResolvesExactlyAsEachOrganizationWouldOnItsOwn() {
        Map<Long, Boolean> page = resolver.resolveForOrganizations(KEY, List.of(1L, 2L, 3L, 4L));

        assertThat(page).containsExactlyInAnyOrderEntriesOf(Map.of(1L, false, 2L, false, 3L, true, 4L, true));
        for (long id = 1; id <= 4; id++) {
            assertThat(page.get(id)).as("organization %d", id).isEqualTo(resolver.resolveUncached(KEY, id));
        }
    }

    @Test
    void aGlobalSwitchOffIsOffEverywhere() {
        global(false);

        assertThat(resolver.resolveForOrganizations(KEY, List.of(1L, 2L, 3L, 4L))).containsOnlyKeys(1L, 2L, 3L, 4L)
                .doesNotContainValue(true);
    }

    @Test
    void anEmptyPageIsFree() {
        assertThat(resolver.resolveForOrganizations(KEY, List.of())).isEmpty();
        verify(globalRepo, never()).findResolutionViewByFeatureKey(anyString());
        verify(organizationRepo, never()).findOrgTypeById(anyLong());
    }

    private void global(boolean enabled) {
        GlobalFeatureFlag flag = GlobalFeatureFlag.builder().featureKey(KEY).scope("ORG").category("PLATFORM")
                .enabled(enabled).build();
        when(globalRepo.findResolutionViewByFeatureKey(KEY)).thenReturn(Optional.of(FeatureFlagResolverTest.view(flag)));
    }

    private static OrganizationRepository.OrgTypeView orgType(long id, String type) {
        return new OrganizationRepository.OrgTypeView() {
            @Override public Long getId() { return id; }
            @Override public String getOrgType() { return type; }
        };
    }

    private static OrganizationFeatureFlag override(long organizationId, boolean enabled, boolean adminLocked) {
        return OrganizationFeatureFlag.builder().organizationId(organizationId).featureKey(KEY).enabled(enabled)
                .adminLocked(adminLocked).build();
    }

    private static OrganizationFeatureFlagRepository.OverrideView view(boolean enabled, boolean adminLocked) {
        return new OrganizationFeatureFlagRepository.OverrideView() {
            @Override public Boolean getEnabled() { return enabled; }
            @Override public Boolean getAdminLocked() { return adminLocked; }
        };
    }
}
