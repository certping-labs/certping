// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.repository.GlobalFeatureFlagRepository;
import com.certmanagement.repository.OrganizationFeatureFlagRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.OrgTypeFeatureFlagRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Exhaustive coverage of {@link FeatureFlagResolver#resolve(String, Long)} across the
 * resolution decision tree: global presence, kill switch, scope, and per-org / per-org-type overrides.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class FeatureFlagResolverTest {

    private static final String KEY = "TEST_FLAG";
    private static final long ORG_ID = 100L;

    @Mock private GlobalFeatureFlagRepository       globalRepo;
    @Mock private OrganizationFeatureFlagRepository orgRepo;
    @Mock private OrgTypeFeatureFlagRepository      orgTypeRepo;
    @Mock private OrganizationRepository            organizationRepo;

    @InjectMocks private FeatureFlagResolver resolver;

    @BeforeEach
    void defaults() {
        // Default: no overrides for any key/org/orgType lookup.
        when(orgRepo.findOverrideViewByOrganizationIdAndFeatureKey(anyOrg(), anyKey())).thenReturn(Optional.empty());
        when(orgTypeRepo.findEnabledByOrgTypeAndFeatureKey(anyType(), anyKey())).thenReturn(Optional.empty());
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private static Long anyOrg()  { return org.mockito.ArgumentMatchers.anyLong(); }
    private static String anyKey()  { return org.mockito.ArgumentMatchers.anyString(); }
    private static String anyType() { return org.mockito.ArgumentMatchers.anyString(); }

    private GlobalFeatureFlag flag(String scope, String category, boolean enabled) {
        return GlobalFeatureFlag.builder()
                .featureKey(KEY).displayName(KEY)
                .scope(scope).category(category).enabled(enabled).build();
    }

    private void stubGlobal(GlobalFeatureFlag g) {
        when(globalRepo.findResolutionViewByFeatureKey(KEY)).thenReturn(Optional.of(view(g)));
    }

    static GlobalFeatureFlagRepository.ResolutionView view(GlobalFeatureFlag g) {
        return new GlobalFeatureFlagRepository.ResolutionView() {
            @Override public Boolean getEnabled() { return g.getEnabled(); }
            @Override public String getCategory() { return g.getCategory(); }
            @Override public String getScope() { return g.getScope(); }
        };
    }

    private void stubOrgType(String orgType) {
        when(organizationRepo.findOrgTypeById(ORG_ID)).thenReturn(Optional.ofNullable(orgType));
    }

    private void stubOrgOverride(boolean enabled) {
        when(orgRepo.findOverrideViewByOrganizationIdAndFeatureKey(ORG_ID, KEY))
                .thenReturn(Optional.of(overrideView(enabled, false)));
    }

    /** A super admin's override: the row is admin-locked. */
    private void stubAdminLockedOverride(boolean enabled) {
        when(orgRepo.findOverrideViewByOrganizationIdAndFeatureKey(ORG_ID, KEY))
                .thenReturn(Optional.of(overrideView(enabled, true)));
    }

    private static OrganizationFeatureFlagRepository.OverrideView overrideView(boolean enabled, boolean adminLocked) {
        return new OrganizationFeatureFlagRepository.OverrideView() {
            @Override public Boolean getEnabled() { return enabled; }
            @Override public Boolean getAdminLocked() { return adminLocked; }
        };
    }

    private void stubOrgTypeOverride(String orgType, boolean enabled) {
        when(orgTypeRepo.findEnabledByOrgTypeAndFeatureKey(orgType, KEY)).thenReturn(Optional.of(() -> enabled));
    }

    // ── A. Global missing → fail-open ───────────────────────────────────

    @Test
    void missingGlobal_returnsTrueFailOpen() {
        when(globalRepo.findResolutionViewByFeatureKey(KEY)).thenReturn(Optional.empty());
        stubOrgType("B2B");
        assertThat(resolver.resolve(KEY, ORG_ID)).isTrue();
    }

    // ── B. Kill switch ──────────────────────────────────────────────────

    @Test
    void killSwitch_globalDisabled_returnsFalse() {
        stubGlobal(flag("ORG", "PLATFORM", false));
        stubOrgType("B2B");
        assertThat(resolver.resolve(KEY, ORG_ID)).isFalse();
    }

    @Test
    void killSwitch_overridesAnyOverride() {
        stubGlobal(flag("ORG", "PLATFORM", false));
        stubOrgType("B2B");
        // Even with an org override saying "enabled=true", a disabled global wins.
        stubOrgOverride(true);
        assertThat(resolver.resolve(KEY, ORG_ID)).isFalse();
    }

    // ── C. Platform-context check (orgId == null) ──────────────────────

    @Nested
    class PlatformContext {

        @Test
        void platformScope_platformCategory_nullOrg_returnsTrue() {
            stubGlobal(flag("PLATFORM", "PLATFORM", true));
            assertThat(resolver.resolve(KEY, null)).isTrue();
        }

        @Test
        void platformScope_killSwitch_nullOrg_returnsFalse() {
            stubGlobal(flag("PLATFORM", "PLATFORM", false));
            assertThat(resolver.resolve(KEY, null)).isFalse();
        }

        @Test
        void orgScope_nullOrg_returnsTrue_skipsOrgChecks() {
            // No org context: overrides cannot be evaluated; the kill switch still applies.
            stubGlobal(flag("ORG", "PLATFORM", true));
            assertThat(resolver.resolve(KEY, null)).isTrue();
        }
    }

    // ── D. PLATFORM scope ──────────────────────────────────────────────

    @Nested
    class PlatformScope {

        @Test
        void platformScope_withOrg_ignoresOrgOverrides() {
            stubGlobal(flag("PLATFORM", "PLATFORM", true));
            stubOrgType("B2B");
            // Even if an org row somehow existed, PLATFORM scope shouldn't read it.
            stubOrgOverride(false);
            assertThat(resolver.resolve(KEY, ORG_ID)).isTrue();
        }
    }

    // ── E. Override precedence ─────────────────────────────────────────

    @Nested
    class OverridePrecedence {

        @Test
        void orgAdminOverrideOn_doesNotUndoAnOrgTypeOff() {
            stubGlobal(flag("ORG", "PLATFORM", true));
            stubOrgType("B2B");
            stubOrgTypeOverride("B2B", false);
            stubOrgOverride(true);
            assertThat(resolver.resolve(KEY, ORG_ID)).isFalse();
        }

        @Test
        void orgAdminOverrideOff_winsOverAnOrgTypeOn() {
            stubGlobal(flag("ORG", "PLATFORM", true));
            stubOrgType("B2B");
            stubOrgTypeOverride("B2B", true);
            stubOrgOverride(false);
            assertThat(resolver.resolve(KEY, ORG_ID)).isFalse();
        }

        @Test
        void orgAdminOverrideOn_appliesWithoutAnOrgTypeOff() {
            stubGlobal(flag("ORG", "PLATFORM", true));
            stubOrgType("B2B");
            stubOrgOverride(true);
            assertThat(resolver.resolve(KEY, ORG_ID)).isTrue();
        }

        @Test
        void superAdminOverrideOn_winsOverAnOrgTypeOff() {
            stubGlobal(flag("ORG", "PLATFORM", true));
            stubOrgType("B2B");
            stubOrgTypeOverride("B2B", false);
            stubAdminLockedOverride(true);
            assertThat(resolver.resolve(KEY, ORG_ID)).isTrue();
        }

        @Test
        void superAdminOverrideOff_winsOverAnOrgTypeOn() {
            stubGlobal(flag("ORG", "PLATFORM", true));
            stubOrgType("B2B");
            stubOrgTypeOverride("B2B", true);
            stubAdminLockedOverride(false);
            assertThat(resolver.resolve(KEY, ORG_ID)).isFalse();
        }

        @Test
        void superAdminOverride_stillLosesToTheGlobalKillSwitch() {
            stubGlobal(flag("ORG", "PLATFORM", false));
            stubOrgType("B2B");
            stubAdminLockedOverride(true);
            assertThat(resolver.resolve(KEY, ORG_ID)).isFalse();
        }

        @Test
        void orgTypeOverride_appliesWhenNoOrgOverride() {
            stubGlobal(flag("ORG", "PLATFORM", true));
            stubOrgType("B2B");
            stubOrgTypeOverride("B2B", false);
            assertThat(resolver.resolve(KEY, ORG_ID)).isFalse();
        }

        @Test
        void noOverrides_globalEnabled_returnsTrue() {
            stubGlobal(flag("ORG", "PLATFORM", true));
            stubOrgType("B2B");
            assertThat(resolver.resolve(KEY, ORG_ID)).isTrue();
        }
    }
}
