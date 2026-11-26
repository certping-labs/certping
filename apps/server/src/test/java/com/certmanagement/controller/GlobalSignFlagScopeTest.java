// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.dto.featureflags.FeatureFlagUpdateRequest;
import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.entity.OrgTypeFeatureFlag;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.repository.GlobalFeatureFlagRepository;
import com.certmanagement.repository.OrgTypeFeatureFlagRepository;
import com.certmanagement.repository.OrganizationFeatureFlagRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.audit.FeatureFlagChangeAudit;
import com.certmanagement.service.cert.CertIssuanceService;
import com.certmanagement.service.lifecycle.FeatureLifecycleService;
import com.certmanagement.service.lifecycle.ForcedFlagChanges;
import com.certmanagement.testing.BeanProviders;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationEventPublisher;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The GLOBALSIGN flag as the baseline seeds it (ORG scope, PLATFORM category, on), decided by the real resolver: an
 * organization admin cannot bring GlobalSign back for their workspace once CertPing has switched it off,
 * globally or for the organization type. Issuance asks {@link FeatureFlagService#assertCaEnabled} and
 * the renewal trigger {@link FeatureFlagService#isEnabled} for this key before anything else.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class GlobalSignFlagScopeTest {

    private static final long ORG_ID = 100L;
    private static final String GLOBALSIGN = CertIssuanceService.toCaFeatureKey(CaProvider.GLOBALSIGN);

    @Mock private GlobalFeatureFlagRepository globalRepo;
    @Mock private OrganizationFeatureFlagRepository orgRepo;
    @Mock private OrgTypeFeatureFlagRepository orgTypeRepo;
    @Mock private OrganizationRepository organizationRepo;
    @Mock private ApplicationEventPublisher events;
    @Mock private FeatureFlagChangeAudit changeAudit;

    private FeatureFlagService service;
    private FeatureFlagController controller;

    @BeforeEach
    void setUp() {
        FeatureFlagResolver resolver = new FeatureFlagResolver(globalRepo, orgRepo, orgTypeRepo, organizationRepo);
        service = new FeatureFlagService(globalRepo, orgRepo, orgTypeRepo, organizationRepo, resolver,
                events, changeAudit,
                BeanProviders.of(FeatureLifecycleService.class, mock(FeatureLifecycleService.class)),
                BeanProviders.of(ForcedFlagChanges.class, mock(ForcedFlagChanges.class)));
        controller = new FeatureFlagController(service, mock(FeatureLifecycleService.class));
        GatewayRequestContext.set(7, String.valueOf(ORG_ID), "req-test", "admin@example.com");
        when(organizationRepo.findOrgTypeById(ORG_ID)).thenReturn(Optional.of("B2B"));
        when(orgRepo.findOverrideViewByOrganizationIdAndFeatureKey(any(), any())).thenReturn(Optional.empty());
        when(orgTypeRepo.findEnabledByOrgTypeAndFeatureKey(any(), any())).thenReturn(Optional.empty());
        when(orgRepo.findByOrganizationIdAndFeatureKey(any(), any())).thenReturn(Optional.empty());
        when(orgTypeRepo.findByOrgTypeAndFeatureKey(any(), any())).thenReturn(Optional.empty());
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void globallyOff_anOrgAdminCannotSwitchGlobalSignOn() {
        globalSign(false);

        assertThatThrownBy(() -> controller.updateOrgFlag(GLOBALSIGN, enable())).isInstanceOf(BadRequestException.class);
        verify(orgRepo, never()).save(any());
    }

    @Test
    void globallyOff_anOrgAdminsOverrideFromBeforeDoesNotBringItBack() {
        globalSign(false);
        orgAdminOverride(true);
        orgTypeDefault(true);

        assertGlobalSignOffForTheOrganization();
    }

    @Test
    void offForTheOrganizationType_anOrgAdminCannotSwitchGlobalSignOn() {
        globalSign(true);
        orgTypeDefault(false);

        assertThatThrownBy(() -> controller.updateOrgFlag(GLOBALSIGN, enable())).isInstanceOf(BadRequestException.class);
        verify(orgRepo, never()).save(any());
    }

    @Test
    void offForTheOrganizationType_anOrgAdminsOverrideFromBeforeDoesNotBringItBack() {
        globalSign(true);
        orgTypeDefault(false);
        orgAdminOverride(true);

        assertGlobalSignOffForTheOrganization();
    }

    @Test
    void onGloballyAndForTheType_itIsOnForTheOrganization() {
        globalSign(true);

        assertThat(service.isEnabled(GLOBALSIGN, ORG_ID)).isTrue();
    }

    private void assertGlobalSignOffForTheOrganization() {
        assertThat(service.isEnabled(GLOBALSIGN, ORG_ID)).as("the renewal trigger's check").isFalse();
        assertThatThrownBy(() -> service.assertCaEnabled(GLOBALSIGN, ORG_ID)).as("issuance's check")
                .isInstanceOfSatisfying(FeatureDisabledException.class,
                        e -> assertThat(e.getCode()).isEqualTo("CA_DISABLED"));
    }

    private void globalSign(boolean enabled) {
        GlobalFeatureFlag flag = GlobalFeatureFlag.builder()
                .featureKey(GLOBALSIGN).displayName("GlobalSign CA").description("")
                .scope("ORG").category("PLATFORM").enabled(enabled).build();
        when(globalRepo.findByFeatureKey(GLOBALSIGN)).thenReturn(Optional.of(flag));
        when(globalRepo.findResolutionViewByFeatureKey(GLOBALSIGN)).thenReturn(Optional.of(
                new GlobalFeatureFlagRepository.ResolutionView() {
                    @Override public Boolean getEnabled() { return enabled; }
                    @Override public String getCategory() { return "PLATFORM"; }
                    @Override public String getScope() { return "ORG"; }
                }));
    }

    private void orgAdminOverride(boolean enabled) {
        when(orgRepo.findOverrideViewByOrganizationIdAndFeatureKey(ORG_ID, GLOBALSIGN))
                .thenReturn(Optional.of(new OrganizationFeatureFlagRepository.OverrideView() {
                    @Override public Boolean getEnabled() { return enabled; }
                    @Override public Boolean getAdminLocked() { return false; }
                }));
    }

    private void orgTypeDefault(boolean enabled) {
        when(orgTypeRepo.findEnabledByOrgTypeAndFeatureKey("B2B", GLOBALSIGN)).thenReturn(Optional.of(() -> enabled));
        when(orgTypeRepo.findByOrgTypeAndFeatureKey("B2B", GLOBALSIGN)).thenReturn(Optional.of(
                OrgTypeFeatureFlag.builder().orgType("B2B").featureKey(GLOBALSIGN).enabled(enabled).build()));
    }

    private static FeatureFlagUpdateRequest enable() {
        FeatureFlagUpdateRequest request = new FeatureFlagUpdateRequest();
        request.setEnabled(true);
        return request;
    }
}
