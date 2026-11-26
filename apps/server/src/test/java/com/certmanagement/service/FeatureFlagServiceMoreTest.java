// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.entity.OrgTypeFeatureFlag;
import com.certmanagement.entity.OrganizationFeatureFlag;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.GlobalFeatureFlagRepository;
import com.certmanagement.repository.OrgTypeFeatureFlagRepository;
import com.certmanagement.repository.OrganizationFeatureFlagRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.audit.FeatureFlagChangeAudit;
import com.certmanagement.service.lifecycle.FeatureLifecycleService;
import com.certmanagement.service.lifecycle.ForcedFlagChanges;
import com.certmanagement.exception.FeatureInUseException;
import com.certmanagement.testing.BeanProviders;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.springframework.context.ApplicationEventPublisher;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FeatureFlagServiceMoreTest {

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
    void setup() {
        service = new FeatureFlagService(globalRepo, orgRepo, orgTypeRepo, organizationRepo, resolver,
                events, changeAudit, BeanProviders.of(FeatureLifecycleService.class, lifecycleService),
                BeanProviders.of(ForcedFlagChanges.class, forcedChanges));
    }

    @AfterEach
    void clear() {
        GatewayRequestContext.clear();
    }

    private GlobalFeatureFlag global(String key, String scope, String category, boolean enabled) {
        return GlobalFeatureFlag.builder()
                .featureKey(key).scope(scope).category(category).enabled(enabled).build();
    }


    // ── getGlobal / listGlobal ────────────────────────────────────────────────

    @Test
    void getGlobal_foundReturnsFlag() {
        GlobalFeatureFlag g = global("k", "ORG", "B2B", true);
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(g));
        assertThat(service.getGlobal("k")).isSameAs(g);
    }

    @Test
    void getGlobal_missingThrows404() {
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.getGlobal("k"))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void listGlobal_returnsAll() {
        when(globalRepo.findAll()).thenReturn(List.of(global("a", "ORG", "B2B", true)));
        assertThat(service.listGlobal()).hasSize(1);
    }

    @Test
    void listOrgTypeEffective_delegates() {
        when(orgTypeRepo.findAllByOrgType("B2B")).thenReturn(List.of(
                OrgTypeFeatureFlag.builder().orgType("B2B").featureKey("k").enabled(true).build()));
        assertThat(service.listOrgTypeEffective("B2B")).hasSize(1);
    }

    @Test
    void listOrgOverrides_delegates() {
        Page<OrganizationFeatureFlag> page = new PageImpl<>(List.of(
                OrganizationFeatureFlag.builder().organizationId(1L).featureKey("k").enabled(true).build()));
        when(orgRepo.findAllByFeatureKey("k", Pageable.unpaged())).thenReturn(page);
        assertThat(service.listOrgOverrides("k", Pageable.unpaged()).getContent()).hasSize(1);
    }

    // ── assertEnabled / assertCaEnabled ───────────────────────────────────────

    @Test
    void assertEnabled_passesWhenEnabled() {
        when(resolver.resolve("k", 1L)).thenReturn(true);
        service.assertEnabled("k", 1L); // no throw
    }

    @Test
    void assertEnabled_throwsWhenDisabled() {
        when(resolver.resolve("k", 1L)).thenReturn(false);
        assertThatThrownBy(() -> service.assertEnabled("k", 1L))
                .isInstanceOf(FeatureDisabledException.class);
    }

    @Test
    void assertCaEnabled_throwsWithCaCode() {
        when(resolver.resolve("ca", 1L)).thenReturn(false);
        assertThatThrownBy(() -> service.assertCaEnabled("ca", 1L))
                .isInstanceOf(FeatureDisabledException.class)
                .satisfies(e -> assertThat(((FeatureDisabledException) e).getCode()).isEqualTo("CA_DISABLED"));
    }

    // ── updateGlobal ───────────────────────────────────────────────────────────

    @Test
    void updateGlobal_setsEnabledAndActor() {
        GatewayRequestContext.set(77, "1", "req", "a@b.c");
        GlobalFeatureFlag g = global("k", "ORG", "B2B", true);
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(g));
        when(globalRepo.save(any())).thenAnswer(i -> i.getArgument(0));

        GlobalFeatureFlag saved = service.updateGlobal("k", false, "kill it");
        assertThat(saved.getEnabled()).isFalse();
        assertThat(saved.getUpdatedByUserId()).isEqualTo(77);
    }

    // ── upsertOrgTypeOverride ──────────────────────────────────────────────────

    @Test
    void upsertOrgTypeOverride_invalidOrgTypeThrows() {
        assertThatThrownBy(() -> service.upsertOrgTypeOverride("X", "k", true, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Invalid orgType");
    }

    @Test
    void upsertOrgTypeOverride_nonOrgScopeThrows() {
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "PLATFORM", "B2B", true)));
        assertThatThrownBy(() -> service.upsertOrgTypeOverride("B2B", "k", true, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("not org-scoped");
    }

    @Test
    void upsertOrgTypeOverride_globallyDisabledThrows() {
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "B2B", false)));
        assertThatThrownBy(() -> service.upsertOrgTypeOverride("B2B", "k", true, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("globally disabled");
    }

    @Test
    void upsertOrgTypeOverride_updatesExisting() {
        GatewayRequestContext.set(5, "1", "req", "a@b.c");
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "B2B", true)));
        OrgTypeFeatureFlag existing = OrgTypeFeatureFlag.builder()
                .orgType("B2B").featureKey("k").enabled(false).build();
        when(orgTypeRepo.findByOrgTypeAndFeatureKey("B2B", "k")).thenReturn(Optional.of(existing));
        when(orgTypeRepo.save(any())).thenAnswer(i -> i.getArgument(0));

        OrgTypeFeatureFlag saved = service.upsertOrgTypeOverride("B2B", "k", true, null);
        assertThat(saved.getEnabled()).isTrue();
        assertThat(saved.getUpdatedByUserId()).isEqualTo(5);
    }

    @Test
    void upsertOrgTypeOverride_createsNew() {
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "B2B", true)));
        when(orgTypeRepo.findByOrgTypeAndFeatureKey("B2B", "k")).thenReturn(Optional.empty());
        when(orgTypeRepo.save(any())).thenAnswer(i -> i.getArgument(0));

        OrgTypeFeatureFlag saved = service.upsertOrgTypeOverride("B2B", "k", true, null);
        assertThat(saved.getOrgType()).isEqualTo("B2B");
        assertThat(saved.getFeatureKey()).isEqualTo("k");
        assertThat(saved.getEnabled()).isTrue();
    }

    // ── removeOrgTypeOverride ──────────────────────────────────────────────────

    @Test
    void removeOrgTypeOverride_invalidOrgTypeThrows() {
        assertThatThrownBy(() -> service.removeOrgTypeOverride("Z", "k", null))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void removeOrgTypeOverride_deletedReturnsTrueAndIsAudited() {
        OrgTypeFeatureFlag existing = OrgTypeFeatureFlag.builder().id(3L).orgType("B2B").featureKey("k").enabled(false).build();
        when(orgTypeRepo.findByOrgTypeAndFeatureKey("B2B", "k")).thenReturn(Optional.of(existing));
        when(orgTypeRepo.deleteByOrgTypeAndFeatureKey("B2B", "k")).thenReturn(1);

        assertThat(service.removeOrgTypeOverride("B2B", "k", "cleanup")).isTrue();

        verify(changeAudit).recordOrgType(3L, "B2B", "k", false, null, "cleanup");
    }

    @Test
    void removeOrgTypeOverride_nothingToRemoveReturnsFalse() {
        when(orgTypeRepo.findByOrgTypeAndFeatureKey("B2B", "k")).thenReturn(Optional.empty());
        assertThat(service.removeOrgTypeOverride("B2B", "k", null)).isFalse();
        verify(orgTypeRepo, never()).deleteByOrgTypeAndFeatureKey(any(), any());
        verifyNoInteractions(changeAudit);
    }

    // ── upsertOrgOverride ──────────────────────────────────────────────────────

    @ParameterizedTest(name = "{0}")
    @CsvSource(nullValues = "NULL", value = {
            "platform scope,          PLATFORM, B2B, true,  B2B",
            "globally off,            ORG,      B2B, false, B2B",
    })
    void upsertOrgOverride_refusesFlagsTheOrgCannotControl(
            String name, String scope, String category, boolean enabled, String orgType) {
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", scope, category, enabled)));
        lenient().when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.ofNullable(orgType));

        assertThatThrownBy(() -> service.upsertOrgOverride(1L, "k", true, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("cannot be overridden for this organization");
        verify(orgRepo, never()).save(any());
    }

    @Test
    void upsertOrgOverride_updatesExisting() {
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "B2B", true)));
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));
        OrganizationFeatureFlag existing = OrganizationFeatureFlag.builder()
                .organizationId(1L).featureKey("k").enabled(false).build();
        when(orgRepo.findByOrganizationIdAndFeatureKey(1L, "k")).thenReturn(Optional.of(existing));
        when(orgRepo.save(any())).thenAnswer(i -> i.getArgument(0));

        OrganizationFeatureFlag saved = service.upsertOrgOverride(1L, "k", true, null);
        assertThat(saved.getEnabled()).isTrue();
    }

    @Test
    void upsertOrgOverride_restoresSoftDeleted() {
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "B2B", true)));
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));
        when(orgRepo.findByOrganizationIdAndFeatureKey(1L, "k")).thenReturn(Optional.empty());
        OrganizationFeatureFlag soft = OrganizationFeatureFlag.builder()
                .organizationId(1L).featureKey("k").enabled(false).isDeleted(true).build();
        when(orgRepo.findByOrganizationIdAndFeatureKeyIncludeDeleted(1L, "k")).thenReturn(Optional.of(soft));
        when(orgRepo.save(any())).thenAnswer(i -> i.getArgument(0));

        OrganizationFeatureFlag saved = service.upsertOrgOverride(1L, "k", true, null);
        assertThat(saved.getIsDeleted()).isFalse();
        assertThat(saved.getEnabled()).isTrue();
    }

    @Test
    void upsertOrgOverride_createsNew() {
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "B2B", true)));
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));
        when(orgRepo.findByOrganizationIdAndFeatureKey(1L, "k")).thenReturn(Optional.empty());
        when(orgRepo.findByOrganizationIdAndFeatureKeyIncludeDeleted(1L, "k")).thenReturn(Optional.empty());
        when(orgRepo.save(any())).thenAnswer(i -> i.getArgument(0));

        OrganizationFeatureFlag saved = service.upsertOrgOverride(1L, "k", false, null);
        assertThat(saved.getOrganizationId()).isEqualTo(1L);
        assertThat(saved.getEnabled()).isFalse();
    }

    // ── Super admin lock ───────────────────────────────────────────────────────

    private OrganizationFeatureFlag override(boolean enabled, boolean adminLocked) {
        return OrganizationFeatureFlag.builder()
                .organizationId(1L).featureKey("k").enabled(enabled).adminLocked(adminLocked).build();
    }

    @Test
    void upsertOrgOverride_refusesToChangeASuperAdminOverride() {
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "PLATFORM", true)));
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));
        when(orgRepo.findByOrganizationIdAndFeatureKey(1L, "k")).thenReturn(Optional.of(override(false, true)));

        assertThatThrownBy(() -> service.upsertOrgOverride(1L, "k", true, null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("decided by a platform administrator");
        verify(orgRepo, never()).save(any());
    }

    @Test
    void upsertOrgOverride_refusesToUndoAnOrgTypeOff() {
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "PLATFORM", true)));
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));
        when(orgTypeRepo.findByOrgTypeAndFeatureKey("B2B", "k")).thenReturn(Optional.of(
                OrgTypeFeatureFlag.builder().orgType("B2B").featureKey("k").enabled(false).build()));

        assertThatThrownBy(() -> service.upsertOrgOverride(1L, "k", true, null))
                .isInstanceOf(BadRequestException.class);
        verify(orgRepo, never()).save(any());
    }

    @Test
    void upsertOrgOverride_mayOptOutOfAnOrgTypeOn() {
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "PLATFORM", true)));
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));
        when(orgTypeRepo.findByOrgTypeAndFeatureKey("B2B", "k")).thenReturn(Optional.of(
                OrgTypeFeatureFlag.builder().orgType("B2B").featureKey("k").enabled(true).build()));
        when(orgRepo.save(any())).thenAnswer(i -> i.getArgument(0));

        OrganizationFeatureFlag saved = service.upsertOrgOverride(1L, "k", false, null);

        assertThat(saved.getEnabled()).isFalse();
        assertThat(saved.getAdminLocked()).isFalse();
    }

    @Test
    void upsertOrgOverride_refusesAFlagOnlySuperAdminsDecide() {
        when(globalRepo.findByFeatureKey(FeatureFlags.NOTIFICATION_PREFERENCES))
                .thenReturn(Optional.of(global(FeatureFlags.NOTIFICATION_PREFERENCES, "ORG", "PLATFORM", true)));
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));

        assertThatThrownBy(() -> service.upsertOrgOverride(1L, FeatureFlags.NOTIFICATION_PREFERENCES, true, null))
                .isInstanceOf(BadRequestException.class);
        verify(orgRepo, never()).save(any());
    }

    @Test
    void upsertOrgOverrideAsAdmin_locksTheOverride() {
        when(globalRepo.findByFeatureKey(FeatureFlags.NOTIFICATION_PREFERENCES))
                .thenReturn(Optional.of(global(FeatureFlags.NOTIFICATION_PREFERENCES, "ORG", "PLATFORM", true)));
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));
        OrganizationFeatureFlag orgAdmins = override(false, false);
        when(orgRepo.findByOrganizationIdAndFeatureKey(1L, FeatureFlags.NOTIFICATION_PREFERENCES)).thenReturn(Optional.of(orgAdmins));
        when(orgRepo.save(any())).thenAnswer(i -> i.getArgument(0));
        GatewayRequestContext.set(9, "1", "req", "root@example.com");

        OrganizationFeatureFlag saved = service.upsertOrgOverrideAsAdmin(1L, FeatureFlags.NOTIFICATION_PREFERENCES, true, null);

        assertThat(saved).isSameAs(orgAdmins);
        assertThat(saved.getEnabled()).isTrue();
        assertThat(saved.getAdminLocked()).isTrue();
        assertThat(saved.getUpdatedByUserId()).isEqualTo(9);
    }

    @Test
    void upsertOrgOverrideAsAdmin_stillRefusesFlagsNoOrgOverrideCanDecide() {
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "PLATFORM", "PLATFORM", true)));
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));

        assertThatThrownBy(() -> service.upsertOrgOverrideAsAdmin(1L, "k", true, null))
                .isInstanceOf(BadRequestException.class);
        verify(orgRepo, never()).save(any());
    }

    // ── removeOrgOverride ──────────────────────────────────────────────────────

    @Test
    void removeOrgOverride_deletedReturnsTrueAndIsAudited() {
        OrganizationFeatureFlag existing = override(false, false);
        existing.setId(4L);
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "B2B", true)));
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));
        when(orgRepo.findByOrganizationIdAndFeatureKey(1L, "k")).thenReturn(Optional.of(existing));
        when(orgRepo.softDeleteUnlockedByOrganizationIdAndFeatureKey(1L, "k")).thenReturn(1);

        assertThat(service.removeOrgOverride(1L, "k", "back to default")).isTrue();

        verify(changeAudit).recordOrganization(4L, 1L, "k",
                new FeatureFlagChangeAudit.OverrideState(false, false), null, "back to default");
    }

    @Test
    void removeOrgOverride_nothingToRemoveReturnsFalse() {
        when(orgRepo.findByOrganizationIdAndFeatureKey(1L, "k")).thenReturn(Optional.empty());
        assertThat(service.removeOrgOverride(1L, "k", null)).isFalse();
        verify(orgRepo, never()).softDeleteUnlockedByOrganizationIdAndFeatureKey(any(), any());
        verifyNoInteractions(changeAudit);
    }

    @Test
    void removeOrgOverride_refusesToRemoveASuperAdminOverride() {
        when(orgRepo.findByOrganizationIdAndFeatureKey(1L, "k")).thenReturn(Optional.of(override(false, true)));

        assertThatThrownBy(() -> service.removeOrgOverride(1L, "k", null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("only a platform administrator can remove it");
        verify(orgRepo, never()).softDeleteUnlockedByOrganizationIdAndFeatureKey(any(), any());
        verify(orgRepo, never()).softDeleteByOrganizationIdAndFeatureKey(any(), any());
        verifyNoInteractions(changeAudit);
    }

    @Test
    void removeOrgOverrideAsAdmin_removesLockedOverridesToo() {
        when(orgRepo.findByOrganizationIdAndFeatureKey(2L, "k")).thenReturn(Optional.of(override(false, true)));
        when(orgRepo.softDeleteByOrganizationIdAndFeatureKey(2L, "k")).thenReturn(1);
        assertThat(service.removeOrgOverrideAsAdmin(2L, "k", null)).isTrue();
        verify(orgRepo, never()).softDeleteUnlockedByOrganizationIdAndFeatureKey(any(), any());
        verify(changeAudit).recordOrganization(any(), org.mockito.ArgumentMatchers.eq(2L),
                org.mockito.ArgumentMatchers.eq("k"),
                org.mockito.ArgumentMatchers.eq(new FeatureFlagChangeAudit.OverrideState(false, true)),
                org.mockito.ArgumentMatchers.isNull(), org.mockito.ArgumentMatchers.isNull());
    }

    // ── audit of writes ────────────────────────────────────────────────────────

    @Test
    void updateGlobal_auditsBeforeAfterAndReason() {
        GlobalFeatureFlag g = global("k", "ORG", "B2B", true);
        g.setId(11L);
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(g));
        when(globalRepo.save(any())).thenAnswer(i -> i.getArgument(0));

        service.updateGlobal("k", false, "incident 42");

        verify(changeAudit).recordGlobal(11L, "k", true, false, "incident 42");
    }

    @Test
    void upsertOrgTypeOverride_auditsACreationButNotANoOp() {
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "B2B", true)));
        when(orgTypeRepo.findByOrgTypeAndFeatureKey("B2B", "k")).thenReturn(Optional.empty());
        when(orgTypeRepo.save(any())).thenAnswer(i -> i.getArgument(0));

        service.upsertOrgTypeOverride("B2B", "k", false, "pilot");
        verify(changeAudit).recordOrgType(null, "B2B", "k", null, false, "pilot");

        when(orgTypeRepo.findByOrgTypeAndFeatureKey("B2B", "k")).thenReturn(Optional.of(
                OrgTypeFeatureFlag.builder().orgType("B2B").featureKey("k").enabled(false).build()));
        service.upsertOrgTypeOverride("B2B", "k", false, "again");
        verify(changeAudit, never()).recordOrgType(any(), any(), any(), any(), any(),
                org.mockito.ArgumentMatchers.eq("again"));
    }

    @Test
    void upsertOrgOverrideAsAdmin_auditsTheLockAndPreviousState() {
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "PLATFORM", true)));
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));
        when(orgRepo.findByOrganizationIdAndFeatureKey(1L, "k")).thenReturn(Optional.of(override(true, false)));
        when(orgRepo.save(any())).thenAnswer(i -> i.getArgument(0));

        service.upsertOrgOverrideAsAdmin(1L, "k", false, "abuse");

        verify(changeAudit).recordOrganization(null, 1L, "k",
                new FeatureFlagChangeAudit.OverrideState(true, false),
                new FeatureFlagChangeAudit.OverrideState(false, true), "abuse");
    }

    @Test
    void disabledFeatureKeys_listsOnlyTheFlagsThatAreOffInTheResolversEffectiveMap() {
        when(resolver.effectiveMap(1L)).thenReturn(Map.of("on", true, "killed", false, "orgOff", false));

        assertThat(service.disabledFeatureKeys(1L)).containsExactlyInAnyOrder("killed", "orgOff");
        assertThat(service.effectiveMap(1L)).containsEntry("on", true).hasSize(3);
        verifyNoInteractions(globalRepo, orgRepo, orgTypeRepo);
    }

    // ── listEffective ──────────────────────────────────────────────────────────

    @Test
    void listEffective_coversAllResolutionBranches() {
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));

        GlobalFeatureFlag killed = global("killed", "ORG", "B2B", false);
        GlobalFeatureFlag platform = global("platform", "PLATFORM", "PLATFORM", true);
        GlobalFeatureFlag orgOverridden = global("orgOv", "ORG", "B2B", true);
        GlobalFeatureFlag typeOverridden = global("typeOv", "ORG", "B2B", true);
        GlobalFeatureFlag defaulted = global("default", "ORG", "B2B", true);

        when(globalRepo.findAll()).thenReturn(List.of(
                killed, platform, orgOverridden, typeOverridden, defaulted));

        when(orgRepo.findAllByOrganizationId(1L)).thenReturn(List.of(
                OrganizationFeatureFlag.builder().featureKey("orgOv").enabled(false).build()));
        when(orgTypeRepo.findAllByOrgType("B2B")).thenReturn(List.of(
                OrgTypeFeatureFlag.builder().orgType("B2B").featureKey("typeOv").enabled(false).build()));

        var result = service.listEffective(1L);
        assertThat(result).hasSize(5);

        assertThat(result).filteredOn(r -> r.global().getFeatureKey().equals("killed"))
                .allMatch(r -> !r.effectiveEnabled());
        assertThat(result).filteredOn(r -> r.global().getFeatureKey().equals("platform"))
                .allMatch(r -> r.effectiveEnabled());
        assertThat(result).filteredOn(r -> r.global().getFeatureKey().equals("orgOv"))
                .allMatch(r -> !r.effectiveEnabled() && Boolean.FALSE.equals(r.orgEnabled()));
        assertThat(result).filteredOn(r -> r.global().getFeatureKey().equals("typeOv"))
                .allMatch(r -> !r.effectiveEnabled() && Boolean.FALSE.equals(r.orgTypeEnabled()));
        assertThat(result).filteredOn(r -> r.global().getFeatureKey().equals("default"))
                .allMatch(r -> r.effectiveEnabled());
    }

    @Test
    void listEffective_orgControllableOnlyWhenTheOrgAdminDecides() {
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));
        when(globalRepo.findAll()).thenReturn(List.of(
                global("globallyOff", "ORG", "B2B", false),
                global("platformScope", "PLATFORM", "PLATFORM", true),
                global("orgOverridden", "ORG", "B2B", true),
                global("typeDefaultOff", "ORG", "PLATFORM", true),
                global("typeDefaultOn", "ORG", "PLATFORM", true),
                global("superAdminLocked", "ORG", "PLATFORM", true),
                global(FeatureFlags.NOTIFICATION_PREFERENCES, "ORG", "PLATFORM", true),
                global("defaulted", "ORG", "B2B", true)));
        when(orgRepo.findAllByOrganizationId(1L)).thenReturn(List.of(
                OrganizationFeatureFlag.builder().featureKey("orgOverridden").enabled(false).build(),
                OrganizationFeatureFlag.builder().featureKey("superAdminLocked").enabled(true).adminLocked(true).build()));
        when(orgTypeRepo.findAllByOrgType("B2B")).thenReturn(List.of(
                OrgTypeFeatureFlag.builder().orgType("B2B").featureKey("typeDefaultOff").enabled(false).build(),
                OrgTypeFeatureFlag.builder().orgType("B2B").featureKey("typeDefaultOn").enabled(true).build()));

        var result = service.listEffective(1L);

        assertThat(result).filteredOn(FeatureFlagService.ResolvedFlag::orgControllable)
                .extracting(r -> r.global().getFeatureKey())
                .containsExactly("orgOverridden", "typeDefaultOn", "defaulted");
    }

    @Test
    void listEffective_superAdminDecisionsOutrankTheOrgAdmins() {
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));
        when(globalRepo.findAll()).thenReturn(List.of(
                global("orgOnTypeOff", "ORG", "PLATFORM", true),
                global("lockedOnTypeOff", "ORG", "PLATFORM", true),
                global("lockedOffTypeOn", "ORG", "PLATFORM", true)));
        when(orgRepo.findAllByOrganizationId(1L)).thenReturn(List.of(
                OrganizationFeatureFlag.builder().featureKey("orgOnTypeOff").enabled(true).build(),
                OrganizationFeatureFlag.builder().featureKey("lockedOnTypeOff").enabled(true).adminLocked(true).build(),
                OrganizationFeatureFlag.builder().featureKey("lockedOffTypeOn").enabled(false).adminLocked(true).build()));
        when(orgTypeRepo.findAllByOrgType("B2B")).thenReturn(List.of(
                OrgTypeFeatureFlag.builder().orgType("B2B").featureKey("orgOnTypeOff").enabled(false).build(),
                OrgTypeFeatureFlag.builder().orgType("B2B").featureKey("lockedOnTypeOff").enabled(false).build(),
                OrgTypeFeatureFlag.builder().orgType("B2B").featureKey("lockedOffTypeOn").enabled(true).build()));

        var byKey = service.listEffective(1L).stream()
                .collect(java.util.stream.Collectors.toMap(r -> r.global().getFeatureKey(), r -> r));

        assertThat(byKey.get("orgOnTypeOff").effectiveEnabled()).isFalse();
        assertThat(byKey.get("orgOnTypeOff").adminLocked()).isFalse();
        assertThat(byKey.get("lockedOnTypeOff").effectiveEnabled()).isTrue();
        assertThat(byKey.get("lockedOnTypeOff").adminLocked()).isTrue();
        assertThat(byKey.get("lockedOffTypeOn").effectiveEnabled()).isFalse();
    }

    @Test
    void listEffective_nullOrgTypeSkipsTypeOverrides() {
        when(organizationRepo.findOrgTypeById(9L)).thenReturn(Optional.empty()); // orgType null
        // PLATFORM-category flag so it is unaffected by master/category mismatch
        GlobalFeatureFlag platform = global("p", "PLATFORM", "PLATFORM", true);
        when(globalRepo.findAll()).thenReturn(List.of(platform));
        when(orgRepo.findAllByOrganizationId(9L)).thenReturn(List.of());

        var result = service.listEffective(9L);
        assertThat(result.get(0).effectiveEnabled()).isTrue();
        assertThat(result.get(0).orgType()).isNull();
        verify(orgTypeRepo, never()).findAllByOrgType(any());
    }

    // ── Clear-first and the lifecycle trigger ─────────────────────────────────

    @Test
    void anOrgAdminSwitchingOffAFeatureThatIsOnMustFindItClearFirst() {
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "PLATFORM", true)));
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));
        org.mockito.Mockito.doThrow(new FeatureInUseException("k", java.util.List.of()))
                .when(lifecycleService).lockAndAssertNothingInUse(1L, "k");

        assertThatThrownBy(() -> service.upsertOrgOverride(1L, "k", false, null))
                .isInstanceOf(FeatureInUseException.class);
        verify(orgRepo, never()).save(any());
    }

    @Test
    void switchingOnOrReSavingAnOffFeatureNeedsNoClearing() {
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "PLATFORM", true)));
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));
        when(orgRepo.findByOrganizationIdAndFeatureKey(1L, "k"))
                .thenReturn(Optional.empty(), Optional.of(OrganizationFeatureFlag.builder()
                        .organizationId(1L).featureKey("k").enabled(false).adminLocked(false).build()));
        when(orgRepo.save(any())).thenAnswer(i -> i.getArgument(0));

        service.upsertOrgOverride(1L, "k", true, null);
        service.upsertOrgOverride(1L, "k", false, null);

        verify(lifecycleService, never()).lockAndAssertNothingInUse(anyLong(), anyString());
    }

    @Test
    void aSuperAdminSwitchOffIsForcedAndTriggersTheReconcilerForThatOrganization() {
        GatewayRequestContext.set(9, "1", "req-1", "root@example.com");
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "PLATFORM", true)));
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));
        when(orgRepo.save(any())).thenAnswer(i -> i.getArgument(0));

        service.upsertOrgOverrideAsAdmin(1L, "k", false, "incident");

        verify(lifecycleService, never()).lockAndAssertNothingInUse(anyLong(), anyString());
        verify(forcedChanges).recordOrganization("k", 1L, null,
                new FeatureFlagChangeAudit.OverrideState(false, true), 9);
        verify(events, never()).publishEvent(any(FeatureFlagStateChangedEvent.class));
    }

    @Test
    void anOrgAdminsOwnChangeIsNeverForcedAndReconcilesOnlyThatOrganization() {
        GatewayRequestContext.set(5, "1", "req-1", "admin@example.com");
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "PLATFORM", true)));
        when(organizationRepo.findOrgTypeById(1L)).thenReturn(Optional.of("B2B"));
        when(orgRepo.save(any())).thenAnswer(i -> i.getArgument(0));

        service.upsertOrgOverride(1L, "k", true, null);

        verifyNoInteractions(forcedChanges);
        verify(events).publishEvent(new FeatureFlagStateChangedEvent("k", 1L, 5, null));
    }

    @Test
    void aSuperAdminRemovingAnOverrideIsForced() {
        GatewayRequestContext.set(9, "1", "req-1", "root@example.com");
        when(orgRepo.findByOrganizationIdAndFeatureKey(1L, "k")).thenReturn(Optional.of(OrganizationFeatureFlag
                .builder().id(3L).organizationId(1L).featureKey("k").enabled(false).adminLocked(true).build()));
        when(orgRepo.softDeleteByOrganizationIdAndFeatureKey(1L, "k")).thenReturn(1);

        service.removeOrgOverrideAsAdmin(1L, "k", "restore");

        verify(forcedChanges).recordOrganization("k", 1L, new FeatureFlagChangeAudit.OverrideState(false, true),
                null, 9);
    }

    @Test
    void anOrgTypeDefaultChangeIsForcedWithItsValueBefore() {
        GatewayRequestContext.set(9, "1", "req-1", "root@example.com");
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "PLATFORM", true)));
        when(orgTypeRepo.findByOrgTypeAndFeatureKey("B2B", "k")).thenReturn(Optional.empty());
        when(orgTypeRepo.save(any())).thenAnswer(i -> i.getArgument(0));

        service.upsertOrgTypeOverride("B2B", "k", false, null);

        verify(forcedChanges).recordOrgType("k", "B2B", null, false, 9);
    }

    @Test
    void aGlobalWriteTriggersTheReconcilerForEveryOrganization() {
        GatewayRequestContext.set(9, "1", "req-1", "root@example.com");
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "PLATFORM", true)));
        when(globalRepo.save(any())).thenAnswer(i -> i.getArgument(0));

        service.updateGlobal("k", false, null);

        verify(forcedChanges).recordGlobal("k", true, false, 9);
    }

    @Test
    void aGlobalWriteThatChangesNothingRecordsNoTransition() {
        GatewayRequestContext.set(9, "1", "req-1", "root@example.com");
        when(globalRepo.findByFeatureKey("k")).thenReturn(Optional.of(global("k", "ORG", "PLATFORM", true)));
        when(globalRepo.save(any())).thenAnswer(i -> i.getArgument(0));

        service.updateGlobal("k", true, null);

        verifyNoInteractions(forcedChanges);
    }
}
