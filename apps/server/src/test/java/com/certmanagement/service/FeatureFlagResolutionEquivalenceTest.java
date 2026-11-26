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
import com.certmanagement.service.audit.FeatureFlagChangeAudit;
import com.certmanagement.service.lifecycle.FeatureLifecycleService;
import com.certmanagement.service.lifecycle.ForcedFlagChanges;
import com.certmanagement.testing.BeanProviders;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Proves the single-flag resolver and the batch {@code listEffective} agree on every combination of
 * global state, scope, category, org type, org override (plain or admin-locked) and
 * org-type default. Both now delegate to {@link FeatureFlagDecision}; this guards against a future
 * edit that loads rows differently on one side.
 */
class FeatureFlagResolutionEquivalenceTest {

    private static final long ORG_ID = 7L;
    private static final String KEY = "EQUIV_FLAG";

    private record Case(boolean globalEnabled, String scope, String category,
                        String orgType, Boolean orgEnabled, boolean adminLocked, Boolean orgTypeEnabled) {}

    @Test
    void resolverAndListEffectiveAgreeOnEveryCombination() {
        List<Case> cases = allCases();
        for (Case c : cases) {
            boolean single = resolveSingle(c);
            assertThat(single)
                    .as("resolver vs listEffective for %s", c)
                    .isEqualTo(resolveBatch(c));
            assertThat(single)
                    .as("resolver vs the cached per-organization effectiveMap for %s", c)
                    .isEqualTo(resolveEffectiveMap(c));
        }
        assertThat(cases).hasSize(288);
    }

    private static List<Case> allCases() {
        List<Case> cases = new ArrayList<>();
        List<String> orgTypes = Arrays.asList("B2B", null);
        List<Boolean> tristate = Arrays.asList(null, true, false);
        for (boolean globalEnabled : new boolean[] {true, false}) {
            for (String scope : List.of("ORG", "PLATFORM")) {
                for (String category : List.of("PLATFORM", "B2B")) {
                    for (String orgType : orgTypes) {
                        for (Boolean orgEnabled : tristate) {
                            for (boolean locked : new boolean[] {true, false}) {
                                for (Boolean typeEnabled : tristate) {
                                    cases.add(new Case(globalEnabled, scope, category, orgType,
                                            orgEnabled, locked, typeEnabled));
                                }
                            }
                        }
                    }
                }
            }
        }
        return cases;
    }

    private static boolean resolveSingle(Case c) {
        Repos repos = new Repos(c);
        when(repos.global.findResolutionViewByFeatureKey(KEY)).thenReturn(Optional.of(view(c)));
        when(repos.org.findOverrideViewByOrganizationIdAndFeatureKey(anyLong(), anyString()))
                .thenReturn(c.orgEnabled() == null ? Optional.empty() : Optional.of(overrideView(c)));
        when(repos.orgType.findEnabledByOrgTypeAndFeatureKey(anyString(), anyString()))
                .thenReturn(c.orgTypeEnabled() == null ? Optional.empty() : Optional.of(c::orgTypeEnabled));
        return repos.resolver().resolve(KEY, ORG_ID);
    }

    private static boolean resolveBatch(Case c) {
        Repos repos = batchRepos(c);
        FeatureFlagService service = new FeatureFlagService(repos.global, repos.org, repos.orgType,
                repos.organizations, repos.resolver(), mock(ApplicationEventPublisher.class),
                mock(FeatureFlagChangeAudit.class),
                BeanProviders.of(FeatureLifecycleService.class, mock(FeatureLifecycleService.class)),
                BeanProviders.of(ForcedFlagChanges.class, mock(ForcedFlagChanges.class)));
        return service.listEffective(ORG_ID).get(0).effectiveEnabled();
    }

    private static boolean resolveEffectiveMap(Case c) {
        return batchRepos(c).resolver().effectiveMap(ORG_ID).get(KEY);
    }

    /** The rows as the catalog-wide reads ({@code findAll} and per-organization lists) return them. */
    private static Repos batchRepos(Case c) {
        Repos repos = new Repos(c);
        when(repos.global.findAll()).thenReturn(List.of(GlobalFeatureFlag.builder()
                .featureKey(KEY).scope(c.scope()).category(c.category()).enabled(c.globalEnabled()).build()));
        when(repos.org.findAllByOrganizationId(ORG_ID)).thenReturn(c.orgEnabled() == null ? List.of()
                : List.of(OrganizationFeatureFlag.builder().organizationId(ORG_ID).featureKey(KEY)
                        .enabled(c.orgEnabled()).adminLocked(c.adminLocked()).build()));
        when(repos.orgType.findAllByOrgType(any())).thenReturn(c.orgTypeEnabled() == null ? List.of()
                : List.of(OrgTypeFeatureFlag.builder().orgType(c.orgType()).featureKey(KEY)
                        .enabled(c.orgTypeEnabled()).build()));
        return repos;
    }

    /** Fresh mocks per case, so one case's stubs never leak into the next. */
    private static final class Repos {
        final GlobalFeatureFlagRepository global = mock(GlobalFeatureFlagRepository.class);
        final OrganizationFeatureFlagRepository org = mock(OrganizationFeatureFlagRepository.class);
        final OrgTypeFeatureFlagRepository orgType = mock(OrgTypeFeatureFlagRepository.class);
        final OrganizationRepository organizations = mock(OrganizationRepository.class);

        Repos(Case c) {
            when(organizations.findOrgTypeById(ORG_ID)).thenReturn(Optional.ofNullable(c.orgType()));
        }

        FeatureFlagResolver resolver() {
            return new FeatureFlagResolver(global, org, orgType, organizations);
        }
    }

    private static GlobalFeatureFlagRepository.ResolutionView view(Case c) {
        return new GlobalFeatureFlagRepository.ResolutionView() {
            @Override public Boolean getEnabled() { return c.globalEnabled(); }
            @Override public String getCategory() { return c.category(); }
            @Override public String getScope() { return c.scope(); }
        };
    }

    private static OrganizationFeatureFlagRepository.OverrideView overrideView(Case c) {
        return new OrganizationFeatureFlagRepository.OverrideView() {
            @Override public Boolean getEnabled() { return c.orgEnabled(); }
            @Override public Boolean getAdminLocked() { return c.adminLocked(); }
        };
    }
}
