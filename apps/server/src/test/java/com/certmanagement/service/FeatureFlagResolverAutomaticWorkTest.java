// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.repository.GlobalFeatureFlagRepository;
import com.certmanagement.repository.OrgTypeFeatureFlagRepository;
import com.certmanagement.repository.OrganizationFeatureFlagRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.FeatureFlagDecision.OffCause;
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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Automatic renewal needs CERTIFICATE_RENEWAL and DNS_CREDENTIALS; the feature itself (a manual renewal)
 * needs only its own flag.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class FeatureFlagResolverAutomaticWorkTest {

    private static final String RENEWAL = FeatureFlags.CERTIFICATE_RENEWAL;
    private static final String DNS = FeatureFlags.DNS_CREDENTIALS;
    private static final long ORG = 7L;

    @Mock private GlobalFeatureFlagRepository globalRepo;
    @Mock private OrganizationFeatureFlagRepository orgRepo;
    @Mock private OrgTypeFeatureFlagRepository orgTypeRepo;
    @Mock private OrganizationRepository organizationRepo;

    private FeatureFlagResolver resolver;

    @BeforeEach
    void setUp() {
        resolver = new FeatureFlagResolver(globalRepo, orgRepo, orgTypeRepo, organizationRepo);
        when(organizationRepo.findOrgTypeById(ORG)).thenReturn(Optional.of("B2B"));
        global(RENEWAL, true);
        global(DNS, true);
    }

    @Test
    void bothOn_automaticWorkRuns() {
        assertThat(resolver.automaticWorkBlockerUncached(RENEWAL, ORG)).isEmpty();
        assertThat(resolver.loadInputsUncached(RENEWAL, ORG).automaticWorkEnabled()).isTrue();
    }

    @Test
    void dnsCredentialsOff_stopsOnlyTheAutomaticWorkAndNamesThemAsTheCause() {
        global(DNS, false);

        assertThat(resolver.resolveUncached(RENEWAL, ORG)).as("Renew now").isTrue();
        assertThat(resolver.automaticWorkBlockerUncached(RENEWAL, ORG)).contains(DNS);
        FeatureFlagInputs inputs = resolver.loadInputsUncached(RENEWAL, ORG);
        assertThat(inputs.enabled()).isTrue();
        assertThat(inputs.automaticWorkEnabled()).isFalse();
        assertThat(inputs.automaticWorkOffCause()).isEqualTo(OffCause.REQUIREMENT);
    }

    @Test
    void renewalOff_isItsOwnCauseWhateverDnsCredentialsSay() {
        global(RENEWAL, false);
        global(DNS, false);

        assertThat(resolver.automaticWorkBlockerUncached(RENEWAL, ORG)).contains(RENEWAL);
        assertThat(resolver.loadInputsUncached(RENEWAL, ORG).automaticWorkOffCause()).isEqualTo(OffCause.GLOBAL);
    }

    @Test
    void aPageCarriesTheRequirementOfEachOrganization() {
        global(DNS, false);
        when(organizationRepo.findOrgTypesByIdIn(List.of(ORG))).thenReturn(List.of(new OrganizationRepository.OrgTypeView() {
            @Override public Long getId() { return ORG; }
            @Override public String getOrgType() { return "B2B"; }
        }));

        Map<Long, FeatureFlagInputs> page = resolver.loadInputs(RENEWAL, List.of(ORG));

        assertThat(page.get(ORG).requirement().featureKey()).isEqualTo(DNS);
        assertThat(page.get(ORG).automaticWorkEnabled()).isFalse();
        assertThat(resolver.resolveForOrganizations(RENEWAL, List.of(ORG))).as("the flag's own answer")
                .containsEntry(ORG, true);
    }

    @Test
    void aFeatureWithoutARequirementLoadsNothingMore() {
        String monitoring = FeatureFlags.DISCOVERY;
        global(monitoring, true);

        assertThat(resolver.loadInputsUncached(monitoring, ORG).requirement()).isNull();
        assertThat(resolver.automaticWorkBlockerUncached(monitoring, ORG)).isEmpty();
        verify(globalRepo, never()).findResolutionViewByFeatureKey(DNS);
    }

    @Test
    void anEmptyPageIsFree() {
        assertThat(resolver.loadInputs(RENEWAL, List.of())).isEmpty();
        verify(globalRepo, never()).findResolutionViewByFeatureKey(anyString());
    }

    private void global(String featureKey, boolean enabled) {
        GlobalFeatureFlag flag = GlobalFeatureFlag.builder().featureKey(featureKey).scope("ORG").category("PLATFORM")
                .enabled(enabled).build();
        when(globalRepo.findResolutionViewByFeatureKey(featureKey))
                .thenReturn(Optional.of(FeatureFlagResolverTest.view(flag)));
    }
}
