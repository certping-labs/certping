// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.repository.GlobalFeatureFlagRepository;
import com.certmanagement.repository.OrganizationFeatureFlagRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.OrgTypeFeatureFlagRepository;
import com.certmanagement.service.audit.FeatureFlagChangeAudit;
import com.certmanagement.service.lifecycle.FeatureLifecycleService;
import com.certmanagement.service.lifecycle.ForcedFlagChanges;
import com.certmanagement.testing.BeanProviders;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.LongStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** {@link FeatureFlagService#disabledFeatureKeysFor}: one batched resolution per feature key, not per organization. */
class FeatureFlagServiceDisabledForPageTest {

    private final FeatureFlagResolver resolver = mock(FeatureFlagResolver.class);
    private final FeatureFlagService service = new FeatureFlagService(mock(GlobalFeatureFlagRepository.class),
            mock(OrganizationFeatureFlagRepository.class), mock(OrgTypeFeatureFlagRepository.class),
            mock(OrganizationRepository.class), resolver,
            mock(ApplicationEventPublisher.class), mock(FeatureFlagChangeAudit.class),
            BeanProviders.of(FeatureLifecycleService.class, mock(FeatureLifecycleService.class)),
            BeanProviders.of(ForcedFlagChanges.class, mock(ForcedFlagChanges.class)));

    @Test
    void fiftyOrganizationsCostOneResolutionPerFeatureKey() {
        List<Long> organizations = LongStream.rangeClosed(1, 50).boxed().toList();
        Map<Long, Boolean> evenOff = organizations.stream()
                .collect(Collectors.toMap(id -> id, id -> id % 2 == 1));
        when(resolver.resolveForOrganizations(eq("CREDENTIALS_MANAGEMENT"), anyCollection())).thenReturn(evenOff);
        when(resolver.resolveForOrganizations(eq("PQC_READINESS"), anyCollection()))
                .thenReturn(organizations.stream().collect(Collectors.toMap(id -> id, id -> true)));

        Map<Long, Set<String>> off = service.disabledFeatureKeysFor(organizations, List.of("CREDENTIALS_MANAGEMENT", "PQC_READINESS"));

        assertThat(off).hasSize(50);
        assertThat(off.get(2L)).containsExactly("CREDENTIALS_MANAGEMENT");
        assertThat(off.get(3L)).isEmpty();
        verify(resolver, times(2)).resolveForOrganizations(any(), anyCollection());
        verify(resolver, never()).effectiveMap(anyLong());
    }

    @Test
    void noOrganizationsNeedNoLookup() {
        assertThat(service.disabledFeatureKeysFor(List.of(), List.of("CREDENTIALS_MANAGEMENT"))).isEmpty();
        verify(resolver, never()).resolveForOrganizations(any(), anyCollection());
    }
}
