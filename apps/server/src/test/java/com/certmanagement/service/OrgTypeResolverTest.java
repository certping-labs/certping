// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.entity.Organization;
import com.certmanagement.repository.OrganizationRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OrgTypeResolverTest {

    @Mock private OrganizationRepository organizationRepository;

    @InjectMocks private OrgTypeResolver resolver;

    @Test
    void resolve_returnsOrgTypeAndCaches() {
        Organization org = Organization.builder().id(1L).orgType("B2B").build();
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(org));

        assertThat(resolver.resolve(1L)).isEqualTo("B2B");
        // Second call must hit cache, not the repo again.
        assertThat(resolver.resolve(1L)).isEqualTo("B2B");
        verify(organizationRepository, times(1)).findById(1L);
    }

    @Test
    void resolve_nullId_throws() {
        assertThatThrownBy(() -> resolver.resolve((Long) null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void resolve_unknownOrg_throwsIllegalState() {
        when(organizationRepository.findById(9L)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> resolver.resolve(9L))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Unknown organizationId");
    }

    @Test
    void resolveString_parsesNumericId() {
        Organization org = Organization.builder().id(5L).orgType("B2B").build();
        when(organizationRepository.findById(5L)).thenReturn(Optional.of(org));
        assertThat(resolver.resolve("5")).isEqualTo("B2B");
    }

    @Test
    void resolveString_nonNumeric_throws() {
        assertThatThrownBy(() -> resolver.resolve("not-a-number"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("numeric id");
    }

    @Test
    void invalidateAll_clearsCache() {
        Organization org = Organization.builder().id(1L).orgType("B2B").build();
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(org));

        resolver.resolve(1L);
        resolver.invalidateAll();
        resolver.resolve(1L);

        verify(organizationRepository, times(2)).findById(1L);
    }
}
