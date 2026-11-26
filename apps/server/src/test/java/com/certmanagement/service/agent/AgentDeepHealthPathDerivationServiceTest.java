// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/** Unit coverage for {@link AgentDeepHealthPathDerivationService}: dedup, trim, blank filtering. */
@ExtendWith(MockitoExtension.class)
class AgentDeepHealthPathDerivationServiceTest {

    @Mock private CertificateRepository certificateRepository;
    @Mock private RenewalScheduleRepository renewalScheduleRepository;
    @Mock private CredentialReferenceRepository credentialReferenceRepository;

    private AgentDeepHealthPathDerivationService service;

    @BeforeEach
    void setUp() {
        service = new AgentDeepHealthPathDerivationService(
                certificateRepository, renewalScheduleRepository,
                credentialReferenceRepository);
    }

    @Test
    void derivePaths_dedupsTrimsAndDropsBlanks_preservingInsertionOrder() {
        when(certificateRepository.findDistinctCertSecretHandlesByOrganizationId(1L))
                .thenReturn(Arrays.asList("  path-a  ", "path-b", null, "  "));
        when(certificateRepository.findDistinctAcmeAccountHandlesByOrganizationId(1L))
                .thenReturn(List.of("path-a")); // duplicate after trim -> dropped
        when(certificateRepository.findDistinctCaCredentialHandlesByOrganizationId(1L))
                .thenReturn(List.of("path-c"));
        when(renewalScheduleRepository.findDistinctCertSecretHandlesByOrganizationId(1L))
                .thenReturn(List.of());
        when(renewalScheduleRepository.findDistinctAcmeAccountHandlesByOrganizationId(1L))
                .thenReturn(List.of());
        when(renewalScheduleRepository.findDistinctCaCredentialHandlesByOrganizationId(1L))
                .thenReturn(List.of("path-d"));
        when(credentialReferenceRepository.findDistinctKvPathsByOrganizationId(1L))
                .thenReturn(List.of("path-e"));

        List<String> paths = service.derivePaths(1L);

        assertThat(paths).containsExactly("path-a", "path-b", "path-c", "path-d", "path-e");
    }

    @Test
    void derivePaths_singleSource_returnsIt() {
        when(certificateRepository.findDistinctCertSecretHandlesByOrganizationId(2L)).thenReturn(List.of("p1"));
        when(certificateRepository.findDistinctAcmeAccountHandlesByOrganizationId(2L)).thenReturn(List.of());
        when(certificateRepository.findDistinctCaCredentialHandlesByOrganizationId(2L)).thenReturn(List.of());
        when(renewalScheduleRepository.findDistinctCertSecretHandlesByOrganizationId(2L)).thenReturn(List.of());
        when(renewalScheduleRepository.findDistinctAcmeAccountHandlesByOrganizationId(2L)).thenReturn(List.of());
        when(renewalScheduleRepository.findDistinctCaCredentialHandlesByOrganizationId(2L)).thenReturn(List.of());
        when(credentialReferenceRepository.findDistinctKvPathsByOrganizationId(2L)).thenReturn(List.of());

        assertThat(service.derivePaths(2L)).containsExactly("p1");
    }
}
