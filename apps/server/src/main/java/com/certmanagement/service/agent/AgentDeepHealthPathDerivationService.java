// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AgentDeepHealthPathDerivationService {

    private final CertificateRepository certificateRepository;
    private final RenewalScheduleRepository renewalScheduleRepository;
    private final CredentialReferenceRepository credentialReferenceRepository;

    public List<String> derivePaths(Long organizationId) {
        Set<String> dedup = new LinkedHashSet<>();
        addAll(dedup, certificateRepository.findDistinctCertSecretHandlesByOrganizationId(organizationId));
        addAll(dedup, certificateRepository.findDistinctAcmeAccountHandlesByOrganizationId(organizationId));
        addAll(dedup, certificateRepository.findDistinctCaCredentialHandlesByOrganizationId(organizationId));
        addAll(dedup, renewalScheduleRepository.findDistinctCertSecretHandlesByOrganizationId(organizationId));
        addAll(dedup, renewalScheduleRepository.findDistinctAcmeAccountHandlesByOrganizationId(organizationId));
        addAll(dedup, renewalScheduleRepository.findDistinctCaCredentialHandlesByOrganizationId(organizationId));
        addAll(dedup, credentialReferenceRepository.findDistinctKvPathsByOrganizationId(organizationId));
        return new ArrayList<>(dedup);
    }

    private void addAll(Set<String> target, List<String> values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                target.add(value.trim());
            }
        }
    }
}
