// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig;

import com.certmanagement.entity.DomainCredentialConfigEntity;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

@Data
@Jacksonized
@Builder
public class DomainCredentialConfigResponse {

    private Long id;
    private Long userDomainCertId;

    /** Current DNS bindings: { "example.com": "cred-xref-a", "example.org": "cred-xref-b" } */
    private Map<String, String> dnsConfig;

    /** Current deployment targets (ordered): ["cred-xref-deploy-1", "cred-xref-deploy-2"] */
    private List<String> deploymentTargets;

    private OffsetDateTime updatedAt;

    public static DomainCredentialConfigResponse from(DomainCredentialConfigEntity entity) {
        return DomainCredentialConfigResponse.builder()
                .id(entity.getId())
                .userDomainCertId(entity.getUserDomainCertId())
                .dnsConfig(entity.getDnsConfig())
                .deploymentTargets(entity.getDeploymentTargets())
                .updatedAt(entity.getUpdatedAt())
                .build();
    }
}
