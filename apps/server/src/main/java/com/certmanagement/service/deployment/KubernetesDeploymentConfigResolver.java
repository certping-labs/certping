// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment;

import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.exception.BadRequestException;
import tools.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class KubernetesDeploymentConfigResolver {

    private final CertDeploymentConfigService certDeploymentConfigService;

    public String resolveOrUpsert(
            Long organizationId,
            Long userDomainCertId,
            CredentialReferenceEntity deployCred,
            Boolean useDefault,
            JsonNode nsSecretMap,
            String contextId) {
        if (!"KUBERNETES_SECRETS".equals(deployCred.getProvider())) {
            throw new BadRequestException("config is supported only for provider KUBERNETES_SECRETS");
        }
        if (userDomainCertId == null) {
            throw new BadRequestException("Certificate has no userDomainCertId; cannot store kubernetes deployment config");
        }
        if (Boolean.TRUE.equals(useDefault)) {
            if (nsSecretMap != null) {
                log.info("Ignoring kubernetes config.nsSecretMap because useDefault=true for target={}", contextId);
            }
            return certDeploymentConfigService.requireReconciledConfigJson(organizationId, userDomainCertId, deployCred);
        }
        return certDeploymentConfigService.validateAndUpsertKubernetesConfig(
                organizationId,
                userDomainCertId,
                deployCred,
                nsSecretMap);
    }
}
