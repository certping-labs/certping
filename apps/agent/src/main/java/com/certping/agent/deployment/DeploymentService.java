// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment;

import com.certping.agent.deployment.adapter.DeploymentAdapter;
import com.certping.agent.deployment.adapter.DeploymentAdapterFactory;
import com.certping.agent.deployment.util.CertificateBundleUtils;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Orchestrates the CERT_DEPLOYMENT flow:
 *
 * Step 1 — Read cert PEM bundle from the secret store (certSecretHandle from message)
 * Step 2 — Parse PEM bundle into CertificateBundle (leaf, chain, private key)
 * Step 3 — Create appropriate adapter (Azure KV or AWS ACM) via factory
 * Step 4 — Call adapter.deploy() → DeploymentResult with targetResourceId
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DeploymentService {

    private final SecretStore secretStore;
    private final DeploymentAdapterFactory adapterFactory;

    public DeploymentResult deploy(CertDeploymentMessage message) {
        log.info("DeploymentService: targetType={}, xref={}, certSecretHandle={}",
                message.getTargetType(), message.getCertificateXref(), message.getCertSecretHandle());

        // Step 1 — Read cert PEM bundle from the secret store
        String rawBundle = secretStore.read(message.getCertSecretHandle());

        // Step 2 — Parse PEM bundle
        CertificateBundle bundle = CertificateBundleUtils.parse(rawBundle);
        log.debug("PEM bundle parsed: hasLeaf={}, hasChain={}, hasKey={}",
                !bundle.leafCertificate().isBlank(),
                !bundle.certChain().isBlank(),
                !bundle.privateKey().isBlank());

        // Step 3 — Select adapter
        DeploymentAdapter adapter = adapterFactory.create(message.getTargetType());

        // Step 4 — Deploy
        DeploymentResult result = adapter.deploy(bundle, message);
        log.info("Deployment complete: targetResourceId={}", result.targetResourceId());
        return result;
    }
}
