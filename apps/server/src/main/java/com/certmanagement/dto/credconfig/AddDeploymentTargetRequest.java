// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig;

import tools.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class AddDeploymentTargetRequest {

    /**
     * Deployment credentialXref to add to deployment_targets.
     * Must be type=DEPLOYMENT, status=ACTIVE.
     */
    @NotBlank
    private String credentialXref;

    /**
     * Legacy field — Kubernetes-specific config payload ({@code useDefault} + {@code nsSecretMap}).
     * Used for {@code KUBERNETES_SECRETS} provider only. Other providers should use {@link #targets}.
     */
    private KubernetesDeploymentConfigRequest config;

    /**
     * Provider-specific targets payload — populates {@code cert_deployment_config.config.targets}.
     * Schema is per-provider (validated by {@code DeploymentTargetsValidator} for the credential's
     * provider). Optional on add — adapters that don't need a per-cert targets plan (e.g. AWS_ACM)
     * can omit this; the envelope is created with empty targets and the adapter populates result on
     * first deploy.
     */
    private JsonNode targets;
}
