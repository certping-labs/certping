// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig;

import tools.jackson.databind.JsonNode;
import lombok.Data;

/**
 * Replaces the {@code targets} side of the deployment-target envelope for a
 * {@code (cert × deploymentCredential)} pair. Preserves the {@code result} side (so the next
 * deploy is a "subsequent" deploy and reuses the provider-issued identifiers).
 *
 * <p>For {@code KUBERNETES_SECRETS}, the legacy {@link KubernetesDeploymentConfigRequest} body
 * is also accepted and routed through the existing validator.
 */
@Data
public class EditDeploymentTargetRequest {

    /** Generic targets payload — provider-specific schema; validated by the registry. */
    private JsonNode targets;

    /** Legacy kubernetes config — accepted only when the credential's provider is KUBERNETES_SECRETS. */
    private KubernetesDeploymentConfigRequest config;
}
