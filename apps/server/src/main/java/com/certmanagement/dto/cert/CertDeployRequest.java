// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.cert;

import com.certmanagement.messaging.model.TargetType;
import tools.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

/**
 * Request body for POST /api/v1/certs/{certXref}/deploy.
 *
 * deployToVaultUri, deployToCertArn, and certificateName have been removed —
 * these values are now embedded inside the deployment credential KV secret
 * and the agent reads them directly at execution time.
 */
@Data
public class CertDeployRequest {

    /**
     * Deployment credentialXref.
     * Must be type=DEPLOYMENT, status=ACTIVE.
    * The KV secret at this credential's secretHandle must contain all deployment
    * target configuration for the selected target type.
     */
    @NotBlank
    private String deploymentCredentialXref;

    /**
     * Deployment target type.
     * Must match the provider of the resolved deploymentCredentialXref.
        * AZURE_KV | AWS_ACM | AZURE_APP_GW | AZURE_APP_GW_CONTAINERS | AZURE_AFD |
        * AWS_ALB | AWS_NLB | AWS_API_GW_REST | AWS_API_GW_HTTP | AWS_CLOUDFRONT |
        * CLOUDFLARE_EDGE | AKAMAI_CPS | F5_BIGIP
     */
        @NotNull(message = "targetType is required (AZURE_KV | AWS_ACM | AZURE_APP_GW | AZURE_APP_GW_CONTAINERS | AZURE_AFD | AWS_ALB | AWS_NLB | AWS_API_GW_REST | AWS_API_GW_HTTP | AWS_CLOUDFRONT | CLOUDFLARE_EDGE | AKAMAI_CPS | F5_BIGIP)")
    private TargetType targetType;

    /** For KUBERNETES_SECRETS, true means use previously saved deployment config. */
    private Boolean useDefault;

    /** For KUBERNETES_SECRETS with useDefault=false, this is the nsSecretMap payload. */
    private JsonNode config;

    /**
     * Generic provider-specific targets (non-Kubernetes).
     * E.g. for AZURE_KV: {@code {"certificateName":"wildcard-prod"}}
     * Persisted as the targets side of cert_deployment_config.configJson before deploying.
     */
    private JsonNode targets;
}
