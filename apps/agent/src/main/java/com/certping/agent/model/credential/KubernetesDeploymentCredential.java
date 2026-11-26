// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.credential;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Credential payload for Kubernetes deployment authentication.
 *
 * <p>Fields are intentionally optional because each auth provider consumes a different subset.
 * Validation happens in KubernetesAuthService where the selected provider is known.
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class KubernetesDeploymentCredential {

    /**
     * Static Kubernetes API endpoint used by SA_TOKEN mode.
     * Example: https://abc.gr7.us-east-1.eks.amazonaws.com
     */
    private String apiServer;

    /**
     * PEM-encoded cluster CA certificate used by SA_TOKEN mode.
     */
    private String caCertPem;

    /**
     * Base64-encoded cluster CA certificate used by SA_TOKEN mode.
     */
    private String caCertBase64;

    /**
     * Bearer token used by SA_TOKEN mode.
     */
    private String bearerToken;

    /**
     * AWS region for EKS lookup in AWS mode.
     * Still required when using workload identity because the agent must know which regional EKS API to call.
     */
    private String awsRegion;

    /**
     * Optional IAM role ARN to assume before talking to EKS.
     *
     * <p>If static keys are also present, they are used first as the bootstrap identity for STS.
     * If the role ARN is present without static keys, the agent attempts workload identity
     * (for example IRSA) as the STS bootstrap identity.
     */
    private String awsRoleArn;

    /**
     * Static AWS access key used either directly against EKS or as the bootstrap identity for STS AssumeRole.
     * When absent, AWS mode may still succeed through workload identity if awsRoleArn is present.
     */
    private String awsAccessKeyId;

    /**
     * Static AWS secret key paired with awsAccessKeyId.
     */
    private String awsSecretAccessKey;

    /**
     * Azure subscription id used by AKS mode.
     * Required for both explicit client-secret auth and workload identity because ARM still needs the target subscription.
     */
    private String azureSubscriptionId;

    /**
     * Azure resource group containing AKS cluster.
     * Required for both explicit client-secret auth and workload identity because ARM still needs the target cluster resource.
     */
    private String azureResourceGroup;

    /**
     * Azure AD application client id used to request AKS user credentials through ARM.
     * Required for explicit client-secret auth and for Azure workload identity.
     */
    private String azureClientId;

    /**
     * Azure AD application client secret used to request AKS user credentials through ARM.
     * Optional when Azure workload identity is configured on the pod.
     */
    private String azureClientSecret;

    /**
     * Azure tenant id hosting the application registration.
     * Required for both explicit client-secret auth and Azure workload identity.
     */
    private String azureTenantId;

    /**
     * GCP project id used by GKE mode.
     * Required for both explicit service-account auth and workload identity because the agent still has to locate the cluster.
     */
    private String gcpProjectId;

    /**
     * GCP location (zone/region) used by GKE mode.
     * Required for both explicit service-account auth and workload identity.
     */
    private String gcpLocation;

    /**
     * Service account JSON used to call GKE APIs and obtain access tokens.
     * Optional when the pod is running with GKE workload identity / application default credentials.
     */
    private String gcpServiceAccountJson;

    /**
     * Base64-encoded GCP service account JSON. Useful when secret stores escape JSON aggressively.
     * Optional when workload identity is configured.
     */
    private String gcpServiceAccountJsonBase64;

    /**
     * Optional service account token for direct in-cluster API usage.
     */
    private String serviceAccountToken;
}
