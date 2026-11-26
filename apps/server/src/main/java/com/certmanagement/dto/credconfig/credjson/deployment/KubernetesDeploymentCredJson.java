// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.deployment;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

/**
 * Kubernetes deployment — fields required depend on the auth mode picked in {@code configJson.authMethod}.
 *
 * <p><b>SA_INCLUSTER:</b> nothing here required — agent uses in-cluster SA token.
 *
 * <p><b>SA_TOKEN (out-of-cluster):</b>
 * <ul>
 *   <li>REQUIRED: {@code apiServer}, one of {@code bearerToken} or {@code serviceAccountToken},
 *       and one of {@code caCertPem} XOR {@code caCertBase64}.</li>
 * </ul>
 *
 * <p><b>AWS (EKS):</b>
 * <ul>
 *   <li>REQUIRED: {@code awsRegion}.</li>
 *   <li>One of: {@code awsRoleArn} OR ({@code awsAccessKeyId} + {@code awsSecretAccessKey}) —
 *       omit all three to use ambient workload identity.</li>
 * </ul>
 *
 * <p><b>AZURE (AKS):</b>
 * <ul>
 *   <li>REQUIRED: {@code azureTenantId}, {@code azureSubscriptionId}, {@code azureResourceGroup}, {@code azureClientId}.</li>
 *   <li>{@code azureClientSecret} REQUIRED for SERVICE_PRINCIPAL; OPTIONAL for WORKLOAD_IDENTITY.</li>
 * </ul>
 *
 * <p><b>GCP (GKE):</b>
 * <ul>
 *   <li>REQUIRED: {@code gcpProjectId}, {@code gcpLocation}.</li>
 *   <li>{@code gcpServiceAccountJson} XOR {@code gcpServiceAccountJsonBase64} — omit both to fall back
 *       to application-default credentials / workload identity.</li>
 * </ul>
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class KubernetesDeploymentCredJson implements CredJsonPayload {
    private String apiServer;
    private String caCertPem;
    private String caCertBase64;
    private String bearerToken;
    private String awsRegion;
    private String awsRoleArn;
    private String awsAccessKeyId;
    private String awsSecretAccessKey;
    private String azureSubscriptionId;
    private String azureResourceGroup;
    private String azureClientId;
    private String azureClientSecret;
    private String azureTenantId;
    private String gcpProjectId;
    private String gcpLocation;
    private String gcpServiceAccountJson;
    private String gcpServiceAccountJsonBase64;
    private String serviceAccountToken;
}
