// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.model.enums.TargetType;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Inbound deployment command sent from certping to the agent.
 *
 * <p>{@code MessageType} is carried in the message application properties, not in the JSON body.
 * {@code deploymentCredHandle} points to deployment credentials in client Key Vault.
 * For Kubernetes targets it is required for all authProvider values except {@code SA_INCLUSTER}.
 *
 * <p>Three JSON-string fields carry adapter-relevant config:
 * <ul>
 *   <li>{@link #credentialScopeJson} — credential-wide scope (region, tenantId, allowed-* lists,
 *       authMode). Mirrors {@code credential_references.config}.</li>
 *   <li>{@link #targetsJson} — per-cert deployment plan (listenerArns, customDomains, zones,
 *       SSL profiles, etc.). The {@code targets} half of the cert_deployment_config envelope.</li>
 *   <li>{@link #configJson} — per-cert state from prior deployments (the {@code result} half,
 *       flat per-provider shape: {@code {"arn":"..."}}, {@code {"certificateName":"..."}}, etc.).
 *       For Kubernetes, this remains the legacy flat shape
 *       ({@code {authProvider, clusterName, nsMaps}}).</li>
 * </ul>
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertDeploymentMessage {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String certificateXref;
    private String domain;
    private String certSecretHandle;
    private TargetType targetType;
    private String deploymentCredHandle;
    private String requestedAt;

    /** Credential-wide scope (mirrors the server's {@code credential_references.config}). */
    private String credentialScopeJson;

    /** Per-cert deployment plan (the {@code targets} half of the envelope). */
    private String targetsJson;

    /** Per-cert state from prior deployments (the {@code result} half, agent-flat per-provider shape). */
    private String configJson;
}
