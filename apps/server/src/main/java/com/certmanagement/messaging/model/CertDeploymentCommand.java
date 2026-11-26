// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Published to the organization's inbound queue ({orgId}-agent-inbound) with MessageType=CERT_DEPLOYMENT.
 *
 * Application properties set on the TransportMessage (for log correlation; routing is by queue):
 *   organizationId    — the organization
 *   MessageType — "CERT_DEPLOYMENT"
 *   requestId   — idempotency key
 */
@Data
@Jacksonized
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CertDeploymentCommand {

    private String organizationId;
    /** Org type, always "B2B"; kept because the agent's message contract carries it. Required. */
    private String orgType;
    private String requestId;
    private String correlationId;
    private String certificateXref;
    private String domain;

    /** Secret-store handle where the issued cert PEM bundle is stored (source). */
    private String certSecretHandle;

    /** Deployment target type — see {@link TargetType}. */
    private TargetType targetType;

    /** Secret-store handle of the deployment service-principal / role credential. */
    private String deploymentCredHandle;

    /**
     * Credential-scope JSON — the {@code credential_references.config} value for the deployment
     * credential (region, tenantId, allowed-* lists, authMode, etc.). Lets the agent build cloud
     * clients without re-fetching the credential row.
     *
     * <p>Null only when the credential has no scope configuration.
     */
    private String credentialScopeJson;

    /**
     * Targets JSON — the {@code targets} side of the per-cert deployment config envelope
     * ({@code cert_deployment_config.config.targets}). Per-cert deployment plan
     * (listenerArns, customDomains, namespaces map, zones, etc.).
     *
     * <p>Null for Kubernetes (uses legacy flat shape via {@link #configJson}) and for
     * adapters that don't yet have a targets schema.
     */
    private String targetsJson;

    /**
     * Per-cert deployment state (the {@code result} side of the envelope):
     * <ul>
     *   <li>Non-K8s providers: just the {@code result} slice — flat per-provider shape
     *       that adapters already understand (e.g. {@code {"arn":"..."}} or {@code {"certificateName":"..."}}).
     *       Null on first deploy.</li>
     *   <li>Kubernetes: legacy flat shape {@code {authProvider, clusterName, nsMaps}}
     *       — preserved as-is until its own refactor.</li>
     * </ul>
     */
    private String configJson;

    @Builder.Default
    private String requestedAt = OffsetDateTime.now(ZoneOffset.UTC).toString();
}
