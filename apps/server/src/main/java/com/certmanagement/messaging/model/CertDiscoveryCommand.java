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
 * Published to the organization's inbound queue ({orgId}-agent-inbound) with MessageType=CERT_DISCOVERY.
 *
 * Application properties set on the TransportMessage (for log correlation; routing is by queue):
 *   organizationId       — the organization
 *   MessageType          — "CERT_DISCOVERY"
 *   requestId            — idempotency key
 *
 * The agent reads deploymentCredHandle from its secret store to obtain
 * provider secrets, and credentialScopeJson for non-secret scope such as AWS
 * region/auth mode or Azure tenant/vault.
 */
@Data
@Jacksonized
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CertDiscoveryCommand {

    private String organizationId;
    /** Org type, always "B2B"; kept because the agent's message contract carries it. Required. */
    private String orgType;
    private String requestId;
    private String correlationId;

    /** Which cloud/platform target to scan. Must match agent's TargetType enum. */
    private String targetType;

    /**
     * Secret-store handle of the deployment credential used to authenticate with the
     * target cloud provider (e.g. AWS access key / secret JSON).
     */
    private String deploymentCredHandle;

    /**
     * Credential-scoped, non-secret provider config from credential_references.config.
     */
    private String credentialScopeJson;

    /** ISO-8601 UTC timestamp when the server dispatched this command. */
    @Builder.Default
    private String requestedAt = OffsetDateTime.now(ZoneOffset.UTC).toString();
}
