// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.agent;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

/**
 * {@code GET /api/v1/certificate-authorities}: every CA the organization can issue from. Metadata
 * only; no field here can carry a key or a secret.
 */
@JsonInclude(JsonInclude.Include.ALWAYS)
public record CertificateAuthoritiesResponse(List<Authority> authorities) {

    /**
     * @param id              LETS_ENCRYPT, DIGICERT or GLOBALSIGN
     * @param kind            ACME or API
     * @param status          CONFIGURED, NOT_CONFIGURED or UNKNOWN (no agent has reported yet)
     * @param configuredWhere AGENT or ORGANIZATION
     * @param maturity        TESTED or BETA
     */
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public record Authority(String id, String name, String kind, String status, String configuredWhere,
                            String maturity, List<AgentView> agents, List<CredentialView> credentials,
                            String docsPath) {
    }

    /** One agent's view of a CA; {@code acme} is set for Let's Encrypt only. */
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public record AgentView(String agentId, String agentName, String lastSeenAt, boolean configured,
                            AcmeView acme) {
    }

    /** The ACME directory and this organization's account on it; account fields are null before the first order. */
    @JsonInclude(JsonInclude.Include.ALWAYS)
    public record AcmeView(String directoryUrl, String environment, String contactEmail, String accountUrl,
                           String keyType, String createdAt) {
    }

    @JsonInclude(JsonInclude.Include.ALWAYS)
    public record CredentialView(String credentialXref, String description, String createdAt, String updatedAt) {
    }
}
