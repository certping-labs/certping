// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Received from certping-agent on cert-agent-outbound with MessageType=CERT_DEPLOYMENT_RESPONSE.
 *
 * <p>{@code targetType} is declared as {@link TargetType} enum so Jackson rejects unexpected
 * values early (before the processor tries to use it), matching the type used in the outbound
 * {@link CertDeploymentCommand}.
 *
 * <p>{@code @JsonIgnoreProperties(ignoreUnknown = true)} ensures forward-compatibility if the
 * agent adds new fields in future without breaking the server's deserialiser.
 */
@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertDeploymentResponse {

    private String requestId;
    private String correlationId;
    private String organizationId;
    private String certificateXref;

    /** "SUCCESS" — set by certping-agent on successful deployment */
    private String status;

    /** Mirrors the targetType from the command. */
    private TargetType targetType;

    /**
    * The resource identifier of the deployed certificate (target-specific).
    * Examples: Azure KV certificate ID, ACM certificate ARN, gateway or listener resource ID.
     * Must not be null/empty when status = "SUCCESS".
     */
    private String targetResourceId;

    private String respondedAt;

    /**
     * Per-domain config returned by the agent on the first deployment for a domain.
     * The server merges this into {@code credential_references.config} and passes a
     * per-domain slice on all future deployments. Null on subsequent deployments.
     * AWS: {"arn":"arn:aws:acm:..."} | Azure KV: {"certificateName":"example-com"}
     */
    private String configJson;
}
