// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Received from certping-agent on cert-agent-outbound with MessageType=AGENT_ERROR.
 *
 * Notable errorCode values:
 *   CREDENTIAL_NOT_FOUND — agent could not read the credential from its secret store
 *   ACME_NETWORK_ERROR   — ACME CA unreachable
 *   ACME_CHALLENGE_FAILED — DNS challenge validation failed
 *   DEPLOYMENT_FAILED    — cert deployment to target store failed
 */
@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AgentErrorMessage {

    private String requestId;
    private String correlationId;
    private String organizationId;
    private String certificateXref;

    /**
     * Optional platform xref when the failed command was a device-identity sync.
     * Absent on older agent builds — the server falls back to in-progress platforms for the org.
     */
    private String sourceXref;
    private String syncXref;

    /**
     * Original MessageType that triggered this error:
     * CERT_ISSUANCE | CERT_RENEWAL | CERT_DEPLOYMENT | CERT_REVOCATION_COMMAND | CERT_DISCOVERY
     * | DEVICE_IDENTITY_SYNC_COMMAND | IOT_CERTIFICATE_PROFILE_COMMAND
     * | IOT_CERTIFICATE_PROFILE_SYNC_COMMAND | IOT_CERTIFICATE_REVOCATION_COMMAND
     * | IOT_INTUNE_REVOCATION_POLL_COMMAND | IOT_INTUNE_REVOCATION_UPLOAD_COMMAND
     */
    private String originalMessageType;

    private String errorCode;

    /** Agent sends this as "errorDetail" (not "errorMessage") — field name must match wire format. */
    private String errorDetail;

    /** Agent sends this as "respondedAt" — field name must match wire format. */
    private String respondedAt;

    /**
     * ISO-8601 UTC instant the upstream told us to retry at — present on
     * {@code RETRY_GIVE_UP} when the last attempt's upstream supplied a {@code Retry-After}
     * (LE/CA rate-limit, provider 429). {@code null} for blind give-ups and first-try
     * permanent failures. Surfaced in the UI as "Try again after &lt;time&gt;".
     */
    private String retryAfterUtc;

    /**
     * Underlying classifier code from the LAST attempt when {@code errorCode} is the
     * outer {@code RETRY_GIVE_UP} wrapper (e.g. {@code ACME_RATE_LIMITED},
     * {@code DEPLOY_PROVIDER_THROTTLED}). Lets us pick specific user-facing text instead
     * of the generic "we gave up" message. {@code null} when {@code errorCode} is itself
     * terminal.
     */
    private String lastReason;
}
