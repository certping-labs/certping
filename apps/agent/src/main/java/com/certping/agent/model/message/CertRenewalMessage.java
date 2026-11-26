// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.exception.CheckpointRecorder;
import com.certping.agent.exception.IssuanceCheckpoint;
import com.certping.agent.model.enums.CaProvider;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Inbound message — certping → agent (published to {orgId}-agent-inbound).
 *
 * <p>The {@code MessageType} is read from the message <em>application property</em> by
 * {@link com.certping.agent.listener.AgentMessageListener} — it is NOT a JSON body field.
 *
 * dnsProvider         — DNS provider type: CLOUDFLARE, AWS_ROUTE53, GODADDY, NAMEDOTCOM, HOSTINGER, NAMECHEAP.
 * dnsCredentialHandle   — KV URI to a raw credential for the primary domain.
 * currentValidTo      — ISO-8601 expiry of the current cert.
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertRenewalMessage {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String certificateXref;
    private String domain;
    private boolean wildcard;
    private CaProvider caProvider;
    /** Validity period in days. Honored by paid CAs; LE ignores. Null = agent default. */
    private Integer validityDays;
    private String dnsProvider;
    private String dnsCredentialHandle;
    private List<SanDomainEntry> sanDomainEntries;
    private String caCredentialHandle;
    private String acmeAccountHandle;
    /** Previous CA order id (used by commercial CAs for renewal linkage). */
    private String orderId;
    /**
     * KV URI of the CURRENT cert PEM, used by LE for ACME ARI ({@code newOrder.replaces}).
     * Null on first issuance, non-LE CAs, or older server versions that don't supply it.
     */
    private String previousCertSecretHandle;
    private String currentValidTo;
    /** Days before expiry that renewals start. */
    private Integer renewalWindowDays;
    private String requestedAt;
    /** Optional CA-specific options. */
    private Map<String, String> caOptions;

    /**
     * Transient resume hint populated by the listener from message {@code Checkpoint.*} application
     * properties on a retry delivery. Never sent over the wire.
     */
    @JsonIgnore
    private IssuanceCheckpoint checkpoint;

    /**
     * Transient, set by the processor: this attempt is the last a DNS propagation wait may take, because the
     * message's retries for {@code DNS_PROPAGATION_PENDING} are used up. Records still propagating are then
     * removed and the wait fails as {@code DNS_PROPAGATION_TIMEOUT}.
     */
    @JsonIgnore
    private boolean finalPropagationWait;

    /**
     * Transient, set by the processor: the last instant this message may still be worked on (its original enqueue
     * time plus the attempt-age bound). A paid CA order is placed only with enough of it left to be collected.
     */
    @JsonIgnore
    private Instant attemptDeadline;

    /**
     * Transient, set by the processor: records this attempt's checkpoints next to the certificate, so a message
     * delivered again resumes from the order already sent instead of ordering again.
     */
    @JsonIgnore
    private CheckpointRecorder checkpointRecorder = CheckpointRecorder.NONE;

    /**
     * Transient, set by the processor: names this attempt, the same for every delivery and retry copy of the command
     * (see {@code ScheduledRetryService.attemptKey}).
     */
    @JsonIgnore
    private String attemptKey;
}
