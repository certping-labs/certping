// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Inbound message from cert-agent-outbound with MessageType=CERT_DISCOVERY_RESPONSE.
 *
 * <p>Field names mirror the agent's {@code CertDiscoveryResponse} exactly so that
 * Jackson round-trips cleanly through the message queue without mapping config.
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertDiscoveryResponse {

    private String requestId;
    private String correlationId;
    private String organizationId;

    /** Matches the targetType sent in the original {@link CertDiscoveryCommand}. */
    private String targetType;

    /** "SUCCESS" or "FAILED". */
    private String status;

    private List<DiscoveredCertEntry> discoveredCerts;

    /** Non-null when status is "FAILED". */
    private String errorCode;
    private String errorDetail;

    /**
     * Parts of the scan the agent could not read; empty or absent when it read everything.
     * Stored certificates in these scopes are never marked MISSING, and the scan ends PARTIAL.
     */
    private List<DiscoveryFailedScope> failedScopes;

    /** ISO-8601 UTC timestamp when the agent completed the scan. */
    private String respondedAt;

    /**
     * Zero-based index of this batch within the overall response.
     * Defaults to 0 for single-batch (legacy) responses.
     */
    private int batchIndex;

    /**
     * Total number of batches being sent for this request.
     * Defaults to 1 for single-batch (legacy) responses.
     */
    private int totalBatches = 1;
}
