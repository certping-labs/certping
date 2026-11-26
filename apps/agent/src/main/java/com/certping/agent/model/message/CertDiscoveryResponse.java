// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.model.enums.TargetType;
import lombok.Builder;
import lombok.Value;

import java.util.List;

/**
 * Outbound discovery result sent from the agent to the server.
 *
 * <p>On success, {@code status} is {@code SUCCESS} and {@code discoveredCerts} contains a single
 * batch of certificates. Large result sets are split across multiple messages; {@code batchIndex}
 * (0-based) and {@code totalBatches} allow the server to track progress.
 * On failure, {@code status} is {@code FAILED} and {@code errorCode} / {@code errorDetail} describe the cause.
 */
@Value
@Builder
public class CertDiscoveryResponse {
    String requestId;
    String correlationId;
    String organizationId;
    TargetType targetType;
    String status;
    List<DiscoveredCertEntry> discoveredCerts;
    String errorCode;
    String errorDetail;
    String respondedAt;
    /** Zero-based index of this batch within the overall response. */
    int batchIndex;
    /** Total number of batches being sent for this request. */
    int totalBatches;
    /**
     * Scopes the scan could not read (accounts, regions, vaults, namespaces). Empty when the scan
     * saw everything. The same full list is sent on every batch of a request. When non-empty the
     * scan is partial: the server must not mark certificates in these scopes MISSING.
     */
    List<DiscoveryFailedScope> failedScopes;
}
