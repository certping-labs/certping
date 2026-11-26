// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Completion signal sent by the agent after all {@code CERT_DISCOVERY_RESPONSE} batches
 * for a given request have been published.
 */
@Data
@NoArgsConstructor
public class DiscoveryCompleteMessage {

    private String requestId;
    private String organizationId;
    private String targetType;
    private int    totalCerts;
    private String completedAt;

    /** Same list as {@link CertDiscoveryResponse#getFailedScopes()}; empty or absent when the scan was complete. */
    private java.util.List<DiscoveryFailedScope> failedScopes;
}
