// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.model.enums.TargetType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Sent by the agent after all {@code CERT_DISCOVERY_RESPONSE} batches for a given request
 * have been published. Allows the server to confirm batch completion.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertDiscoveryCompleteMessage {

    private String     requestId;
    private String     organizationId;
    private TargetType targetType;
    private int        totalCerts;
    private String     completedAt;
    /** Same list as {@code CertDiscoveryResponse.failedScopes}; empty when the scan was complete. */
    private java.util.List<DiscoveryFailedScope> failedScopes;
}
