// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.model.enums.TargetType;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Inbound discovery command sent from the server to the agent.
 *
 * <p>{@code MessageType} is carried in the message application properties, not in the JSON body.
 * {@code deploymentCredHandle} points to provider secrets in the client Key Vault.
 * {@code credentialScopeJson} carries non-secret provider scope, matching deployment messages.
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertDiscoveryMessage {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private TargetType targetType;
    private String deploymentCredHandle;
    private String credentialScopeJson;
    private String requestedAt;
}
