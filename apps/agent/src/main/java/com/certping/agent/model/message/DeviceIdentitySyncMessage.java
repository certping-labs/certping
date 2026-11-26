// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Inbound sync command from the server.
 *
 * <p>Only a FULL run is accepted. Provider health is agent-owned and uses a separate message.
 * This command carries no credential. The profile reference resolves to indexed local agent
 * configuration.
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class DeviceIdentitySyncMessage {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String sourceXref;
    /** INTUNE | JAMF | … — selects the connector. Without it the agent cannot route. */
    private String provider;
    private String connectionProfileRef;
    private String syncXref;
    /** FULL */
    private String mode;
    private String requestedAt;
}
