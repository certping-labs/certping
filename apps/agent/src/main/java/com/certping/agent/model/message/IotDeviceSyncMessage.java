// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Inbound command from the server: ask one managed device to check in with Intune. Best-effort — carries no credential; the source
 * connection resolves to indexed local agent configuration. Metadata only, never cert material.
 */
@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class IotDeviceSyncMessage {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private String sourceXref;
    /** INTUNE | JAMF | … — selects the connector. Without it the agent cannot route. */
    private String provider;
    private String connectionProfileRef;
    /** The provider managed-device id to sync (Intune managedDevice id). */
    private String managedDeviceId;
    /** Correlation back to the server's rows; never used for routing. */
    private String deviceXref;
    private List<String> certificateXrefs;
    /** Advisory operator-action reason. */
    private String reason;
    private String requestedAt;
}
