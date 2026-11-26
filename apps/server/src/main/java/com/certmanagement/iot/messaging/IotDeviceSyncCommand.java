// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.messaging;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

import java.util.List;

/**
 * Published to the org inbound queue with MessageType={@code IOT_DEVICE_SYNC_COMMAND}: a request
 * for the agent to ask one Intune managed device to check in.
 *
 * <p>Field names match the agent's inbound {@code IotDeviceSyncCommand}. {@code orgType} is ignored
 * by the agent ({@code @JsonIgnoreProperties}).
 */
@Data
@Jacksonized
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IotDeviceSyncCommand {

    private String requestId;
    private String correlationId;
    private String organizationId;
    /** Org type, always "B2B"; kept because the agent's message contract carries it. */
    private String orgType;

    private String sourceXref;

    /** INTUNE | … — selects the connector on the agent. */
    private String provider;

    /** Resolves one of the agent's local profiles / tenant credential. Not a secret-store handle. */
    private String connectionProfileRef;

    /** The Intune managedDevice id to sync. */
    private String managedDeviceId;

    /** Correlation back to the server's device and all eligible certificate rows. */
    private String deviceXref;
    private List<String> certificateXrefs;

    /** Stable operator-action reason. */
    private String reason;
    private String requestedAt;
}
