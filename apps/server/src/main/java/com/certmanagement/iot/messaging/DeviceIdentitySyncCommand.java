// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.messaging;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Published to the organization's inbound queue ({@code {orgId}-agent-inbound}) with
 * MessageType={@code DEVICE_IDENTITY_SYNC_COMMAND}.
 *
 * <p>Field names match the agent's {@code DeviceIdentitySyncMessage}. {@code orgType} is ignored by
 * the agent ({@code @JsonIgnoreProperties}).
 */
@Data
@Jacksonized
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DeviceIdentitySyncCommand {

    private String requestId;
    private String correlationId;
    private String organizationId;
    /** Org type, always "B2B"; kept because the agent's message contract carries it. */
    private String orgType;

    private String sourceXref;

    /** INTUNE | JAMF | … — selects the connector on the agent. */
    private String provider;

    /** Resolves one of the agent's local profiles. It is not a secret-store handle. */
    private String connectionProfileRef;

    /** Server-issued run identifier used to fence every response. */
    private String syncXref;

    /** FULL */
    private String mode;

    @Builder.Default
    private String requestedAt = OffsetDateTime.now(ZoneOffset.UTC).toString();
}
