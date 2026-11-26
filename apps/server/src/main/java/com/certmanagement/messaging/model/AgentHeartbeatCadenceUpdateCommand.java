// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

@Data
@Jacksonized
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AgentHeartbeatCadenceUpdateCommand {
    private String organizationId;
    /** Org type, always "B2B"; kept because the agent's message contract carries it. Required. */
    private String orgType;
    private String requestId;
    private String correlationId;
    private Integer heartbeatCadenceMinutes;

    @Builder.Default
    private String requestedAt = OffsetDateTime.now(ZoneOffset.UTC).toString();
}
