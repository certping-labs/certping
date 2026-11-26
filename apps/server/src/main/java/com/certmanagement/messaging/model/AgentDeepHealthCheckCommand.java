// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

@Data
@Jacksonized
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AgentDeepHealthCheckCommand {
    private String deepCheckId;
    private String requestId;
    private String correlationId;
    private String organizationId;
    /** Org type, always "B2B"; kept because the agent's message contract carries it. Required. */
    private String orgType;
    private Integer chunkIndex;
    private Integer totalChunks;
    private List<String> secretHandles;

    @Builder.Default
    private String requestedAt = OffsetDateTime.now(ZoneOffset.UTC).toString();
}
