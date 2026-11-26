// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class AgentHeartbeatCadenceUpdateMessage {
    private String requestId;
    private String correlationId;
    private String organizationId;
    private Integer heartbeatCadenceMinutes;
    private String requestedAt;
}
