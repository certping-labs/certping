// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.agent;

import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

@Data
@Jacksonized
@Builder
public class AgentHeartbeatCadenceDto {
    private Integer heartbeatCadenceMinutes;
}
