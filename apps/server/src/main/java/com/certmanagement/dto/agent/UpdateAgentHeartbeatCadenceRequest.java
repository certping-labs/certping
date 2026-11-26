// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.agent;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class UpdateAgentHeartbeatCadenceRequest {
    @NotNull
    @Min(1)
    @Max(60)
    private Integer heartbeatCadenceMinutes;
}
