// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.deployment;

import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

@Data
@Jacksonized
@Builder
public class DeploymentSummaryDto {
    private long total;
    private long success;
    private long failed;
    private long publishFailed;
    private long inProgress;
}
