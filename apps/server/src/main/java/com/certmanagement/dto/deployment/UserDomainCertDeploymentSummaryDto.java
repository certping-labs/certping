// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.deployment;

import lombok.Builder;
import lombok.extern.jackson.Jacksonized;
import lombok.Data;

@Data
@Jacksonized
@Builder
public class UserDomainCertDeploymentSummaryDto {
    private Long userDomainCertId;
    private String domain;
    private long deploymentsRequested;
    private long deploymentsSucceeded;
    private long deploymentsFailed;
}
