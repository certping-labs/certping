// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.agent;

import lombok.Data;

/**
 * Optional body for {@code POST /api/v1/agent/health/deep-checks}.
 * {@code organizationId} is required when the caller is {@code SUPER_ADMIN};
 * organization-scoped callers use the JWT organization and must not set this field.
 */
@Data
public class TriggerAgentDeepHealthRequest {
    private Long organizationId;
}
