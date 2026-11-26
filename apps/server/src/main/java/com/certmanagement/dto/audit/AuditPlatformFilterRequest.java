// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.audit;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * The filters of the platform view ({@code GET /api/v1/admin/audit-logs} and its export): the list's, where
 * {@code organizationId} is optional (none reads every organization), plus the visibility.
 */
@Data
@EqualsAndHashCode(callSuper = true)
@Schema(description = "Filters of the platform audit view")
public class AuditPlatformFilterRequest extends AuditEventFilterRequest {

    @Schema(description = "CUSTOMER (rows in an organization's trail) or INTERNAL (the platform's own); both "
            + "when omitted", example = "INTERNAL")
    private String visibility;
}
