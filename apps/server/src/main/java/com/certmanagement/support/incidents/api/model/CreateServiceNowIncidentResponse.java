// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.api.model;

import io.swagger.v3.oas.annotations.media.Schema;

public record CreateServiceNowIncidentResponse(
        @Schema(description = "Created ServiceNow incident sys_id.", example = "d977b66a4f411200adf9f8e18110c7b2")
        String sysId,
        @Schema(description = "Created ServiceNow incident number.", example = "INC0010002")
        String number,
        @Schema(description = "Absolute API URL of the created incident record.", example = "https://example.service-now.com/api/now/table/incident/d977b66a4f411200adf9f8e18110c7b2")
        String recordUrl,
        @Schema(description = "Absolute UI URL of the created ServiceNow incident.", example = "https://example.service-now.com/nav_to.do?uri=incident.do?sys_id=d977b66a4f411200adf9f8e18110c7b2")
        String displayUrl
) {
}
