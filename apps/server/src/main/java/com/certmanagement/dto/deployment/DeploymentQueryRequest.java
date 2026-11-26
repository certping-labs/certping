// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.deployment;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.OffsetDateTime;

@Data
@Schema(description = "Optional filters for GET /api/v1/deployments")
public class DeploymentQueryRequest {

    private Long id;
    private String requestId;
    private String certificateXref;
    private String status;
    private String targetType;
    private String flowType;
    @Schema(description = "Optional filter by user-domain certificate ID")
    private Long userDomainCertId;

    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private OffsetDateTime from;

    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private OffsetDateTime to;

    // list (default) or summary
    private String view;

    // Alias binding for query param userdomaincertificateid when using @ModelAttribute.
    public void setUserdomaincertificateid(Long userDomainCertId) {
        this.userDomainCertId = userDomainCertId;
    }
}
