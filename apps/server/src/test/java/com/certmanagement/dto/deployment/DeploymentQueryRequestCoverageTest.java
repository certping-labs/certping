// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.deployment;

import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;

class DeploymentQueryRequestCoverageTest {

    @Test
    void settersGettersAndAlias() {
        DeploymentQueryRequest r = new DeploymentQueryRequest();
        r.setId(1L);
        r.setRequestId("req");
        r.setCertificateXref("xref");
        r.setStatus("SUCCESS");
        r.setTargetType("AZURE_KV");
        r.setFlowType("ISSUANCE");
        r.setView("summary");
        OffsetDateTime now = OffsetDateTime.now();
        r.setFrom(now);
        r.setTo(now);
        r.setUserdomaincertificateid(99L);

        assertThat(r.getId()).isEqualTo(1L);
        assertThat(r.getRequestId()).isEqualTo("req");
        assertThat(r.getCertificateXref()).isEqualTo("xref");
        assertThat(r.getStatus()).isEqualTo("SUCCESS");
        assertThat(r.getTargetType()).isEqualTo("AZURE_KV");
        assertThat(r.getFlowType()).isEqualTo("ISSUANCE");
        assertThat(r.getView()).isEqualTo("summary");
        assertThat(r.getFrom()).isEqualTo(now);
        assertThat(r.getTo()).isEqualTo(now);
        assertThat(r.getUserDomainCertId()).isEqualTo(99L);
        assertThat(r.toString()).contains("req");
    }
}
