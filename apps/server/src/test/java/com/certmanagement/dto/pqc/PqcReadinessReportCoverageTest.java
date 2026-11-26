// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.pqc;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PqcReadinessReportCoverageTest {

    @Test
    void recordsAndEnums() {
        var summary = new PqcReadinessReport.Summary(10, 2, 3, 4, 1, 5);
        assertThat(summary.total()).isEqualTo(10);
        assertThat(summary.pqcCompliant()).isEqualTo(2);
        assertThat(summary.deprecated2030()).isEqualTo(3);
        assertThat(summary.disallowed2035()).isEqualTo(4);
        assertThat(summary.unknown()).isEqualTo(1);
        assertThat(summary.highHndlRisk()).isEqualTo(5);

        var detail = new PqcReadinessReport.CertDetail(
                "xref", "cn", "SHA256withRSA", "RSA", 2048, "P-256",
                PqcReadinessReport.QuantumStatus.DEPRECATED_2030,
                PqcReadinessReport.HndlRisk.HIGH, 2030, 2035, "NIST", "advice", "MANAGED");
        assertThat(detail.certificateXref()).isEqualTo("xref");
        assertThat(detail.commonName()).isEqualTo("cn");
        assertThat(detail.signatureAlgorithm()).isEqualTo("SHA256withRSA");
        assertThat(detail.publicKeyAlgorithm()).isEqualTo("RSA");
        assertThat(detail.keySize()).isEqualTo(2048);
        assertThat(detail.curve()).isEqualTo("P-256");
        assertThat(detail.quantumStatus()).isEqualTo(PqcReadinessReport.QuantumStatus.DEPRECATED_2030);
        assertThat(detail.hndlRisk()).isEqualTo(PqcReadinessReport.HndlRisk.HIGH);
        assertThat(detail.deprecationYear()).isEqualTo(2030);
        assertThat(detail.disallowedYear()).isEqualTo(2035);
        assertThat(detail.complianceRef()).isEqualTo("NIST");
        assertThat(detail.remediationAdvice()).isEqualTo("advice");

        var group = new PqcReadinessReport.AlgorithmGroup(
                "RSA", 2048, null, PqcReadinessReport.QuantumStatus.DEPRECATED_2030, 2030, 2035, 3);
        assertThat(group.publicKeyAlgorithm()).isEqualTo("RSA");
        assertThat(group.keySize()).isEqualTo(2048);
        assertThat(group.curve()).isNull();
        assertThat(group.quantumStatus()).isEqualTo(PqcReadinessReport.QuantumStatus.DEPRECATED_2030);
        assertThat(group.deprecationYear()).isEqualTo(2030);
        assertThat(group.disallowedYear()).isEqualTo(2035);
        assertThat(group.certificates()).isEqualTo(3);

        var report = new PqcReadinessReport(summary, List.of(group));
        assertThat(report.summary()).isSameAs(summary);
        assertThat(report.algorithms()).containsExactly(group);

        for (var s : PqcReadinessReport.QuantumStatus.values()) {
            assertThat(PqcReadinessReport.QuantumStatus.valueOf(s.name())).isSameAs(s);
        }
        for (var h : PqcReadinessReport.HndlRisk.values()) {
            assertThat(PqcReadinessReport.HndlRisk.valueOf(h.name())).isSameAs(h);
        }
    }
}
