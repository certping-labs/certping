// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.pqc.PqcReadinessReport;
import com.certmanagement.dto.pqc.PqcReadinessReport.CertDetail;
import com.certmanagement.dto.pqc.PqcReadinessReport.HndlRisk;
import com.certmanagement.dto.pqc.PqcReadinessReport.QuantumStatus;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.cbom.PqcReadinessService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PqcReadinessControllerTest {

    @Mock
    private PqcReadinessService pqcReadinessService;

    @InjectMocks
    private PqcReadinessController pqcReadinessController;

    private static final Long ORG_ID = 42L;

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void getPqcReadiness_delegatesToServiceAndReturns200() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "user@test.com");

        PqcReadinessReport report = new PqcReadinessReport(
                new PqcReadinessReport.Summary(2, 0, 1, 1, 0, 1),
                List.of(new PqcReadinessReport.AlgorithmGroup(
                        "RSA", 2048, null, QuantumStatus.DEPRECATED_2030, 2030, 2035, 2)));
        when(pqcReadinessService.summary(ORG_ID)).thenReturn(report);

        ResponseEntity<PqcReadinessReport> response = pqcReadinessController.getPqcReadiness();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isSameAs(report);
        verify(pqcReadinessService).summary(ORG_ID);
    }

    @Test
    void getPqcReadiness_emptyOrg_returnsEmptyReport() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-2", "user@test.com");

        PqcReadinessReport emptyReport = new PqcReadinessReport(
                new PqcReadinessReport.Summary(0, 0, 0, 0, 0, 0), List.of());
        when(pqcReadinessService.summary(ORG_ID)).thenReturn(emptyReport);

        ResponseEntity<PqcReadinessReport> response = pqcReadinessController.getPqcReadiness();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().summary().total()).isZero();
    }

    @Test
    void listCertificates_passesFilterAndPageThrough() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-3", "user@test.com");
        Pageable pageable = PageRequest.of(1, 15);
        CertDetail detail = new CertDetail(
                "cert-123", "example.com", "SHA256withRSA", "RSA", 2048, null,
                QuantumStatus.DEPRECATED_2030, HndlRisk.HIGH,
                2030, 2035, "NIST IR 8547 (Nov 2024)",
                "Plan migration to ML-DSA before 2030.", "MANAGED");
        Page<CertDetail> page = new PageImpl<>(List.of(detail), pageable, 16);
        when(pqcReadinessService.certificates(ORG_ID, QuantumStatus.DEPRECATED_2030, pageable)).thenReturn(page);

        ResponseEntity<Page<CertDetail>> response =
                pqcReadinessController.listCertificates(QuantumStatus.DEPRECATED_2030, pageable);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isSameAs(page);
    }
}
