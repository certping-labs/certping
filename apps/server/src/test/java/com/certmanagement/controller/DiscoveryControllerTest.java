// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.discovery.DiscoveredCertDto;
import com.certmanagement.dto.discovery.DiscoveredCertDetailDto;
import com.certmanagement.dto.discovery.DiscoveryRunResponse;
import com.certmanagement.dto.discovery.TriggerDiscoveryRequest;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.discovery.DiscoveryService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.OffsetDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DiscoveryControllerTest {

    @Mock
    private DiscoveryService discoveryService;

    @InjectMocks
    private DiscoveryController controller;

    private static final Long   ORG_ID    = 42L;
    private static final String CRED_XREF = "cred-aws-001";
    private static final String REQ_ID    = "disc-req-123";

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    // ------------------------------------------------------------------ //
    //  POST /api/v1/discovery/trigger
    // ------------------------------------------------------------------ //

    @Test
    void triggerDiscovery_returns202WithRequestId() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "admin@example.com");
        DiscoveryRunResponse runResponse = DiscoveryRunResponse.builder()
                .status("STARTED")
                .requestId(REQ_ID)
                .targetType("AWS_ACM")
                .credentialXref(CRED_XREF)
                .message("Discovery has started. Results will appear shortly.")
                .build();
        when(discoveryService.triggerDiscovery(ORG_ID, "AWS_ACM", CRED_XREF)).thenReturn(runResponse);

        TriggerDiscoveryRequest request = new TriggerDiscoveryRequest();
        request.setTargetType("AWS_ACM");
        request.setCredentialXref(CRED_XREF);

        ResponseEntity<DiscoveryRunResponse> response = controller.triggerDiscovery(request, null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        DiscoveryRunResponse body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.getStatus()).isEqualTo("STARTED");
        assertThat(body.getRequestId()).isEqualTo(REQ_ID);
        assertThat(body.getTargetType()).isEqualTo("AWS_ACM");
        assertThat(body.getMessage()).isEqualTo("Discovery has started. Results will appear shortly.");

        verify(discoveryService).triggerDiscovery(ORG_ID, "AWS_ACM", CRED_XREF);
    }

    @Test
    void listDiscoveryConfigs_returnsAllStatuses() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "admin@example.com");
        DiscoveryRunResponse runResponse = DiscoveryRunResponse.builder()
                .configId(10L)
                .status("IN_PROGRESS")
                .targetType("AWS_ACM")
                .requestId(REQ_ID)
                .message("Discovery is still running. Results will appear shortly.")
                .build();
        when(discoveryService.listDiscoveryConfigs(ORG_ID)).thenReturn(List.of(runResponse));

        ResponseEntity<List<DiscoveryRunResponse>> response = controller.listDiscoveryConfigs(null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsExactly(runResponse);
        verify(discoveryService).listDiscoveryConfigs(ORG_ID);
    }

    @Test
    void getDiscoveryConfigStatus_usesPathConfigIdAndReturnsStatus() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "admin@example.com");
        DiscoveryRunResponse runResponse = DiscoveryRunResponse.builder()
                .configId(10L)
                .status("IN_PROGRESS")
                .targetType("AWS_ACM")
                .requestId(REQ_ID)
                .message("Discovery is still running. Results will appear shortly.")
                .build();
        when(discoveryService.getDiscoveryConfigStatus(ORG_ID, 10L)).thenReturn(runResponse);

        ResponseEntity<DiscoveryRunResponse> response =
                controller.getDiscoveryConfigStatus(10L, null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(runResponse);
        verify(discoveryService).getDiscoveryConfigStatus(ORG_ID, 10L);
    }

    @Test
    void triggerSavedDiscovery_usesPathConfigIdAndReturnsStatus() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "admin@example.com");
        DiscoveryRunResponse runResponse = DiscoveryRunResponse.builder()
                .configId(10L)
                .status("STARTED")
                .targetType("AWS_ACM")
                .requestId(REQ_ID)
                .message("Discovery has started. Results will appear shortly.")
                .build();
        when(discoveryService.triggerSavedDiscovery(ORG_ID, 10L)).thenReturn(runResponse);

        ResponseEntity<DiscoveryRunResponse> response =
                controller.triggerSavedDiscovery(10L, null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getBody()).isEqualTo(runResponse);
        verify(discoveryService).triggerSavedDiscovery(ORG_ID, 10L);
    }

    @Test
    void triggerAllSavedDiscovery_returns202WithStatuses() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "admin@example.com");
        DiscoveryRunResponse runResponse = DiscoveryRunResponse.builder()
                .configId(10L)
                .status("STARTED")
                .targetType("AWS_ACM")
                .requestId(REQ_ID)
                .message("Discovery has started. Results will appear shortly.")
                .build();
        when(discoveryService.triggerAllSavedDiscovery(ORG_ID)).thenReturn(List.of(runResponse));

        ResponseEntity<List<DiscoveryRunResponse>> response =
                controller.triggerAllSavedDiscovery(null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getBody()).containsExactly(runResponse);
        verify(discoveryService).triggerAllSavedDiscovery(ORG_ID);
    }

    @Test
    void deleteDiscoveryConfig_returns204() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "admin@example.com");

        ResponseEntity<Void> response = controller.deleteDiscoveryConfig(10L, null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(discoveryService).deleteDiscoveryConfig(ORG_ID, 10L);
    }

    // ------------------------------------------------------------------ //
    //  GET /api/v1/discovery/certs
    // ------------------------------------------------------------------ //

    @Test
    void listDiscoveredCerts_returnsPagedResults() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "admin@example.com");

        DiscoveredCertDto dto = DiscoveredCertDto.builder()
                .id(1L)
                .organizationId(ORG_ID)
                .targetType("AWS_ACM")
                .resourceId("arn:aws:acm:us-east-1:123:certificate/abc")
                .domain("test.example.net")
                .keyAlgorithm("RSA-2048")
                .signatureAlgorithm("SHA256WITHRSA")
                .certStatus("ISSUED")
                .keyUsage("DIGITAL_SIGNATURE,KEY_ENCIPHERMENT")
                .extendedKeyUsage("TLS_WEB_SERVER_AUTHENTICATION")
                .certType("IMPORTED")
                .managed(false)
                .discoveredAt(OffsetDateTime.parse("2026-05-05T21:30:00Z"))
                .build();

        Page<DiscoveredCertDto> page = new PageImpl<>(List.of(dto));
        when(discoveryService.listDiscoveredCerts(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(page);

        ResponseEntity<Page<DiscoveredCertDto>> response =
                controller.listDiscoveredCerts(null, null, null, null, null, null, null, 0, 20);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getContent()).hasSize(1);
        assertThat(response.getBody().getContent().get(0).getDomain()).isEqualTo("test.example.net");
        assertThat(response.getBody().getContent().get(0).getManaged()).isFalse();
        assertThat(response.getBody().getContent().get(0).getKeyUsage())
                .isEqualTo("DIGITAL_SIGNATURE,KEY_ENCIPHERMENT");
    }

    @Test
    void listDiscoveredCerts_withManagedFilter_passesFlagToService() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "admin@example.com");
        when(discoveryService.listDiscoveredCerts(eq(ORG_ID), eq(true), isNull(), isNull(), isNull(), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(Page.empty());

        controller.listDiscoveredCerts(null, true, null, null, null, null, null, 0, 20);

        verify(discoveryService).listDiscoveredCerts(eq(ORG_ID), eq(true), isNull(), isNull(), isNull(), isNull(), isNull(), any(Pageable.class));
    }

    @Test
    void listDiscoveredCerts_withDomainFilter_passesDomainToService() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "admin@example.com");
        when(discoveryService.listDiscoveredCerts(eq(ORG_ID), isNull(), eq("example.net"), isNull(), isNull(), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(Page.empty());

        controller.listDiscoveredCerts(null, null, "example.net", null, null, null, null, 0, 20);

        verify(discoveryService).listDiscoveredCerts(eq(ORG_ID), isNull(), eq("example.net"), isNull(), isNull(), isNull(), isNull(), any(Pageable.class));
    }

    @Test
    void listDiscoveredCerts_withKeyAlgorithmFilter_passesKeyAlgorithmToService() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "admin@example.com");
        when(discoveryService.listDiscoveredCerts(eq(ORG_ID), isNull(), isNull(), isNull(), eq("RSA_2048"), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(Page.empty());

        controller.listDiscoveredCerts(null, null, null, null, "RSA_2048", null, null, 0, 20);

        verify(discoveryService).listDiscoveredCerts(eq(ORG_ID), isNull(), isNull(), isNull(), eq("RSA_2048"), isNull(), isNull(), any(Pageable.class));
    }

    @Test
    void listDiscoveredCerts_withExpiresWithinDaysFilter_passesValueToService() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "admin@example.com");
        when(discoveryService.listDiscoveredCerts(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(), isNull(), eq(30), any(Pageable.class)))
                .thenReturn(Page.empty());

        controller.listDiscoveredCerts(null, null, null, null, null, null, 30, 0, 20);

        verify(discoveryService).listDiscoveredCerts(eq(ORG_ID), isNull(), isNull(), isNull(), isNull(), isNull(), eq(30), any(Pageable.class));
    }

    @Test
    void getDiscoveredCertificate_resolvesOrganizationAndReturnsDetails() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "admin@example.com");
        DiscoveredCertDetailDto details = DiscoveredCertDetailDto.builder()
                .id(7L)
                .organizationId(ORG_ID)
                .targetType("KUBERNETES_SECRETS")
                .resourceId("k8s://prod/frontend/secrets/api-tls")
                .build();
        when(discoveryService.getDiscoveredCertificate(ORG_ID, 7L)).thenReturn(details);

        ResponseEntity<DiscoveredCertDetailDto> response =
                controller.getDiscoveredCertificate(7L, null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isEqualTo(details);
        verify(discoveryService).getDiscoveredCertificate(ORG_ID, 7L);
    }
}
