// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.deployment.DeploymentQueryRequest;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.deployment.DeploymentQueryService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeploymentControllerTest {

    @Mock
    private DeploymentQueryService deploymentQueryService;

    @InjectMocks
    private DeploymentController deploymentController;

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void getDeployments_withUnsortedPageable_defaultsToUpdatedAtDesc() {
        GatewayRequestContext.set(101, "1", "req-1", "user@example.com");
        when(deploymentQueryService.query(any(), any(), any())).thenReturn(Map.of("mode", "list"));

        deploymentController.getDeployments(new DeploymentQueryRequest(), PageRequest.of(0, 20));

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(deploymentQueryService).query(any(), any(), pageableCaptor.capture());
        Sort.Order order = pageableCaptor.getValue().getSort().getOrderFor("updatedAt");
        assertThat(order).isNotNull();
        assertThat(order.getDirection()).isEqualTo(Sort.Direction.DESC);
    }

    @Test
    void getDeployments_withUserDomainCertIdFilter_forwardsToService() {
        GatewayRequestContext.set(101, "1", "req-1b", "user@example.com");
        when(deploymentQueryService.query(any(), any(), any())).thenReturn(Map.of("mode", "list"));
        Long userDomainCertId = 170L;
        DeploymentQueryRequest filter = new DeploymentQueryRequest();
        filter.setUserdomaincertificateid(userDomainCertId);

        deploymentController.getDeployments(filter, PageRequest.of(0, 20));

        ArgumentCaptor<DeploymentQueryRequest> filterCaptor = ArgumentCaptor.forClass(DeploymentQueryRequest.class);
        verify(deploymentQueryService).query(any(), filterCaptor.capture(), any());
        assertThat(filterCaptor.getValue().getUserDomainCertId()).isEqualTo(userDomainCertId);
    }

    @Test
    void getDeployments_withExplicitSort_preservesCallerSort() {
        GatewayRequestContext.set(101, "1", "req-2", "user@example.com");
        when(deploymentQueryService.query(any(), any(), any())).thenReturn(Map.of("mode", "list"));

        Pageable pageable = PageRequest.of(0, 20, Sort.by(Sort.Direction.ASC, "createdAt"));
        deploymentController.getDeployments(new DeploymentQueryRequest(), pageable);

        verify(deploymentQueryService).query(any(), any(), eq(pageable));
    }

    @Test
    void getUserDomainCertDeploymentSummary_usesDomainAscPaging() {
        GatewayRequestContext.set(101, "1", "req-3", "user@example.com");
        when(deploymentQueryService.listUserDomainCertDeploymentSummary(any(), eq("example"), eq(null), eq(false), any()))
                .thenReturn(Map.of("items", List.of(), "page", 0, "size", 20, "totalItems", 0L, "totalPages", 0));

        deploymentController.getUserDomainCertDeploymentSummary("example", null, false, 0, 20);

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(deploymentQueryService).listUserDomainCertDeploymentSummary(any(), eq("example"), eq(null), eq(false), pageableCaptor.capture());
        Sort.Order order = pageableCaptor.getValue().getSort().getOrderFor("domain");
        assertThat(order).isNotNull();
        assertThat(order.getDirection()).isEqualTo(Sort.Direction.ASC);
    }

    @Test
    void getUserDomainCertDeploymentSummary_withNoFilters_forwardsNullFilters() {
        GatewayRequestContext.set(101, "1", "req-3b", "user@example.com");
        when(deploymentQueryService.listUserDomainCertDeploymentSummary(any(), eq(null), eq(null), eq(false), any()))
                .thenReturn(Map.of("items", List.of(), "page", 0, "size", 20, "totalItems", 0L, "totalPages", 0));

        deploymentController.getUserDomainCertDeploymentSummary(null, null, false, 0, 20);

        verify(deploymentQueryService).listUserDomainCertDeploymentSummary(any(), eq(null), eq(null), eq(false), any());
    }

    @Test
    void getUserDomainCertDeploymentSummary_withUserDomainCertIdFilter_forwardsId() {
        GatewayRequestContext.set(101, "1", "req-3c", "user@example.com");
        Long userDomainCertId = 187L;
        when(deploymentQueryService.listUserDomainCertDeploymentSummary(any(), eq(null), eq(userDomainCertId), eq(false), any()))
                .thenReturn(Map.of("items", List.of(), "page", 0, "size", 20, "totalItems", 0L, "totalPages", 0));

        deploymentController.getUserDomainCertDeploymentSummary(null, userDomainCertId, false, 0, 20);

        verify(deploymentQueryService).listUserDomainCertDeploymentSummary(any(), eq(null), eq(userDomainCertId), eq(false), any());
    }

    @Test
    void getDeploymentCredentialConfig_forwardsParams() {
        GatewayRequestContext.set(101, "1", "req-4", "user@example.com");
        when(deploymentQueryService.getCredentialConfig(1L, "cert-1", "cred-1"))
                .thenReturn(Map.of("certXref", "cert-1", "deploymentCredentialXref", "cred-1"));

        deploymentController.getDeploymentCredentialConfig("cert-1", "cred-1");

        verify(deploymentQueryService).getCredentialConfig(1L, "cert-1", "cred-1");
    }
}
