// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.constants.Paths;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.ProxyService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NotificationControllerTest {

    @Mock private ProxyService proxyService;

    @InjectMocks private NotificationController controller;

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void getNotifications_passesAllParamsAndOrg() {
        GatewayRequestContext.set(1, "10", "req", "u@example.com");
        ResponseEntity<String> proxied = ResponseEntity.ok("[]");
        when(proxyService.get(eq(Paths.NOTIFICATIONS_BASE), org.mockito.ArgumentMatchers.anyMap()))
                .thenReturn(proxied);

        ResponseEntity<String> response = controller.getNotifications(2, 25, "FAILED", null);

        assertThat(response).isSameAs(proxied);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, String>> captor = ArgumentCaptor.forClass(Map.class);
        verify(proxyService).get(eq(Paths.NOTIFICATIONS_BASE), captor.capture());
        Map<String, String> params = captor.getValue();
        assertThat(params).containsEntry("page", "2");
        assertThat(params).containsEntry("size", "25");
        assertThat(params).containsEntry("status", "FAILED");
        assertThat(params).containsEntry("organizationId", "10");
    }

    @Test
    void getNotifications_omitsBlankOrgAndNullParams() {
        GatewayRequestContext.set(1, "  ", "req", "u@example.com");
        ResponseEntity<String> proxied = ResponseEntity.ok("[]");
        when(proxyService.get(eq(Paths.NOTIFICATIONS_BASE), org.mockito.ArgumentMatchers.anyMap()))
                .thenReturn(proxied);

        controller.getNotifications(null, null, null, null);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, String>> captor = ArgumentCaptor.forClass(Map.class);
        verify(proxyService).get(eq(Paths.NOTIFICATIONS_BASE), captor.capture());
        Map<String, String> params = captor.getValue();
        assertThat(params).doesNotContainKey("page");
        assertThat(params).doesNotContainKey("organizationId");
    }

    @Test
    void getNotifications_refusesAnUnknownStatus() {
        GatewayRequestContext.set(1, "10", "req", "u@example.com");

        ResponseEntity<String> response = controller.getNotifications(null, null, "SENT&organizationId=7", null);

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        verifyNoInteractions(proxyService);
    }
}
