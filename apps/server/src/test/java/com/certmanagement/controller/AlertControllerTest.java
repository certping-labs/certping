// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.alert.AlertResponse;
import com.certmanagement.dto.alert.UpdateAlertRequest;
import com.certmanagement.enums.AlertTypeEnum;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.AlertService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AlertControllerTest {

    @Mock private AlertService alertService;

    @InjectMocks private AlertController controller;

    @BeforeEach
    void setUp() {
        GatewayRequestContext.set(4, "10", "req", "u@example.com");
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void getAlerts_returnsOk() {
        AlertResponse resp = AlertResponse.builder().build();
        when(alertService.getAlerts(4, 10L, null)).thenReturn(resp);

        ResponseEntity<AlertResponse> response = controller.getAlerts(null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isSameAs(resp);
    }

    @Test
    void getAlerts_withTypeFilter() {
        AlertResponse resp = AlertResponse.builder().build();
        when(alertService.getAlerts(4, 10L, AlertTypeEnum.CERTIFICATE_FAILURE)).thenReturn(resp);

        ResponseEntity<AlertResponse> response = controller.getAlerts(AlertTypeEnum.CERTIFICATE_FAILURE);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(alertService).getAlerts(4, 10L, AlertTypeEnum.CERTIFICATE_FAILURE);
    }

    @Test
    void updateAlert_marksReadAndReturnsBody() {
        UpdateAlertRequest req = new UpdateAlertRequest();
        req.setUnread(false);

        ResponseEntity<Map<String, Object>> response = controller.updateAlert(7L, req);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("success", true);
        assertThat(response.getBody()).containsEntry("alertId", 7L);
        verify(alertService).updateAlert(7L, false, 4, 10L);
    }
}
