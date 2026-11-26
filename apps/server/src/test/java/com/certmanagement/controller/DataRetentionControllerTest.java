// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.GlobalSettingsService;
import com.certmanagement.service.SoftDeletePurgeService;
import org.junit.jupiter.api.AfterEach;
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
class DataRetentionControllerTest {

    @Mock private GlobalSettingsService globalSettingsService;
    @Mock private SoftDeletePurgeService purgeService;

    @InjectMocks private DataRetentionController controller;

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void purgeOrganization_returnsOkWithDetails() {
        when(globalSettingsService.resolveRetentionDays(10L)).thenReturn(30);
        SoftDeletePurgeService.PurgeResult result =
                new SoftDeletePurgeService.PurgeResult(1, 2, 3, 4, 5, 6, 9, 10);
        when(purgeService.purgeOrganization(10L, 30)).thenReturn(result);

        ResponseEntity<Map<String, Object>> response = controller.purgeOrganization(10L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("organizationId", 10L);
        assertThat(response.getBody()).containsEntry("retentionDays", 30);
        assertThat(response.getBody()).containsKey("totalHardDeleted");
    }

    @Test
    void getOrgRetention_returnsOverrideAndEffective() {
        when(globalSettingsService.getOrgRetentionDaysOverride(10L)).thenReturn(15);
        when(globalSettingsService.resolveRetentionDays(10L)).thenReturn(15);
        when(globalSettingsService.getGlobalRetentionDays()).thenReturn(90);

        ResponseEntity<Map<String, Object>> response = controller.getOrgRetention(10L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("overrideDays", 15);
        assertThat(response.getBody()).containsEntry("globalDays", 90);
    }

    @Test
    void getOrgRetention_nullOverrideRendersNullString() {
        when(globalSettingsService.getOrgRetentionDaysOverride(10L)).thenReturn(null);
        when(globalSettingsService.resolveRetentionDays(10L)).thenReturn(90);
        when(globalSettingsService.getGlobalRetentionDays()).thenReturn(90);

        ResponseEntity<Map<String, Object>> response = controller.getOrgRetention(10L);

        assertThat(response.getBody()).containsEntry("overrideDays", "null");
    }

    @Test
    void setOrgRetention_setsValidDays() {
        when(globalSettingsService.resolveRetentionDays(10L)).thenReturn(45);

        ResponseEntity<Map<String, Object>> response =
                controller.setOrgRetention(10L, Map.of("days", "45"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("overrideDays", 45);
        verify(globalSettingsService).setOrgRetentionDaysOverride(10L, 45);
    }

    @Test
    void setOrgRetention_clearsWhenNull() {
        when(globalSettingsService.resolveRetentionDays(10L)).thenReturn(90);
        java.util.Map<String, Object> body = new java.util.HashMap<>();
        body.put("days", null);

        ResponseEntity<Map<String, Object>> response = controller.setOrgRetention(10L, body);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("overrideDays", "null");
        verify(globalSettingsService).setOrgRetentionDaysOverride(10L, null);
    }

    @Test
    void setOrgRetention_badNumberReturns400() {
        ResponseEntity<Map<String, Object>> response =
                controller.setOrgRetention(10L, Map.of("days", "abc"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).containsKey("error");
    }

    @Test
    void getGlobalRetention_returnsOk() {
        when(globalSettingsService.getGlobalRetentionDays()).thenReturn(90);

        ResponseEntity<Map<String, Object>> response = controller.getGlobalRetention();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("globalRetentionDays", 90);
    }

    @Test
    void setGlobalRetention_setsValid() {
        GatewayRequestContext.set(7, "10", "req", "a@b.com");

        ResponseEntity<Map<String, Object>> response =
                controller.setGlobalRetention(Map.of("days", "120"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("globalRetentionDays", 120);
        verify(globalSettingsService).setGlobalRetentionDays(120, 7L);
    }

    @Test
    void setGlobalRetention_missingDaysReturns400() {
        java.util.Map<String, Object> body = new java.util.HashMap<>();
        body.put("days", null);

        ResponseEntity<Map<String, Object>> response = controller.setGlobalRetention(body);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).containsKey("error");
    }

    @Test
    void setGlobalRetention_badNumberReturns400() {
        ResponseEntity<Map<String, Object>> response =
                controller.setGlobalRetention(Map.of("days", "xyz"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).containsKey("error");
    }

    @Test
    void setGlobalRetention_nullUserIdWhenNoContext() {
        ResponseEntity<Map<String, Object>> response =
                controller.setGlobalRetention(Map.of("days", "60"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(globalSettingsService).setGlobalRetentionDays(60, null);
    }
}
