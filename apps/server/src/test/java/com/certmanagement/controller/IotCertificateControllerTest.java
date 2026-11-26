// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.certificate.IotCertificateNudgeService;
import com.certmanagement.iot.certificate.IotCertificateQueryService;
import com.certmanagement.iot.certificate.DeviceSyncRequest;
import com.certmanagement.iot.certificate.DeviceSyncResponse;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.iot.revocation.IotCertificateRevocationService;
import com.certmanagement.iot.revocation.CreateIotRevocationRequest;
import com.certmanagement.iot.revocation.IotRevocationReason;
import com.certmanagement.iot.revocation.IotRevocationResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.reflect.Method;
import java.util.List;
import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class IotCertificateControllerTest {

    @Mock private IotCertificateQueryService certificateQueryService;
    @Mock private IotCertificateNudgeService certificateNudgeService;
    @Mock private IotCertificateRevocationService certificateRevocationService;

    @InjectMocks private IotCertificateController controller;

    @AfterEach
    void clear() {
        GatewayRequestContext.clear();
    }

    @Test
    void nudgePublishesForTheOrgAndReturns202() {
        GatewayRequestContext.set(101, "42", "req-nudge-1", "user@example.com");

        DeviceSyncRequest request = new DeviceSyncRequest(List.of("dev-1"));
        DeviceSyncResponse serviceResponse = new DeviceSyncResponse(1, 1, 0, List.of());
        org.mockito.Mockito.when(certificateNudgeService.requestDeviceSync(42L, false, request))
                .thenReturn(serviceResponse);

        ResponseEntity<DeviceSyncResponse> response = controller.nudge(false, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getBody()).isSameAs(serviceResponse);
        verify(certificateNudgeService).requestDeviceSync(42L, false, request);
    }

    @Test
    void controllerIsFeatureGatedByIotDeviceManagement() {
        FeatureGated gate = IotCertificateController.class.getAnnotation(FeatureGated.class);
        assertThat(gate).isNotNull();
        assertThat(gate.value()).isEqualTo(FeatureFlags.IOT_DEVICE_MANAGEMENT);
    }

    @Test
    void revokeUsesGatewayOrgAndUserAndReturns202() {
        GatewayRequestContext.set(101, "42", "req-revoke-1", "user@example.com");
        CreateIotRevocationRequest request = new CreateIotRevocationRequest(
                IotRevocationReason.KEY_COMPROMISE, "lost device");
        IotRevocationResponse serviceResponse = new IotRevocationResponse(
                "op-1", "crt-1", "PENDING", "KEY_COMPROMISE", "UI", 0,
                OffsetDateTime.parse("2026-09-01T00:00:00Z"), null, null, null);
        org.mockito.Mockito.when(certificateRevocationService.request(
                42L, "crt-1", "idem-1", 101L, request)).thenReturn(serviceResponse);

        ResponseEntity<IotRevocationResponse> response = controller.revoke(
                "crt-1", "idem-1", request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getBody()).isSameAs(serviceResponse);
        verify(certificateRevocationService).request(42L, "crt-1", "idem-1", 101L, request);
    }

    @Test
    void nudgeEndpointRequiresTheManageWritePermission() throws NoSuchMethodException {
        Method nudge = IotCertificateController.class.getMethod(
                "nudge", boolean.class, DeviceSyncRequest.class);
        PreAuthorize preAuthorize = nudge.getAnnotation(PreAuthorize.class);
        assertThat(preAuthorize).isNotNull();
        assertThat(preAuthorize.value()).contains("iot_device:manage");
    }
}
