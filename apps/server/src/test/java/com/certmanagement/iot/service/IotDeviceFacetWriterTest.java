// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.iot.adapter.PlatformAdapter;
import com.certmanagement.iot.dto.request.DeviceIdentityPayload;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceEndpointPosture;
import com.certmanagement.iot.enums.ComplianceState;
import com.certmanagement.iot.enums.DeviceFacet;
import com.certmanagement.iot.validation.DeviceFieldNormalizer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotDeviceFacetWriterTest {
    @Mock private EntityManager entityManager;
    @Mock private PlatformAdapter adapter;

    @Test
    void updatesThePreloadedPostureWithoutAnotherRead() {
        IotDevice device = IotDevice.builder().id(10L).build();
        IotDeviceEndpointPosture posture = IotDeviceEndpointPosture.builder()
                .deviceId(10L).complianceState(ComplianceState.NON_COMPLIANT).build();
        DeviceIdentityPayload payload = payload();
        when(adapter.facets()).thenReturn(Set.of(DeviceFacet.ENDPOINT_POSTURE));
        when(adapter.mapCompliance("compliant")).thenReturn(ComplianceState.COMPLIANT);

        new IotDeviceFacetWriter(
                entityManager, new DeviceFieldNormalizer(), JsonMapper.builderWithJackson2Defaults().build())
                .write(device, adapter, payload, posture, null);

        assertThat(posture.getComplianceState()).isEqualTo(ComplianceState.COMPLIANT);
        assertThat(posture.getOperatingSystem()).isEqualTo("macOS");
        verifyNoInteractions(entityManager);
    }

    private static DeviceIdentityPayload payload() {
        return new DeviceIdentityPayload(
                "device-1", null, null, null, "device", null, "macOS", "15.6",
                "Apple", "Mac", null, null, null, null, null, "COMPANY",
                "compliant", null, "mdm", null, null, null,
                true, false, null, null, null, null, Map.of());
    }
}
