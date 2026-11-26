// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.config.IotDeviceSyncProperties;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.repository.IotDeviceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotDeviceSyncSelectionServiceTest {

    @Mock private IotDeviceRepository deviceRepository;
    private IotDeviceSyncProperties properties;
    private IotDeviceSyncSelectionService service;

    @BeforeEach
    void setUp() {
        properties = new IotDeviceSyncProperties();
        service = new IotDeviceSyncSelectionService(deviceRepository, properties);
    }

    @Test
    void oneAndManyUseTheSameDeviceXrefListAndReportMissingDevices() {
        IotDevice found = IotDevice.builder().id(1L).deviceXref("dev-found").build();
        when(deviceRepository.findAllByOrganizationIdAndDeviceXrefInAndIsDeletedFalse(
                42L, List.of("dev-found", "dev-missing"))).thenReturn(List.of(found));

        IotDeviceSyncSelectionService.Selection selection = service.select(
                42L, false, new DeviceSyncRequest(List.of("dev-found", "dev-missing")));

        assertThat(selection.selectedCount()).isEqualTo(2);
        assertThat(selection.devices()).containsExactly(found);
        assertThat(selection.initialResults()).singleElement().satisfies(result -> {
            assertThat(result.deviceXref()).isEqualTo("dev-missing");
            assertThat(result.reason()).isEqualTo("DEVICE_NOT_FOUND");
        });
    }

    @Test
    void allSelectsEveryOrganizationDeviceAndRejectsAnAmbiguousBody() {
        IotDevice device = IotDevice.builder().id(1L).deviceXref("dev-1").build();
        when(deviceRepository.findAllByOrganizationIdAndIsDeletedFalseOrderById(
                42L, PageRequest.of(0, 5_001)))
                .thenReturn(List.of(device));

        assertThat(service.select(42L, true, null).devices()).containsExactly(device);
        assertThatThrownBy(() -> service.select(
                42L, true, new DeviceSyncRequest(List.of("dev-1"))))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        exception -> assertThat(exception.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST));
    }

    @Test
    void allIsRejectedByTheSingleBoundedFetch() {
        properties.setMaxAllDevices(1);
        IotDevice first = IotDevice.builder().id(1L).deviceXref("dev-1").build();
        IotDevice overflow = IotDevice.builder().id(2L).deviceXref("dev-2").build();
        when(deviceRepository.findAllByOrganizationIdAndIsDeletedFalseOrderById(
                42L, PageRequest.of(0, 2))).thenReturn(List.of(first, overflow));

        assertThatThrownBy(() -> service.select(42L, true, null))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        exception -> assertThat(exception.getStatusCode())
                                .isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE));
    }

    @Test
    void explicitSelectionIsRequiredAndBounded() {
        assertThatThrownBy(() -> service.select(42L, false, null))
                .isInstanceOf(ResponseStatusException.class);

        properties.setMaxExplicitDevices(1);
        assertThatThrownBy(() -> service.select(
                42L, false, new DeviceSyncRequest(List.of("dev-1", "dev-2"))))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        exception -> assertThat(exception.getStatusCode())
                                .isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE));
    }
}
