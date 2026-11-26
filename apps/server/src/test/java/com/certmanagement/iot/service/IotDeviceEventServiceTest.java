// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.iot.certificate.IotCertificateEnrollment;
import com.certmanagement.iot.dto.response.DeviceEventDto;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceEvent;
import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.repository.IotDeviceEventRepository;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.time.OffsetDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IotDeviceEventServiceTest {

    private static final Long ORGANIZATION_ID = 1L;
    private static final Long DEVICE_ID = 10L;
    private final IotDeviceEventRepository repository = mock(IotDeviceEventRepository.class);
    private final IotDeviceEventService service =
            new IotDeviceEventService(repository, JsonMapper.builderWithJackson2Defaults().build());

    @Test
    void recordPersistsAStatusForOrdinaryDeviceEvents() {
        IotDevice device = IotDevice.builder()
                .id(DEVICE_ID)
                .organizationId(ORGANIZATION_ID)
                .build();
        when(repository.save(any(IotDeviceEvent.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        service.record(device, DeviceEventType.DEVICE_UPDATED, ActorSource.SYNC,
                null, null, "corr-1");

        var eventCaptor = forClass(IotDeviceEvent.class);
        verify(repository).save(eventCaptor.capture());
        assertThat(eventCaptor.getValue().getEventStatus()).isEqualTo("RECORDED");
    }

    @Test
    void listForDeviceNormalizesAnEventWithoutAStatus() {
        PageRequest pageable = PageRequest.of(0, 25);
        IotDeviceEvent event = event(null);
        when(repository.findByDeviceIdAndOrganizationIdOrderByOccurredAtDesc(
                DEVICE_ID, ORGANIZATION_ID, pageable))
                .thenReturn(new PageImpl<>(List.of(event)));

        DeviceEventDto result = service
                .listForDevice(DEVICE_ID, ORGANIZATION_ID, pageable)
                .getContent().getFirst();

        assertThat(result.eventType()).isEqualTo("DEVICE_UPDATED");
        assertThat(result.eventStatus()).isEqualTo("RECORDED");
        assertThat(result.actorSource()).isEqualTo("SYNC");
    }

    @Test
    void recordEnrollmentPersistsAStatusWhenTheCallerOmitsIt() {
        IotCertificateEnrollment enrollment = IotCertificateEnrollment.builder()
                .id(20L)
                .organizationId(ORGANIZATION_ID)
                .build();
        when(repository.save(any(IotDeviceEvent.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        service.recordEnrollment(enrollment, DeviceEventType.CERTIFICATE_REQUESTED,
                null, null, null, "corr-2", null,
                OffsetDateTime.parse("2026-08-27T22:17:02Z"));

        var eventCaptor = forClass(IotDeviceEvent.class);
        verify(repository).save(eventCaptor.capture());
        assertThat(eventCaptor.getValue().getEventStatus()).isEqualTo("RECORDED");
    }

    @Test
    void listForDevicePreservesAnExplicitEnrollmentStatus() {
        PageRequest pageable = PageRequest.of(0, 25);
        IotDeviceEvent event = event("ISSUED");
        when(repository.findByDeviceIdAndOrganizationIdOrderByOccurredAtDesc(
                DEVICE_ID, ORGANIZATION_ID, pageable))
                .thenReturn(new PageImpl<>(List.of(event)));

        DeviceEventDto result = service
                .listForDevice(DEVICE_ID, ORGANIZATION_ID, pageable)
                .getContent().getFirst();

        assertThat(result.eventStatus()).isEqualTo("ISSUED");
    }

    private static IotDeviceEvent event(String status) {
        return IotDeviceEvent.builder()
                .eventXref("evt_1")
                .organizationId(ORGANIZATION_ID)
                .deviceId(DEVICE_ID)
                .eventType(DeviceEventType.DEVICE_UPDATED)
                .eventStatus(status)
                .actorSource(ActorSource.SYNC)
                .occurredAt(OffsetDateTime.parse("2026-08-27T22:17:02Z"))
                .build();
    }
}
