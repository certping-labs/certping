// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.iot.dto.response.DeviceEventDto;
import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceEvent;
import com.certmanagement.iot.certificate.IotCertificateEnrollment;
import com.certmanagement.iot.certificate.IotDeviceCertificate;
import com.certmanagement.iot.enums.ActorSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.repository.IotDeviceEventRepository;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.core.JacksonException;

import java.util.Map;
import java.util.UUID;
import java.time.OffsetDateTime;

/**
 * Writes and reads the device audit trail.
 *
 * <p>Callers are responsible for only invoking {@link #record} when something actually
 * changed — see the change detection in {@link IotDeviceUpsertService}.
 * This service does not second-guess that, so a caller that records unconditionally will
 * fill the table with noise.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IotDeviceEventService {

    private final IotDeviceEventRepository eventRepository;
    private final ObjectMapper objectMapper;

    @Transactional
    public void record(IotDevice device,
                       DeviceEventType eventType,
                       ActorSource actorSource,
                       Long actorUserId,
                       Map<String, ?> detail,
                       String correlationId) {

        eventRepository.save(IotDeviceEvent.builder()
                .eventXref("evt_" + UUID.randomUUID())
                .organizationId(device.getOrganizationId())
                .deviceId(device.getId())
                .eventType(eventType)
                .eventStatus("RECORDED")
                .actorSource(actorSource)
                .actorUserId(actorUserId)
                .detailJson(serialize(detail))
                .correlationId(correlationId)
                .build());
    }

    @Transactional(readOnly = true)
    public Page<DeviceEventDto> listForDevice(Long deviceId, Long organizationId, Pageable pageable) {
        return eventRepository
                .findByDeviceIdAndOrganizationIdOrderByOccurredAtDesc(deviceId, organizationId, pageable)
                .map(this::toDto);
    }

    @Transactional(readOnly = true)
    public Page<DeviceEventDto> listForOrganization(Long organizationId, Pageable pageable) {
        return eventRepository.findByOrganizationIdOrderByOccurredAtDesc(organizationId, pageable)
                .map(this::toDto);
    }

    /** Records one idempotent enrollment transition in the shared device audit stream. */
    @Transactional
    public void recordEnrollment(IotCertificateEnrollment enrollment,
                                 DeviceEventType eventType,
                                 String eventStatus,
                                 String eventMessage,
                                 Map<String, ?> detail,
                                 String correlationId,
                                 String dedupeKey,
                                 OffsetDateTime occurredAt) {
        if (dedupeKey != null
                && eventRepository.existsByOrganizationIdAndDedupeKey(
                        enrollment.getOrganizationId(), dedupeKey)) {
            return;
        }
        eventRepository.save(IotDeviceEvent.builder()
                .eventXref("evt_" + UUID.randomUUID())
                .organizationId(enrollment.getOrganizationId())
                .deviceId(enrollment.getDeviceId())
                .certificateEnrollmentId(enrollment.getId())
                .eventType(eventType)
                .eventStatus(responseStatus(eventStatus))
                .eventMessage(truncate(eventMessage, 1000))
                .actorSource(ActorSource.AGENT)
                .detailJson(serialize(detail))
                .occurredAt(occurredAt)
                .correlationId(truncate(correlationId, 100))
                .dedupeKey(truncate(dedupeKey, 255))
                .build());
    }

    /** Records a certificate lifecycle transition without adding another event-table foreign key. */
    @Transactional
    public void recordCertificate(IotDeviceCertificate certificate,
                                  DeviceEventType eventType,
                                  String eventStatus,
                                  String eventMessage,
                                  ActorSource actorSource,
                                  Long actorUserId,
                                  Map<String, ?> detail,
                                  String correlationId,
                                  String dedupeKey,
                                  OffsetDateTime occurredAt) {
        if (dedupeKey != null && eventRepository.existsByOrganizationIdAndDedupeKey(
                certificate.getOrganizationId(), dedupeKey)) {
            return;
        }
        insertCertificateEvent(certificate, eventType, eventStatus, eventMessage,
                actorSource, actorUserId, detail, correlationId, dedupeKey, occurredAt);
    }

    /** Use when the caller holds the workflow row lock that fences duplicate transitions. */
    @Transactional
    public void recordCertificateUnderWorkflowLock(
                                  IotDeviceCertificate certificate,
                                  DeviceEventType eventType,
                                  String eventStatus,
                                  String eventMessage,
                                  ActorSource actorSource,
                                  Long actorUserId,
                                  Map<String, ?> detail,
                                  String correlationId,
                                  String dedupeKey,
                                  OffsetDateTime occurredAt) {
        insertCertificateEvent(certificate, eventType, eventStatus, eventMessage,
                actorSource, actorUserId, detail, correlationId, dedupeKey, occurredAt);
    }

    private void insertCertificateEvent(IotDeviceCertificate certificate,
                                        DeviceEventType eventType,
                                        String eventStatus,
                                        String eventMessage,
                                        ActorSource actorSource,
                                        Long actorUserId,
                                        Map<String, ?> detail,
                                        String correlationId,
                                        String dedupeKey,
                                        OffsetDateTime occurredAt) {
        eventRepository.save(IotDeviceEvent.builder()
                .eventXref("evt_" + UUID.randomUUID())
                .organizationId(certificate.getOrganizationId())
                .deviceId(certificate.getDeviceId())
                .certificateEnrollmentId(certificate.getEnrollmentId())
                .eventType(eventType)
                .eventStatus(responseStatus(eventStatus))
                .eventMessage(truncate(eventMessage, 1000))
                .actorSource(actorSource)
                .actorUserId(actorUserId)
                .detailJson(serialize(detail))
                .occurredAt(occurredAt)
                .correlationId(truncate(correlationId, 100))
                .dedupeKey(truncate(dedupeKey, 255))
                .build());
    }

    @Transactional(readOnly = true)
    public Page<DeviceEventDto> listForEnrollment(
            Long enrollmentId, Long organizationId, Pageable pageable) {
        return eventRepository
                .findByCertificateEnrollmentIdAndOrganizationIdOrderByOccurredAtDesc(
                        enrollmentId, organizationId, pageable)
                .map(this::toDto);
    }

    private DeviceEventDto toDto(IotDeviceEvent event) {
        return new DeviceEventDto(
                event.getEventXref(),
                event.getEventType() == null ? null : event.getEventType().name(),
                responseStatus(event.getEventStatus()),
                event.getEventMessage(),
                event.getActorSource() == null ? null : event.getActorSource().name(),
                event.getActorUserId(),
                deserialize(event.getDetailJson()),
                event.getOccurredAt(),
                event.getCorrelationId());
    }

    private static String responseStatus(String status) {
        return status == null || status.isBlank() ? "RECORDED" : status;
    }

    private static String truncate(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        return value.length() <= maxLength ? value : value.substring(0, maxLength);
    }

    private Map<String, Object> deserialize(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (JacksonException exception) {
            throw new IllegalStateException("Stored device event detail is invalid JSON", exception);
        }
    }

    private String serialize(Map<String, ?> detail) {
        if (detail == null || detail.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(detail);
        } catch (JacksonException ex) {
            log.warn("Could not serialise device event detail: {}", ex.getMessage());
            return null;
        }
    }
}
