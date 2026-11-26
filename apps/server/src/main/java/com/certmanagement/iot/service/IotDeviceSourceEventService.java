// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.iot.dto.response.DeviceSourceEventDto;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceSourceEventType;
import com.certmanagement.iot.repository.IotDeviceSourceEventRepository;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import tools.jackson.core.JacksonException;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class IotDeviceSourceEventService {
    private final IotDeviceSourceEventRepository repository;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    public void record(IotDeviceSource source,
                       DeviceSourceEventType type,
                       String status,
                       Map<String, ?> detail,
                       OffsetDateTime occurredAt,
                       String correlationId,
                       String dedupeKey) {
        OffsetDateTime receivedAt = OffsetDateTime.now(clock);
        repository.insertIfAbsent(
                xref("event_"), source.getOrganizationId(), source.getId(), type.name(),
                truncate(status, 50), serialize(detail),
                occurredAt == null ? receivedAt : occurredAt, receivedAt,
                truncate(correlationId, 100), truncate(dedupeKey, 200));
    }

    public Page<DeviceSourceEventDto> list(IotDeviceSource source, Pageable pageable) {
        return list(source, null, pageable);
    }

    public Page<DeviceSourceEventDto> list(
            IotDeviceSource source, String correlationId, Pageable pageable) {
        Page<com.certmanagement.iot.entity.IotDeviceSourceEvent> events =
                correlationId == null || correlationId.isBlank()
                        ? repository.findByDeviceSourceIdAndOrganizationIdOrderByOccurredAtDesc(
                                source.getId(), source.getOrganizationId(), pageable)
                        : repository
                                .findByDeviceSourceIdAndOrganizationIdAndCorrelationIdOrderByOccurredAtDesc(
                                        source.getId(), source.getOrganizationId(), correlationId, pageable);
        return events
                .map(event -> new DeviceSourceEventDto(
                        event.getEventXref(), event.getEventType().name(), event.getEventStatus(),
                        deserialize(event.getDetailJson()), event.getOccurredAt(), event.getReceivedAt(),
                        event.getCorrelationId()));
    }

    public Page<DeviceSourceEventDto> listForProfile(
            IotDeviceSource source, String profileXref, Pageable pageable) {
        return repository.findProfileEvents(
                        source.getId(), source.getOrganizationId(), profileXref, pageable)
                .map(event -> new DeviceSourceEventDto(
                        event.getEventXref(), event.getEventType().name(), event.getEventStatus(),
                        deserialize(event.getDetailJson()), event.getOccurredAt(), event.getReceivedAt(),
                        event.getCorrelationId()));
    }

    private Map<String, Object> deserialize(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (JacksonException exception) {
            throw new IllegalStateException("Stored source event detail is invalid JSON", exception);
        }
    }

    private String serialize(Map<String, ?> detail) {
        if (detail == null || detail.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(detail);
        } catch (JacksonException exception) {
            throw new IllegalArgumentException("Source event detail is not valid JSON", exception);
        }
    }

    private static String xref(String prefix) {
        return prefix + UUID.randomUUID().toString().replace("-", "");
    }

    private static String truncate(String value, int maxLength) {
        return value == null || value.length() <= maxLength ? value : value.substring(0, maxLength);
    }
}
