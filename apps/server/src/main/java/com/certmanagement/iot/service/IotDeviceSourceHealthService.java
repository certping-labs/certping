// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.service;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceSourceCategory;
import com.certmanagement.iot.enums.DeviceSourceEventType;
import com.certmanagement.iot.enums.DeviceSourceHealth;
import com.certmanagement.iot.enums.DeviceSourceProvider;
import com.certmanagement.iot.messaging.DeviceSourceHealthMessage;
import com.certmanagement.iot.config.IotDeviceProperties;
import com.certmanagement.iot.revocation.IotIntunePollStateService;
import com.certmanagement.iot.repository.IotDeviceSourceHealthStatusRepository;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.FeatureFlagService;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.core.JacksonException;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
public class IotDeviceSourceHealthService {
    private static final Pattern PROFILE_REF = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,99}");

    private final IotDeviceSourceRepository sourceRepository;
    private final IotDeviceSourceHealthStatusRepository healthRepository;
    private final IotDeviceSourceEventService eventService;
    private final OrganizationRepository organizationRepository;
    private final FeatureFlagService featureFlagService;
    private final DeviceSourceMetadataSanitizer metadataSanitizer;
    private final ObjectMapper objectMapper;
    private final IotDeviceProperties properties;
    private final IotIntunePollStateService intunePollStateService;
    private final Clock clock;

    @Transactional
    public void handle(DeviceSourceHealthMessage message) {
        handle(message, null);
    }

    /** @param agentTokenId the verified token of the agent that sent it; its commands go to that agent */
    @Transactional
    public void handle(DeviceSourceHealthMessage message, Long agentTokenId) {
        if (!featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, null)) {
            log.debug("Dropping IOT_DEVICE_SOURCE_HEALTH because IoT device management is disabled");
            return;
        }
        try {
            apply(message, agentTokenId);
        } catch (IllegalArgumentException exception) {
            log.warn("Dropping invalid IOT_DEVICE_SOURCE_HEALTH: {}", exception.getMessage());
        }
    }

    private void apply(DeviceSourceHealthMessage message, Long agentTokenId) {
        Long organizationId = positiveLong(message.getOrganizationId(), "organizationId");
        if (!organizationRepository.existsById(organizationId)) {
            log.warn("Dropping IOT_DEVICE_SOURCE_HEALTH for unknown organizationId={}", organizationId);
            return;
        }
        if (!featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, organizationId)) {
            log.debug("Dropping IOT_DEVICE_SOURCE_HEALTH because IoT device management is disabled for organizationId={}",
                    organizationId);
            return;
        }
        String profileRef = profileRef(message.getConnectionProfileRef());
        DeviceSourceProvider provider = enumValue(
                DeviceSourceProvider.class, message.getProvider(), "provider");
        if (!isProviderEnabled(provider, organizationId)) {
            log.debug("Dropping IOT_DEVICE_SOURCE_HEALTH because provider={} is disabled for organizationId={}",
                    provider, organizationId);
            return;
        }
        DeviceSourceCategory category = enumValue(
                DeviceSourceCategory.class, message.getSourceCategory(), "sourceCategory");
        DeviceSourceHealth status = enumValue(
                DeviceSourceHealth.class, message.getHealthStatus(), "healthStatus");
        OffsetDateTime checkStartedAt = timestamp(message.getCheckStartedAt(), "checkStartedAt");
        OffsetDateTime observedAt = timestamp(message.getObservedAt(), "observedAt");
        OffsetDateTime publishedAt = timestamp(message.getPublishedAt(), "publishedAt");
        long sequence = nonNegative(message.getAgentSequence(), "agentSequence");
        Long responseTimeMs = message.getResponseTimeMs() == null ? null
                : nonNegative(message.getResponseTimeMs(), "responseTimeMs");
        String healthXref = required(message.getHealthXref(), 100, "healthXref");
        String instanceXref = required(message.getAgentInstanceXref(), 100, "agentInstanceXref");
        OffsetDateTime receivedAt = OffsetDateTime.now(clock);
        validateTimestamps(checkStartedAt, observedAt, publishedAt, receivedAt);

        IotDeviceSource source = upsertSource(
                message, organizationId, profileRef, provider, category, observedAt, receivedAt, agentTokenId);
        Map<String, Object> healthMetadata = metadataSanitizer.health(message.getHealthMetadata());

        eventService.record(source, DeviceSourceEventType.HEALTH_REPORTED, status.name(),
                Map.of("healthXref", healthXref, "providerStatus",
                        Optional.ofNullable(message.getProviderStatus()).orElse("")),
                observedAt, message.getCorrelationId(), healthXref);

        int applied = healthRepository.upsertIfNewer(
                source.getId(), healthXref, status.name(),
                truncate(message.getProviderStatus(), 100), truncate(message.getStatusMessage(), 1000),
                serialize(healthMetadata), instanceXref, sequence, checkStartedAt, observedAt,
                publishedAt, receivedAt, responseTimeMs);
        if (applied == 0) {
            log.info("Stored stale health as event without replacing snapshot: source={} health={}",
                    source.getSourceXref(), healthXref);
        }
    }

    private boolean isProviderEnabled(DeviceSourceProvider provider, Long organizationId) {
        return provider != DeviceSourceProvider.INTUNE
                || featureFlagService.isEnabled(FeatureFlags.IOT_PROVIDER_INTUNE, organizationId);
    }

    private IotDeviceSource upsertSource(DeviceSourceHealthMessage message,
                                         Long organizationId,
                                         String profileRef,
                                         DeviceSourceProvider provider,
                                         DeviceSourceCategory category,
                                         OffsetDateTime advertisedAt,
                                         OffsetDateTime receivedAt,
                                         Long agentTokenId) {
        boolean wasKnown = sourceRepository
                .findByOrganizationIdAndConnectionProfileRef(organizationId, profileRef)
                .isPresent();
        sourceRepository.upsertAdvertisement(
                xref("src_"), organizationId, provider.name(), category.name(), profileRef,
                required(message.getDisplayName(), 200, "displayName"),
                truncate(message.getDescription(), 500),
                serialize(metadataSanitizer.configuration(message.getConfigurationMetadata())),
                advertisedAt, receivedAt, agentTokenId);
        IotDeviceSource source = sourceRepository
                .findByOrganizationIdAndConnectionProfileRef(organizationId, profileRef)
                .orElseThrow(() -> new IllegalStateException("Device source advertisement was not persisted"));
        if (source.getProvider() != provider) {
            throw new IllegalArgumentException(
                    "provider cannot change for connectionProfileRef=" + profileRef);
        }
        if (!wasKnown) {
            eventService.record(source, DeviceSourceEventType.SOURCE_ADVERTISED, "ACTIVE",
                    Map.of("provider", provider.name(), "connectionProfileRef", profileRef),
                    advertisedAt, message.getCorrelationId(), "source-advertised");
        }
        intunePollStateService.ensureFor(source);
        return source;
    }

    private String serialize(Map<String, Object> value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JacksonException exception) {
            throw new IllegalArgumentException("metadata is not valid JSON", exception);
        }
    }

    private static String profileRef(String value) {
        String profileRef = required(value, 100, "connectionProfileRef");
        if (!PROFILE_REF.matcher(profileRef).matches()) {
            throw new IllegalArgumentException("connectionProfileRef contains unsupported characters");
        }
        return profileRef;
    }

    private static String required(String value, int maxLength, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        String trimmed = value.trim();
        if (trimmed.length() > maxLength) {
            throw new IllegalArgumentException(field + " exceeds " + maxLength + " characters");
        }
        return trimmed;
    }

    private static String truncate(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.length() <= maxLength ? trimmed : trimmed.substring(0, maxLength);
    }

    private static Long positiveLong(String value, String field) {
        try {
            long parsed = Long.parseLong(required(value, 30, field));
            if (parsed <= 0) {
                throw new NumberFormatException();
            }
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(field + " must be a positive integer");
        }
    }

    private static long nonNegative(Long value, String field) {
        if (value == null || value < 0) {
            throw new IllegalArgumentException(field + " must be zero or greater");
        }
        return value;
    }

    private static OffsetDateTime timestamp(String value, String field) {
        try {
            return OffsetDateTime.parse(required(value, 50, field));
        } catch (RuntimeException exception) {
            throw new IllegalArgumentException(field + " must be an ISO-8601 timestamp");
        }
    }

    private void validateTimestamps(OffsetDateTime checkStartedAt,
                                    OffsetDateTime observedAt,
                                    OffsetDateTime publishedAt,
                                    OffsetDateTime receivedAt) {
        if (checkStartedAt.isAfter(observedAt) || observedAt.isAfter(publishedAt)) {
            throw new IllegalArgumentException(
                    "health timestamps must satisfy checkStartedAt <= observedAt <= publishedAt");
        }
        OffsetDateTime latestAllowed = receivedAt.plus(properties.getMaxAgentClockSkew());
        if (checkStartedAt.isAfter(latestAllowed)
                || observedAt.isAfter(latestAllowed)
                || publishedAt.isAfter(latestAllowed)) {
            throw new IllegalArgumentException("health timestamps exceed the allowed agent clock skew");
        }
    }

    private static <T extends Enum<T>> T enumValue(Class<T> type, String value, String field) {
        try {
            return Enum.valueOf(type, required(value, 50, field).toUpperCase());
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(field + " is unsupported");
        }
    }

    private static String xref(String prefix) {
        return prefix + UUID.randomUUID().toString().replace("-", "");
    }
}
