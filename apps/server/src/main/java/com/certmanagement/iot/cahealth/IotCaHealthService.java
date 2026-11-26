// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.cahealth;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.iot.config.IotDeviceProperties;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.FeatureFlagService;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.core.JacksonException;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class IotCaHealthService {
    private static final int MAX_CONNECTORS = 20;
    private static final int MAX_JSON_LENGTH = 64 * 1024;
    private static final java.time.Duration MAX_FUTURE_CLOCK_SKEW = java.time.Duration.ofMinutes(5);
    private static final Set<String> STATUSES = Set.of(
            "HEALTHY", "DEGRADED", "UNCONFIGURED", "UNREACHABLE", "UNAUTHORIZED", "ERROR", "UNKNOWN");

    private final IotCaHealthStatusRepository repository;
    private final OrganizationRepository organizationRepository;
    private final FeatureFlagService featureFlagService;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    private final IotDeviceProperties properties;

    @Transactional
    public void handle(CaHealthReportMessage report) {
        if (!featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, null)) return;
        try {
            apply(report);
        } catch (IllegalArgumentException exception) {
            log.warn("Dropping invalid AGENT_CA_HEALTH_REPORT: {}", exception.getMessage());
        }
    }

    private void apply(CaHealthReportMessage report) {
        if (report == null) throw new IllegalArgumentException("report is required");
        Long organizationId = positiveLong(report.getOrganizationId(), "organizationId");
        if (!organizationRepository.existsById(organizationId)
                || !featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, organizationId)) {
            return;
        }
        int version = report.getReportVersion() == null ? 0 : report.getReportVersion();
        if (version != 1) throw new IllegalArgumentException("unsupported reportVersion=" + version);
        List<CaHealthReportMessage.Connector> connectors = report.getConnectors() == null
                ? List.of() : report.getConnectors();
        if (connectors.size() > MAX_CONNECTORS) throw new IllegalArgumentException("too many connectors");
        OffsetDateTime receivedAt = OffsetDateTime.now(clock);
        OffsetDateTime respondedAt = boundedTimestamp(
                report.getRespondedAt(), "respondedAt", receivedAt);
        List<ValidatedConnector> validated = connectors.stream()
                .map(connector -> validateConnector(connector, receivedAt))
                .toList();
        for (ValidatedConnector connector : validated) {
            applyConnector(organizationId, version, respondedAt, receivedAt, connector);
        }
    }

    private void applyConnector(Long organizationId, int version, OffsetDateTime respondedAt,
                                OffsetDateTime receivedAt, ValidatedConnector connector) {
        int updated = repository.upsertIfNewer(
                organizationId, connector.connectorId(), connector.caProvider(), connector.enabled(),
                connector.status(), connector.checkedAt(), respondedAt, receivedAt,
                connector.latencyMs(), connector.endpoint(), connector.authMethod(), connector.productJson(),
                connector.capabilitiesJson(), connector.profilesJson(), connector.issuesJson(), version);
        if (updated == 0) {
            log.debug("Ignored stale CA health snapshot connectorId={}", connector.connectorId());
        }
    }

    private ValidatedConnector validateConnector(
            CaHealthReportMessage.Connector connector, OffsetDateTime receivedAt) {
        if (connector == null) throw new IllegalArgumentException("connector is required");
        String status = required(connector.getStatus(), 30, "status").toUpperCase(Locale.ROOT);
        if (!STATUSES.contains(status)) throw new IllegalArgumentException("unsupported CA health status");
        Long latency = connector.getLatencyMs();
        if (latency != null && latency < 0) throw new IllegalArgumentException("latencyMs must be non-negative");
        return new ValidatedConnector(
                required(connector.getConnectorId(), 100, "connectorId"),
                required(connector.getCaProvider(), 50, "caProvider").toUpperCase(Locale.ROOT),
                Boolean.TRUE.equals(connector.getEnabled()), status,
                boundedTimestamp(connector.getCheckedAt(), "checkedAt", receivedAt),
                latency, truncate(connector.getEndpoint(), 1000), truncate(connector.getAuthMethod(), 80),
                json(connector.getProduct()), json(defaultList(connector.getCapabilities())),
                json(defaultList(connector.getProfiles())), json(defaultList(connector.getIssues())));
    }

    @Transactional(readOnly = true)
    public List<CaConnectorResponse> list(Long organizationId) {
        return repository.findByOrganizationIdOrderByCaProviderAscConnectorIdAsc(organizationId)
                .stream()
                .filter(row -> isCaProviderVisible(row.getCaProvider(), organizationId))
                .map(this::toResponse)
                .toList();
    }

    /**
     * @throws ResourceNotFoundException if no connector with this id exists for the org, or its
     *         CA provider's feature flag is disabled — a disabled provider must not be
     *         distinguishable from a nonexistent one.
     */
    @Transactional(readOnly = true)
    public CaConnectorResponse getByConnectorId(Long organizationId, String connectorId) {
        IotCaHealthStatus row = repository.findByOrganizationIdAndConnectorId(organizationId, connectorId)
                .filter(candidate -> isCaProviderVisible(candidate.getCaProvider(), organizationId))
                .orElseThrow(() -> new ResourceNotFoundException("CA connector not found: " + connectorId));
        return toResponse(row);
    }

    private boolean isCaProviderVisible(String caProvider, Long organizationId) {
        String flag = caProviderFeatureFlag(caProvider);
        return flag == null || featureFlagService.isEnabled(flag, organizationId);
    }

    private static String caProviderFeatureFlag(String caProvider) {
        return switch (caProvider) {
            case "EJBCA" -> FeatureFlags.CA_EJBCA;
            case "SMALLSTEP" -> FeatureFlags.CA_SMALLSTEP;
            default -> null;
        };
    }

    /**
     * Same freshness rule as device sources: the agent reports every connector on a fixed cadence, so a report
     * older than {@code certping.iot.health-stale-after} means the agent stopped (or was removed) and the
     * stored status no longer says anything.
     */
    private CaConnectorResponse toResponse(IotCaHealthStatus row) {
        OffsetDateTime staleAt = row.getReceivedAt().plus(properties.getHealthStaleAfter());
        boolean stale = !OffsetDateTime.now(clock).isBefore(staleAt);
        return new CaConnectorResponse(
                row.getConnectorId(), row.getCaProvider(), Boolean.TRUE.equals(row.getEnabled()),
                stale ? "STALE" : row.getHealthStatus(), row.getHealthStatus(), stale, staleAt,
                row.getCheckedAt(), row.getRespondedAt(), row.getReceivedAt(),
                row.getLatencyMs(), row.getEndpoint(), row.getAuthMethod(), tree(row.getProductJson()),
                strings(row.getCapabilitiesJson()), tree(row.getProfilesJson()), tree(row.getIssuesJson()),
                row.getReportVersion());
    }

    private String json(Object value) {
        if (value == null) return null;
        try {
            String json = objectMapper.writeValueAsString(value);
            if (json.length() > MAX_JSON_LENGTH) throw new IllegalArgumentException("CA health metadata is too large");
            return json;
        } catch (JacksonException exception) {
            throw new IllegalArgumentException("CA health metadata is not valid JSON", exception);
        }
    }

    private JsonNode tree(String json) {
        if (json == null || json.isBlank()) return objectMapper.nullNode();
        try { return objectMapper.readTree(json); }
        catch (JacksonException exception) { throw new IllegalStateException("Stored CA health JSON is invalid", exception); }
    }

    private List<String> strings(String json) {
        if (json == null || json.isBlank()) return List.of();
        try { return objectMapper.readValue(json, new TypeReference<>() {}); }
        catch (JacksonException exception) { throw new IllegalStateException("Stored capabilities JSON is invalid", exception); }
    }

    private static List<?> defaultList(List<?> values) { return values == null ? List.of() : values; }
    private static OffsetDateTime timestamp(String value, String field) {
        try { return OffsetDateTime.parse(required(value, 50, field)); }
        catch (RuntimeException exception) { throw new IllegalArgumentException(field + " must be ISO-8601"); }
    }
    private static OffsetDateTime boundedTimestamp(String value, String field, OffsetDateTime receivedAt) {
        OffsetDateTime parsed = timestamp(value, field);
        if (parsed.isAfter(receivedAt.plus(MAX_FUTURE_CLOCK_SKEW))) {
            throw new IllegalArgumentException(field + " is too far in the future");
        }
        return parsed;
    }
    private static Long positiveLong(String value, String field) {
        try { long parsed = Long.parseLong(required(value, 30, field)); if (parsed <= 0) throw new NumberFormatException(); return parsed; }
        catch (NumberFormatException exception) { throw new IllegalArgumentException(field + " must be positive"); }
    }
    private static String required(String value, int max, String field) {
        String normalized = value == null ? null : value.trim();
        if (normalized == null || normalized.isEmpty()) throw new IllegalArgumentException(field + " is required");
        if (normalized.length() > max) throw new IllegalArgumentException(field + " is too long");
        return normalized;
    }
    private static String truncate(String value, int max) {
        if (value == null) return null;
        String normalized = value.trim();
        return normalized.length() <= max ? normalized : normalized.substring(0, max);
    }

    private record ValidatedConnector(
            String connectorId,
            String caProvider,
            boolean enabled,
            String status,
            OffsetDateTime checkedAt,
            Long latencyMs,
            String endpoint,
            String authMethod,
            String productJson,
            String capabilitiesJson,
            String profilesJson,
            String issuesJson) {
    }
}
