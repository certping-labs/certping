// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.cahealth;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

public interface IotCaHealthStatusRepository extends JpaRepository<IotCaHealthStatus, Long> {
    List<IotCaHealthStatus> findByOrganizationIdOrderByCaProviderAscConnectorIdAsc(Long organizationId);

    Optional<IotCaHealthStatus> findByOrganizationIdAndConnectorId(Long organizationId, String connectorId);

    @Modifying
    @NativeQuery("""
            INSERT INTO iot_ca_health_status (
                organization_id, connector_id, ca_provider, enabled, health_status,
                checked_at, responded_at, received_at, latency_ms, endpoint, auth_method,
                product_json, capabilities_json, profiles_json, issues_json, report_version, updated_at)
            VALUES (
                :organizationId, :connectorId, :caProvider, :enabled, :healthStatus,
                :checkedAt, :respondedAt, :receivedAt, :latencyMs, :endpoint, :authMethod,
                CAST(:productJson AS jsonb), CAST(:capabilitiesJson AS jsonb),
                CAST(:profilesJson AS jsonb), CAST(:issuesJson AS jsonb), :reportVersion, :receivedAt)
            ON CONFLICT (organization_id, connector_id) DO UPDATE SET
                ca_provider = EXCLUDED.ca_provider,
                enabled = EXCLUDED.enabled,
                health_status = EXCLUDED.health_status,
                checked_at = EXCLUDED.checked_at,
                responded_at = EXCLUDED.responded_at,
                received_at = EXCLUDED.received_at,
                latency_ms = EXCLUDED.latency_ms,
                endpoint = EXCLUDED.endpoint,
                auth_method = EXCLUDED.auth_method,
                product_json = EXCLUDED.product_json,
                capabilities_json = EXCLUDED.capabilities_json,
                profiles_json = EXCLUDED.profiles_json,
                issues_json = EXCLUDED.issues_json,
                report_version = EXCLUDED.report_version,
                updated_at = EXCLUDED.updated_at
            WHERE EXCLUDED.checked_at > iot_ca_health_status.checked_at
               OR (EXCLUDED.checked_at = iot_ca_health_status.checked_at
                   AND EXCLUDED.responded_at > iot_ca_health_status.responded_at)
            """)
    int upsertIfNewer(
            @Param("organizationId") Long organizationId,
            @Param("connectorId") String connectorId,
            @Param("caProvider") String caProvider,
            @Param("enabled") boolean enabled,
            @Param("healthStatus") String healthStatus,
            @Param("checkedAt") OffsetDateTime checkedAt,
            @Param("respondedAt") OffsetDateTime respondedAt,
            @Param("receivedAt") OffsetDateTime receivedAt,
            @Param("latencyMs") Long latencyMs,
            @Param("endpoint") String endpoint,
            @Param("authMethod") String authMethod,
            @Param("productJson") String productJson,
            @Param("capabilitiesJson") String capabilitiesJson,
            @Param("profilesJson") String profilesJson,
            @Param("issuesJson") String issuesJson,
            @Param("reportVersion") int reportVersion);
}
