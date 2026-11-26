// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.cahealth;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.iot.config.IotDeviceProperties;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.service.FeatureFlagService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotCaHealthServiceTest {
    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-08-26T12:00:00Z"), ZoneOffset.UTC);

    @Mock private IotCaHealthStatusRepository repository;
    @Mock private OrganizationRepository organizationRepository;
    @Mock private FeatureFlagService featureFlagService;

    @BeforeEach
    void enableFeature() {
        lenient().when(featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, null))
                .thenReturn(true);
        lenient().when(featureFlagService.isEnabled(FeatureFlags.IOT_DEVICE_MANAGEMENT, 42L))
                .thenReturn(true);
        lenient().when(organizationRepository.existsById(42L)).thenReturn(true);
    }

    @Test
    void storesOneLatestSnapshotPerConnector() {
        CaHealthReportMessage report = validReport();
        service().handle(report);

        verify(repository).upsertIfNewer(
                eq(42L), eq("ejbca-primary"), eq("EJBCA"), eq(true), eq("HEALTHY"),
                eq(java.time.OffsetDateTime.parse("2026-08-26T11:59:58Z")),
                eq(java.time.OffsetDateTime.parse("2026-08-26T11:59:59Z")),
                eq(java.time.OffsetDateTime.parse("2026-08-26T12:00:00Z")),
                eq(25L), eq("https://ejbca.internal"), eq("MTLS"),
                any(), any(), any(), any(), eq(1));
    }

    @Test
    void invalidConnectorDoesNotWriteAPartialSnapshot() {
        CaHealthReportMessage report = validReport();
        CaHealthReportMessage.Connector invalid = connector("smallstep-primary", "smallstep");
        invalid.setStatus("invented");
        report.setConnectors(List.of(report.getConnectors().getFirst(), invalid));

        service().handle(report);

        verify(repository, never()).upsertIfNewer(any(), any(), any(), anyBoolean(), any(),
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), anyInt());
    }

    @Test
    void futureDatedReportDoesNotReplaceCurrentHealth() {
        CaHealthReportMessage report = validReport();
        report.setRespondedAt("2026-08-26T12:05:01Z");

        service().handle(report);

        verify(repository, never()).upsertIfNewer(any(), any(), any(), anyBoolean(), any(),
                any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), anyInt());
    }

    @Test
    void listReturnsBothProvidersWhenBothFlagsEnabled() {
        lenient().when(featureFlagService.isEnabled(FeatureFlags.CA_EJBCA, 42L)).thenReturn(true);
        lenient().when(featureFlagService.isEnabled(FeatureFlags.CA_SMALLSTEP, 42L)).thenReturn(true);
        when(repository.findByOrganizationIdOrderByCaProviderAscConnectorIdAsc(42L))
                .thenReturn(List.of(connectorRow("ejbca-primary", "EJBCA"),
                        connectorRow("smallstep-primary", "SMALLSTEP")));

        List<CaConnectorResponse> connectors = service().list(42L);

        assertThat(connectors).extracting(CaConnectorResponse::connectorId)
                .containsExactlyInAnyOrder("ejbca-primary", "smallstep-primary");
    }

    @Test
    void listHidesConnectorsWhoseCaProviderFlagIsDisabled() {
        lenient().when(featureFlagService.isEnabled(FeatureFlags.CA_EJBCA, 42L)).thenReturn(true);
        lenient().when(featureFlagService.isEnabled(FeatureFlags.CA_SMALLSTEP, 42L)).thenReturn(false);
        when(repository.findByOrganizationIdOrderByCaProviderAscConnectorIdAsc(42L))
                .thenReturn(List.of(connectorRow("ejbca-primary", "EJBCA"),
                        connectorRow("smallstep-primary", "SMALLSTEP")));

        List<CaConnectorResponse> connectors = service().list(42L);

        assertThat(connectors).extracting(CaConnectorResponse::connectorId)
                .containsExactly("ejbca-primary");
    }

    @Test
    void getByConnectorIdReturnsTheConnectorWhenVisible() {
        lenient().when(featureFlagService.isEnabled(FeatureFlags.CA_EJBCA, 42L)).thenReturn(true);
        when(repository.findByOrganizationIdAndConnectorId(42L, "ejbca-primary"))
                .thenReturn(Optional.of(connectorRow("ejbca-primary", "EJBCA")));

        CaConnectorResponse connector = service().getByConnectorId(42L, "ejbca-primary");

        assertThat(connector.connectorId()).isEqualTo("ejbca-primary");
        assertThat(connector.caProvider()).isEqualTo("EJBCA");
    }

    @Test
    void getByConnectorIdThrowsWhenTheCaProviderFlagIsDisabled() {
        lenient().when(featureFlagService.isEnabled(FeatureFlags.CA_SMALLSTEP, 42L)).thenReturn(false);
        when(repository.findByOrganizationIdAndConnectorId(42L, "smallstep-primary"))
                .thenReturn(Optional.of(connectorRow("smallstep-primary", "SMALLSTEP")));

        assertThatThrownBy(() -> service().getByConnectorId(42L, "smallstep-primary"))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void aConnectorWhoseLastReportIsOlderThanTheFreshnessWindowIsStale() {
        lenient().when(featureFlagService.isEnabled(FeatureFlags.CA_SMALLSTEP, 42L)).thenReturn(true);
        IotCaHealthStatus fresh = connectorRow("step-fresh", "SMALLSTEP");
        fresh.setReceivedAt(OffsetDateTime.parse("2026-08-26T11:46:00Z"));
        IotCaHealthStatus removedAgent = connectorRow("step-orphaned", "SMALLSTEP");
        removedAgent.setReceivedAt(OffsetDateTime.parse("2026-08-25T19:00:00Z"));
        when(repository.findByOrganizationIdOrderByCaProviderAscConnectorIdAsc(42L))
                .thenReturn(List.of(fresh, removedAgent));

        List<CaConnectorResponse> connectors = service().list(42L);

        assertThat(connectors).extracting(CaConnectorResponse::connectorId, CaConnectorResponse::status,
                        CaConnectorResponse::reportedStatus, CaConnectorResponse::stale)
                .containsExactly(tuple("step-fresh", "HEALTHY", "HEALTHY", false),
                        tuple("step-orphaned", "STALE", "HEALTHY", true));
        assertThat(connectors.get(1).staleAt()).isEqualTo(OffsetDateTime.parse("2026-08-25T19:15:00Z"));
    }

    @Test
    void getByConnectorIdThrowsWhenTheConnectorDoesNotExist() {
        when(repository.findByOrganizationIdAndConnectorId(42L, "unknown"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service().getByConnectorId(42L, "unknown"))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    private static IotCaHealthStatus connectorRow(String connectorId, String caProvider) {
        OffsetDateTime now = OffsetDateTime.parse("2026-08-26T12:00:00Z");
        return IotCaHealthStatus.builder()
                .organizationId(42L)
                .connectorId(connectorId)
                .caProvider(caProvider)
                .enabled(true)
                .healthStatus("HEALTHY")
                .checkedAt(now)
                .respondedAt(now)
                .receivedAt(now)
                .capabilitiesJson("[]")
                .profilesJson("[]")
                .issuesJson("[]")
                .reportVersion(1)
                .updatedAt(now)
                .build();
    }

    private IotCaHealthService service() {
        return new IotCaHealthService(repository, organizationRepository, featureFlagService,
                JsonMapper.builderWithJackson2Defaults().build(), CLOCK, new IotDeviceProperties());
    }

    private static CaHealthReportMessage validReport() {
        CaHealthReportMessage.Connector connector = connector("ejbca-primary", "ejbca");
        CaHealthReportMessage report = new CaHealthReportMessage();
        report.setReportVersion(1);
        report.setOrganizationId("42");
        report.setRespondedAt("2026-08-26T11:59:59Z");
        report.setConnectors(List.of(connector));
        return report;
    }

    private static CaHealthReportMessage.Connector connector(String connectorId, String provider) {
        CaHealthReportMessage.Connector connector = new CaHealthReportMessage.Connector();
        connector.setConnectorId(connectorId);
        connector.setCaProvider(provider);
        connector.setEnabled(true);
        connector.setStatus("healthy");
        connector.setCheckedAt("2026-08-26T11:59:58Z");
        connector.setLatencyMs(25L);
        connector.setEndpoint("https://ejbca.internal");
        connector.setAuthMethod("MTLS");
        connector.setProduct(Map.of("name", "EJBCA", "edition", "Community"));
        connector.setCapabilities(List.of("SIGN_CSR"));
        connector.setProfiles(List.of(Map.of("kind", "CA", "name", "ManagementCA")));
        connector.setIssues(List.of());
        return connector;
    }
}
