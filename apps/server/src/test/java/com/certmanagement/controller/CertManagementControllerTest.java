// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.constants.ExpiringCertsConstants;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.cert.CertConversionService;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.service.cert.CertIssuanceService;
import com.certmanagement.service.cert.CertManualIssuanceService;
import com.certmanagement.service.cert.DnsCredentialAvailability;
import com.certmanagement.service.cert.export.CertExportEligibilityPolicy;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.SliceImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertManagementControllerTest {

    @Mock
    private CertIssuanceService certIssuanceService;

    @Mock
    private CertManualIssuanceService certManualIssuanceService;

        @Mock
        private CertConversionService certConversionService;

    @Mock
    private FeatureFlagService featureFlagService;


    @Spy
    private CertExportEligibilityPolicy certExportEligibilityPolicy = new CertExportEligibilityPolicy(
            new StaticListableBeanFactory().getBeanProvider(AgentSecretStore.class),
            Clock.systemUTC());

    @Mock
    private DnsCredentialAvailability dnsCredentialAvailability;

    @InjectMocks
    private CertManagementController controller;

    private static final Long ORGANIZATION_ID = 1L;

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void getStatus_includesExpectedFieldsAndOmitsCreatedUpdated() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-1", "user@example.com");

        CertificateEntity cert = buildCertificate("ACTIVE");
        cert.setSanDomains(new String[]{"api.example.com", "*.api.example.com"});
        cert.setValidFrom(OffsetDateTime.parse("2026-01-01T00:00:00Z"));
        cert.setValidTo(OffsetDateTime.parse("2026-04-01T00:00:00Z"));
        cert.setTargetResourceId("arn:aws:acm:us-east-1:123456789012:certificate/abc");
        cert.setCreatedAt(OffsetDateTime.parse("2026-01-01T00:00:00Z"));
        cert.setUpdatedAt(OffsetDateTime.parse("2026-02-01T00:00:00Z"));

        when(certIssuanceService.getStatus(ORGANIZATION_ID, "cert-1")).thenReturn(cert);
        when(certIssuanceService.resolveCredentialRefsForResponse(cert))
                .thenReturn(new CertIssuanceService.CredentialRefs(
                        Map.of("example.com", "cred-dns-1", "api.example.com", "cred-dns-2"),
                        List.of("cred-deploy-1"),
                        "https://kv.vault.azure.net/secrets/dns-1",
                        List.of("https://kv.vault.azure.net/secrets/deploy-1")));

        ResponseEntity<Map<String, Object>> response = controller.getStatus("cert-1");

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        Map<String, Object> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body)
                .containsEntry("wildcard", false)
                .containsEntry("san", true)
                .containsEntry("userDomainCertId", cert.getUserDomainCertId())
                .containsEntry("dnsConfigXref", Map.of("example.com", "cred-dns-1", "api.example.com", "cred-dns-2"))
                .containsEntry("deploymentCredentialXrefs", List.of("cred-deploy-1"))
                .containsEntry("dnsCredentialKvPath", "https://kv.vault.azure.net/secrets/dns-1")
                .containsEntry("deploymentCredentialKvPaths", List.of("https://kv.vault.azure.net/secrets/deploy-1"))
                .containsEntry("targetResourceId", "arn:aws:acm:us-east-1:123456789012:certificate/abc");
        assertThat(body.get("sanDomains")).isInstanceOf(String[].class);
        assertThat((String[]) body.get("sanDomains"))
                .containsExactly("api.example.com", "*.api.example.com");
        assertThat(body).containsKeys("validFrom", "validTo");
        assertThat(body).doesNotContainKeys("createdAt", "updatedAt");

        verify(certIssuanceService).getStatus(ORGANIZATION_ID, "cert-1");
    }

    @Test
    void list_includesExpandedSummaryFieldsAndConditionalRefs() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-2", "user@example.com");

        CertificateEntity cert = buildCertificate("PENDING");
        cert.setSanDomains(new String[]{"example.com"});
        cert.setValidFrom(OffsetDateTime.parse("2026-01-01T00:00:00Z"));
        cert.setValidTo(OffsetDateTime.parse("2026-04-01T00:00:00Z"));

        Page<CertificateEntity> page = new PageImpl<>(List.of(cert));
        when(certIssuanceService.list(ORGANIZATION_ID, null, null, 0, 20)).thenReturn(page);
        when(certIssuanceService.resolveCredentialRefsForResponse(cert))
                .thenReturn(new CertIssuanceService.CredentialRefs(null, List.of(), null, List.of()));

        ResponseEntity<Map<String, Object>> response = controller.list(null, null, 0, 20);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        Map<String, Object> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body).containsKeys("items", "page", "size", "totalItems", "totalPages");

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) body.get("items");
        assertThat(items).hasSize(1);
        Map<String, Object> item = items.get(0);

        assertThat(item)
                .containsEntry("wildcard", false)
                .containsEntry("san", true)
                .containsEntry("userDomainCertId", cert.getUserDomainCertId())
                .containsEntry("dnsConfigXref", null)
                .containsEntry("deploymentCredentialXrefs", List.of())
                .containsEntry("dnsCredentialKvPath", null)
                .containsEntry("deploymentCredentialKvPaths", List.of());
        assertThat(item.get("sanDomains")).isInstanceOf(String[].class);
        assertThat(item).containsKeys("validFrom", "validTo");
        assertThat(item).doesNotContainKeys("createdAt", "updatedAt");
    }

    @Test
    void dashboard_containsStatsAndItemsWithCertFields() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-3", "user@example.com");

        CertificateEntity cert = buildCertificate("ACTIVE");
        cert.setSanDomains(new String[]{"api.example.com"});
        cert.setValidFrom(OffsetDateTime.parse("2026-01-01T00:00:00Z"));
        cert.setValidTo(OffsetDateTime.parse("2026-04-01T00:00:00Z"));
        cert.setTargetResourceId("https://example-vault-blue-wus.vault.azure.net/certificates/example");

        when(certIssuanceService.dashboard(ORGANIZATION_ID))
                .thenReturn(Map.of("total", 1L, "expiringIn30Days", 0L, "byStatus", Map.of("ACTIVE", 1L)));
        when(certIssuanceService.list(eq(ORGANIZATION_ID), eq(null), eq(null), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(cert)));
        when(certIssuanceService.resolveCredentialRefsForResponse(cert))
                .thenReturn(new CertIssuanceService.CredentialRefs(
                        Map.of("example.com", "cred-dns-1"),
                        List.of("cred-deploy-1"),
                        "https://kv.vault.azure.net/secrets/dns-1",
                        List.of("https://kv.vault.azure.net/secrets/deploy-1")));

        ResponseEntity<Map<String, Object>> response = controller.dashboard();

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        Map<String, Object> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body).containsKeys("total", "expiringIn30Days", "byStatus", "items");

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) body.get("items");
        assertThat(items).hasSize(1);
        assertThat(items.get(0)).containsEntry("userDomainCertId", cert.getUserDomainCertId());
        assertThat(items.get(0)).containsEntry("dnsConfigXref", Map.of("example.com", "cred-dns-1"));
        assertThat(items.get(0)).containsEntry("deploymentCredentialXrefs", List.of("cred-deploy-1"));
        assertThat(items.get(0)).containsEntry("dnsCredentialKvPath", "https://kv.vault.azure.net/secrets/dns-1");
        assertThat(items.get(0)).containsEntry("deploymentCredentialKvPaths", List.of("https://kv.vault.azure.net/secrets/deploy-1"));
        assertThat(items.get(0)).containsEntry("targetResourceId", "https://example-vault-blue-wus.vault.azure.net/certificates/example");
        assertThat(items.get(0)).containsKeys("sanDomains", "validFrom", "validTo");
    }

    @Test
    void list_usesEmptyArrayForMissingSanDomains() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-4", "user@example.com");

        CertificateEntity cert = buildCertificate("ACTIVE");
        cert.setSanDomains(null);

        when(certIssuanceService.list(ORGANIZATION_ID, null, null, 0, 20))
                .thenReturn(new PageImpl<>(List.of(cert)));
        when(certIssuanceService.resolveCredentialRefsForResponse(cert))
                .thenReturn(new CertIssuanceService.CredentialRefs(null, List.of(), null, List.of()));

        ResponseEntity<Map<String, Object>> response = controller.list(null, null, 0, 20);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) response.getBody().get("items");
        assertThat(items).hasSize(1);
        assertThat(items.get(0).get("sanDomains")).isInstanceOf(String[].class);
        assertThat((String[]) items.get(0).get("sanDomains")).isEmpty();
    }

    @Test
    void history_returnsListEnvelopeAndItemsForUdc() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-5", "user@example.com");

        Long udcId = 2L;
        CertificateEntity cert = buildCertificate("ACTIVE");
        cert.setSanDomains(new String[]{"api.example.com"});

        when(certIssuanceService.history(ORGANIZATION_ID, udcId, 0, 20))
                .thenReturn(new PageImpl<>(List.of(cert)));
        when(certIssuanceService.resolveCredentialRefsForResponse(cert))
                .thenReturn(new CertIssuanceService.CredentialRefs(null, List.of(), null, List.of()));

        ResponseEntity<Map<String, Object>> response = controller.history(udcId, 0, 20);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        Map<String, Object> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body).containsKeys("items", "page", "size", "totalItems", "totalPages");

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) body.get("items");
        assertThat(items).hasSize(1);
        assertThat(items.get(0))
                .containsEntry("certificateXref", "cert-1")
                .containsEntry("userDomainCertId", cert.getUserDomainCertId());

        verify(certIssuanceService).history(ORGANIZATION_ID, udcId, 0, 20);
    }

    @Test
    void history_includesFailedAndActiveCerts_whenServiceReturnsAll() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-5b", "user@example.com");

        Long udcId = 2L;
        CertificateEntity failed = buildCertificate("FAILED");
        failed.setCertificateXref("cert-failed");
        CertificateEntity active = buildCertificate("ACTIVE");
        active.setCertificateXref("cert-active");

        when(certIssuanceService.history(ORGANIZATION_ID, udcId, 0, 20))
                .thenReturn(new PageImpl<>(List.of(failed, active)));
        when(certIssuanceService.resolveCredentialRefsForResponse(failed))
                .thenReturn(new CertIssuanceService.CredentialRefs(null, List.of(), null, List.of()));
        when(certIssuanceService.resolveCredentialRefsForResponse(active))
                .thenReturn(new CertIssuanceService.CredentialRefs(null, List.of(), null, List.of()));

        ResponseEntity<Map<String, Object>> response = controller.history(udcId, 0, 20);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) response.getBody().get("items");
        assertThat(items).hasSize(2);
        assertThat(items).extracting(m -> m.get("certificateXref"))
                .containsExactly("cert-failed", "cert-active");
        assertThat(items).extracting(m -> m.get("status"))
                .containsExactly("FAILED", "ACTIVE");
    }

    @Test
    void history_saysWhetherAScheduledOrAManualRenewalProducedEachCertificate() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-5c", "user@example.com");
        com.certmanagement.repository.CertificateEventRepository events =
                org.mockito.Mockito.mock(com.certmanagement.repository.CertificateEventRepository.class);
        controller.setCertificateEvents(events);

        Long udcId = 2L;
        CertificateEntity scheduled = buildCertificate("ACTIVE");
        scheduled.setCertificateXref("cert-scheduled");
        CertificateEntity manual = buildCertificate("RENEW_SUCCESS");
        manual.setCertificateXref("cert-manual");
        CertificateEntity first = buildCertificate("RENEW_SUCCESS");
        first.setCertificateXref("cert-first");
        when(certIssuanceService.history(ORGANIZATION_ID, udcId, 0, 20))
                .thenReturn(new PageImpl<>(List.of(scheduled, manual, first)));
        for (CertificateEntity c : List.of(scheduled, manual, first)) {
            when(certIssuanceService.resolveCredentialRefsForResponse(c))
                    .thenReturn(new CertIssuanceService.CredentialRefs(null, List.of(), null, List.of()));
        }
        when(events.findRenewalSources(ORGANIZATION_ID, List.of("cert-scheduled", "cert-manual", "cert-first")))
                .thenReturn(List.of(
                        new Object[]{"cert-scheduled", "certping-scheduler"},
                        new Object[]{"cert-manual", "certping-cert-manager"}));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) controller.history(udcId, 0, 20)
                .getBody().get("items");

        assertThat(items).extracting(m -> m.get("renewalTrigger"))
                .containsExactly("SCHEDULED", "MANUAL", null);
    }

    @Test
    void convertToAutomated_returnsAcceptedResult() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-6", "user@example.com");

        Map<String, Object> result = Map.of(
                "certificateXref", "cert-1",
                "plannedAction", "CONFIG_UPDATED_AND_RENEWAL_TRIGGERED",
                "effectiveWhen", "immediate");

        when(certConversionService.convertToAutomated(eq(ORGANIZATION_ID), eq("cert-1"), any()))
                .thenReturn(result);

        ResponseEntity<Map<String, Object>> response = controller.convertToAutomated(
                "cert-1", new com.certmanagement.dto.cert.ConvertToAutomatedRequest());

        assertThat(response.getStatusCode().value()).isEqualTo(202);
        assertThat(response.getBody()).isEqualTo(result);
        verify(certConversionService).convertToAutomated(eq(ORGANIZATION_ID), eq("cert-1"), any());
    }

    private CertificateEntity buildCertificate(String status) {
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(2L)
                .organizationId(ORGANIZATION_ID)
                .domain("example.com")
                .build();

        return CertificateEntity.builder()
                .id(3L)
                .certificateXref("cert-1")
                .userDomainCertId(udc.getId())
                .userDomainCert(udc)
                .caProvider(CaProvider.LETS_ENCRYPT)
                .status(status)
                .wildcard(false)
                .san(true)
                .build();
    }

    @Test
    void listExpiring_returnsProjectionSliceWithoutSecrets() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-expiring", "user@example.com");

        CertificateRepository.ExpiringCertificateRow row = mockExpiringRow(
                "example.com",
                "cert-exp-1",
                OffsetDateTime.parse("2026-04-01T00:00:00Z"),
                "ACTIVE",
                CaProvider.LETS_ENCRYPT);
        Slice<CertificateRepository.ExpiringCertificateRow> slice =
                new SliceImpl<>(List.of(row), PageRequest.of(0, 20), false);
        when(certIssuanceService.listExpiring(
                eq(ORGANIZATION_ID),
                eq(ExpiringCertsConstants.DEFAULT_WITHIN_DAYS),
                any(Pageable.class)))
                .thenReturn(slice);

        ResponseEntity<Map<String, Object>> response = controller.listExpiring(
                ExpiringCertsConstants.DEFAULT_WITHIN_DAYS,
                PageRequest.of(0, 20));

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        Map<String, Object> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body)
                .containsEntry("page", 0)
                .containsEntry("size", 20)
                .containsEntry("hasNext", false)
                .containsEntry("withinDays", ExpiringCertsConstants.DEFAULT_WITHIN_DAYS);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) body.get("items");
        assertThat(items).hasSize(1);
        assertThat(items.get(0))
                .containsEntry("domain", "example.com")
                .containsEntry("certificateXref", "cert-exp-1")
                .containsEntry("validTo", "2026-04-01T00:00Z")
                .containsEntry("status", "ACTIVE")
                .containsEntry("caProvider", CaProvider.LETS_ENCRYPT)
                .doesNotContainKeys("dnsCredentialKvPath", "certSecretHandle", "deploymentCredentialXrefs");
        verify(certIssuanceService).listExpiring(
                eq(ORGANIZATION_ID),
                eq(ExpiringCertsConstants.DEFAULT_WITHIN_DAYS),
                eq(PageRequest.of(0, 20)));
    }

    @Test
    void listExpiring_forwardsCustomWithinDaysAndPageable() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-expiring-2", "user@example.com");

        Slice<CertificateRepository.ExpiringCertificateRow> slice =
                new SliceImpl<>(List.of(), PageRequest.of(1, 5), true);
        when(certIssuanceService.listExpiring(eq(ORGANIZATION_ID), eq(30), any(Pageable.class)))
                .thenReturn(slice);

        ResponseEntity<Map<String, Object>> response =
                controller.listExpiring(30, PageRequest.of(1, 5));

        assertThat(response.getBody())
                .containsEntry("hasNext", true)
                .containsEntry("page", 1)
                .containsEntry("size", 5)
                .containsEntry("withinDays", 30);
        verify(certIssuanceService).listExpiring(ORGANIZATION_ID, 30, PageRequest.of(1, 5));
    }

    private static CertificateRepository.ExpiringCertificateRow mockExpiringRow(
            String domain,
            String xref,
            OffsetDateTime validTo,
            String status,
            CaProvider ca) {
        return new CertificateRepository.ExpiringCertificateRow() {
            @Override public String getDomain() { return domain; }
            @Override public String getCertificateXref() { return xref; }
            @Override public OffsetDateTime getValidTo() { return validTo; }
            @Override public String getStatus() { return status; }
            @Override public CaProvider getCaProvider() { return ca; }
        };
    }


}
