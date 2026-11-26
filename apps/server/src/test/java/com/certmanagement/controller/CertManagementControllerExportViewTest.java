// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.Permissions;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.cert.CertConversionService;
import com.certmanagement.service.cert.CertIssuanceService;
import com.certmanagement.service.cert.CertManualIssuanceService;
import com.certmanagement.service.cert.DnsCredentialAvailability;
import com.certmanagement.service.cert.export.CertExportEligibilityPolicy;
import com.certmanagement.service.cert.export.CertExportFormat;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.data.domain.PageImpl;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

/**
 * The export view on certificate responses comes from the row and the CERTIFICATE_DOWNLOAD flag
 * (resolved once per request, for the org the endpoint serves), its formats from the caller's
 * permissions; the vault handle is always returned.
 */
class CertManagementControllerExportViewTest {

    private static final long ORG_ID = 1L;
    private static final String HANDLE = "https://kv-example.vault.azure.net/secrets/cert-1";

    private final CertIssuanceService certIssuanceService = mock(CertIssuanceService.class);
    private final AgentSecretStore store = mock(AgentSecretStore.class);
    private final FeatureFlagService featureFlagService = mock(FeatureFlagService.class);
    private CertManagementController controller;
    private CertificateEntity cert;

    @BeforeEach
    void setUp() {
        GatewayRequestContext.set(101, String.valueOf(ORG_ID), "req-1", "user@example.com");
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        beans.addBean("agentSecretStore", store);
        when(store.isReady()).thenReturn(true);
        when(store.isAgentCertificateHandle(HANDLE, "cert-1")).thenReturn(true);
        controller = new CertManagementController(mock(CertConversionService.class), certIssuanceService,
                mock(CertManualIssuanceService.class), featureFlagService,
                new CertExportEligibilityPolicy(beans.getBeanProvider(AgentSecretStore.class),
                        Clock.systemUTC()),
                mock(DnsCredentialAvailability.class));
        cert = CertificateEntity.builder().certificateXref("cert-1").caProvider(CaProvider.LETS_ENCRYPT)
                .status("ACTIVE").certSecretHandle(HANDLE).fingerprintSha256("AB:CD")
                .validTo(OffsetDateTime.now().plusDays(30)).build();
        when(certIssuanceService.getStatus(ORG_ID, "cert-1")).thenReturn(cert);
        when(featureFlagService.isEnabled(FeatureFlags.CERTIFICATE_DOWNLOAD, ORG_ID)).thenReturn(true);
        when(certIssuanceService.resolveCredentialRefsForResponse(any()))
                .thenReturn(new CertIssuanceService.CredentialRefs(Map.of(), List.of(), null, List.of()));
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    @SuppressWarnings("unchecked")
    void detail_forADeployHolder_offersEveryFormat() {
        authenticateWith(Permissions.CERTIFICATE_READ, Permissions.CERTIFICATE_DEPLOY);

        Map<String, Object> export = (Map<String, Object>) controller.getStatus("cert-1").getBody().get("export");

        assertThat(export).containsEntry("available", true).containsEntry("formats", List.of(
                CertExportFormat.FULLCHAIN_PEM, CertExportFormat.CERTIFICATE_PEM,
                CertExportFormat.CERTIFICATE_DER, CertExportFormat.PKCS7,
                CertExportFormat.PRIVATE_KEY_PEM, CertExportFormat.PKCS12));
    }

    @Test
    @SuppressWarnings("unchecked")
    void detail_forAViewer_offersOnlyTheCertificateAndChain_andStaysAvailable() {
        authenticateWith(Permissions.CERTIFICATE_READ, "ROLE_VIEWER");

        Map<String, Object> export = (Map<String, Object>) controller.getStatus("cert-1").getBody().get("export");

        assertThat(export).containsEntry("available", true).containsEntry("reason", null).containsEntry("formats",
                List.of(CertExportFormat.FULLCHAIN_PEM, CertExportFormat.CERTIFICATE_PEM,
                        CertExportFormat.CERTIFICATE_DER, CertExportFormat.PKCS7));
    }

    private static void authenticateWith(String... authorities) {
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("user", null, authorities));
    }

    @Test
    @SuppressWarnings("unchecked")
    void detail_carriesExportObject_andTheVaultHandle() {

        Map<String, Object> body = controller.getStatus("cert-1").getBody();

        assertThat(body).containsEntry("certSecretHandle", HANDLE);
        Map<String, Object> export = (Map<String, Object>) body.get("export");
        assertThat(export).containsEntry("available", true).containsEntry("reason", null)
                .containsKey("formats");
        verify(store, never()).read(any());
        verifyFlagResolvedOnceForTheServedOrg();
    }

    @Test
    @SuppressWarnings("unchecked")
    void detail_whenDownloadIsOff_isFeatureDisabledWithNoFormats() {
        when(featureFlagService.isEnabled(FeatureFlags.CERTIFICATE_DOWNLOAD, ORG_ID)).thenReturn(false);

        Map<String, Object> body = controller.getStatus("cert-1").getBody();

        assertThat((Map<String, Object>) body.get("export")).containsEntry("available", false)
                .containsEntry("reason", "FEATURE_DISABLED").containsEntry("formats", List.of());
        verify(store, never()).isAgentCertificateHandle(any(), any());
        verifyFlagResolvedOnceForTheServedOrg();
    }

    @Test
    @SuppressWarnings("unchecked")
    void listItems_carryExportAvailable_withoutAnySecretStoreRead_andOneFlagLookupForThePage() {
        stubListOf(cert, secondCert());

        Map<String, Object> body = controller.list(null, null, 0, 20).getBody();

        List<Map<String, Object>> items = (List<Map<String, Object>>) body.get("items");
        assertThat(items).hasSize(2);
        assertThat(items.get(0)).containsEntry("exportAvailable", true).doesNotContainKey("certSecretHandle");
        verify(store, never()).read(any());
        verifyFlagResolvedOnceForTheServedOrg();
    }

    @Test
    @SuppressWarnings("unchecked")
    void listItems_whenDownloadIsOff_areNotExportable() {
        when(featureFlagService.isEnabled(FeatureFlags.CERTIFICATE_DOWNLOAD, ORG_ID)).thenReturn(false);
        stubListOf(cert, secondCert());

        Map<String, Object> body = controller.list(null, null, 0, 20).getBody();

        assertThat((List<Map<String, Object>>) body.get("items"))
                .allSatisfy(item -> assertThat(item).containsEntry("exportAvailable", false));
        verifyFlagResolvedOnceForTheServedOrg();
    }

    private void stubListOf(CertificateEntity... certs) {
        when(certIssuanceService.list(eq(ORG_ID), any(), any(), anyInt(), anyInt()))
                .thenReturn(new PageImpl<>(List.of(certs)));
        when(certIssuanceService.resolveCredentialRefsForResponseBatch(anyList())).thenReturn(Map.of());
    }

    private CertificateEntity secondCert() {
        return CertificateEntity.builder().certificateXref("cert-2").caProvider(CaProvider.LETS_ENCRYPT)
                .status("ACTIVE").certSecretHandle(HANDLE).fingerprintSha256("EF:01")
                .validTo(OffsetDateTime.now().plusDays(30)).build();
    }

    /**
     * Exactly one lookup per request, and only for the org the endpoint serves (its
     * {@code OrgResolver.fromJwt()} org, the one the certificates were read from): never per row,
     * never another org.
     */
    private void verifyFlagResolvedOnceForTheServedOrg() {
        verify(featureFlagService, times(1)).isEnabled(FeatureFlags.CERTIFICATE_DOWNLOAD, ORG_ID);
        verifyNoMoreInteractions(featureFlagService);
    }
}
