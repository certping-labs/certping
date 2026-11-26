// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.cert.CertDeployRequest;
import com.certmanagement.dto.cert.CertIssuanceRequest;
import com.certmanagement.dto.cert.CertRenewalRequest;
import com.certmanagement.dto.cert.ConvertToAutomatedRequest;
import com.certmanagement.dto.cert.IssueManualRequest;
import com.certmanagement.dto.cert.RevokeRequest;
import com.certmanagement.dto.cert.TxtRecordDto;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.cert.CertConversionService;
import com.certmanagement.service.cert.CertIssuanceService;
import com.certmanagement.service.cert.CertManualIssuanceService;
import com.certmanagement.service.cert.DnsCredentialAvailability;
import com.certmanagement.service.cert.export.CertExportEligibilityPolicy;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CertManagementControllerMoreTest {

    @Mock private CertConversionService certConversionService;
    @Mock private CertIssuanceService certIssuanceService;
    @Mock private CertManualIssuanceService certManualIssuanceService;
    @Mock private FeatureFlagService featureFlagService;
    @Mock private FeatureFlagResolver featureFlagResolver;
    @Mock private CredentialReferenceRepository credentials;

    private CertManagementController controller;

    private static final Long ORG_ID = 1L;

    @BeforeEach
    void setUp() {
        controller = new CertManagementController(
                certConversionService, certIssuanceService, certManualIssuanceService, featureFlagService,
                new CertExportEligibilityPolicy(new StaticListableBeanFactory().getBeanProvider(AgentSecretStore.class), Clock.systemUTC()),
                new DnsCredentialAvailability(credentials, featureFlagResolver));
        GatewayRequestContext.set(101, String.valueOf(ORG_ID), "req-1", "user@example.com");
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    private CertificateEntity cert(String status) {
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(2L).organizationId(ORG_ID).domain("example.com").build();
        return CertificateEntity.builder()
                .certificateXref("cert-xref-1")
                .userDomainCert(udc)
                .userDomainCertId(2L)
                .caProvider(CaProvider.LETS_ENCRYPT)
                .status(status)
                .build();
    }

    @Test
    void issue_returnsAcceptedWithCertFields() {
        when(certIssuanceService.issue(eq(ORG_ID), any(CertIssuanceRequest.class)))
                .thenReturn(cert("PENDING"));

        ResponseEntity<Map<String, Object>> resp = controller.issue(new CertIssuanceRequest());

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(resp.getBody()).containsEntry("certificateXref", "cert-xref-1");
        assertThat(resp.getBody()).containsEntry("status", "PENDING");
        assertThat(resp.getBody()).containsKey("submittedAt");
    }

    @Test
    void issue_namingADnsCredentialWhileDnsCredentialsIsOff_isRefusedBeforeAnythingHappens() {
        when(featureFlagResolver.resolveUncached(FeatureFlags.DNS_CREDENTIALS, ORG_ID)).thenReturn(false);
        CertIssuanceRequest request = new CertIssuanceRequest();
        request.setDnsCredentialXref("cred-dns");

        assertThatThrownBy(() -> controller.issue(request))
                .isInstanceOf(FeatureDisabledException.class)
                .hasMessage("DNS credentials aren't available. Ask your CertPing administrator.")
                .satisfies(e -> {
                    assertThat(((FeatureDisabledException) e).getCode()).isEqualTo("FEATURE_DISABLED");
                    assertThat(((FeatureDisabledException) e).getFeatureKey()).isEqualTo(FeatureFlags.DNS_CREDENTIALS);
                });
        verifyNoInteractions(certIssuanceService);
    }

    @Test
    void issue_namingADnsCredentialOnlyForASanEntryWhileOff_isRefused() {
        when(featureFlagResolver.resolveUncached(FeatureFlags.DNS_CREDENTIALS, ORG_ID)).thenReturn(false);
        CertIssuanceRequest.SanDomainEntry san = new CertIssuanceRequest.SanDomainEntry();
        san.setPatterns(List.of("www.example.com"));
        san.setDnsCredentialXref("cred-san");
        CertIssuanceRequest request = new CertIssuanceRequest();
        request.setSanDomainEntries(List.of(san));

        assertThatThrownBy(() -> controller.issue(request)).isInstanceOf(FeatureDisabledException.class);
        verifyNoInteractions(certIssuanceService);
    }

    @Test
    void issue_namingADnsCredentialWhileDnsCredentialsIsOn_goesThrough() {
        when(featureFlagResolver.resolveUncached(FeatureFlags.DNS_CREDENTIALS, ORG_ID)).thenReturn(true);
        when(certIssuanceService.issue(eq(ORG_ID), any(CertIssuanceRequest.class))).thenReturn(cert("PENDING"));
        CertIssuanceRequest request = new CertIssuanceRequest();
        request.setDnsCredentialXref("cred-dns");

        assertThat(controller.issue(request).getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
    }

    @Test
    void issue_namingTheOrganizationsCertPingDnsCredentialWhileDnsCredentialsIsOff_goesThrough() {
        when(featureFlagResolver.resolveUncached(FeatureFlags.DNS_CREDENTIALS, ORG_ID)).thenReturn(false);
        when(credentials.findByCredentialXrefIn(Set.of("cred-certping")))
                .thenReturn(List.of(dnsCredential("cred-certping", ORG_ID, "CERTPING")));
        when(certIssuanceService.issue(eq(ORG_ID), any(CertIssuanceRequest.class))).thenReturn(cert("PENDING"));
        CertIssuanceRequest request = new CertIssuanceRequest();
        request.setDnsCredentialXref("cred-certping");

        assertThat(controller.issue(request).getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
    }

    @Test
    void issue_namingAnotherOrganizationsCertPingDnsCredentialWhileOff_isRefused() {
        when(featureFlagResolver.resolveUncached(FeatureFlags.DNS_CREDENTIALS, ORG_ID)).thenReturn(false);
        when(credentials.findByCredentialXrefIn(Set.of("cred-certping")))
                .thenReturn(List.of(dnsCredential("cred-certping", ORG_ID + 1, "CERTPING")));
        CertIssuanceRequest request = new CertIssuanceRequest();
        request.setDnsCredentialXref("cred-certping");

        assertThatThrownBy(() -> controller.issue(request)).isInstanceOf(FeatureDisabledException.class);
        verifyNoInteractions(certIssuanceService);
    }

    @Test
    void issue_namingADeletedCertPingDnsCredentialWhileOff_isRefused() {
        when(featureFlagResolver.resolveUncached(FeatureFlags.DNS_CREDENTIALS, ORG_ID)).thenReturn(false);
        CredentialReferenceEntity deleted = dnsCredential("cred-certping", ORG_ID, "CERTPING");
        deleted.setStatus("DELETED");
        deleted.setIsDeleted(true);
        when(credentials.findByCredentialXrefIn(Set.of("cred-certping"))).thenReturn(List.of(deleted));
        CertIssuanceRequest request = new CertIssuanceRequest();
        request.setDnsCredentialXref("cred-certping");

        assertThatThrownBy(() -> controller.issue(request)).isInstanceOf(FeatureDisabledException.class);
        verifyNoInteractions(certIssuanceService);
    }

    @Test
    void issue_namingACertPingCredentialThatIsNotForDnsWhileOff_isRefused() {
        when(featureFlagResolver.resolveUncached(FeatureFlags.DNS_CREDENTIALS, ORG_ID)).thenReturn(false);
        CredentialReferenceEntity deployment = dnsCredential("cred-certping", ORG_ID, "CERTPING");
        deployment.setType("DEPLOYMENT");
        when(credentials.findByCredentialXrefIn(Set.of("cred-certping"))).thenReturn(List.of(deployment));
        CertIssuanceRequest request = new CertIssuanceRequest();
        request.setDnsCredentialXref("cred-certping");

        assertThatThrownBy(() -> controller.issue(request)).isInstanceOf(FeatureDisabledException.class);
        verifyNoInteractions(certIssuanceService);
    }

    @Test
    void issue_namingCertPingAndAThirdPartyDnsCredentialWhileOff_isRefused() {
        when(featureFlagResolver.resolveUncached(FeatureFlags.DNS_CREDENTIALS, ORG_ID)).thenReturn(false);
        when(credentials.findByCredentialXrefIn(Set.of("cred-certping", "cred-cloudflare"))).thenReturn(List.of(
                dnsCredential("cred-certping", ORG_ID, "CERTPING"), dnsCredential("cred-cloudflare", ORG_ID, "CLOUDFLARE")));
        CertIssuanceRequest.SanDomainEntry san = new CertIssuanceRequest.SanDomainEntry();
        san.setPatterns(List.of("www.example.com"));
        san.setDnsCredentialXref("cred-cloudflare");
        CertIssuanceRequest request = new CertIssuanceRequest();
        request.setDnsCredentialXref("cred-certping");
        request.setSanDomainEntries(List.of(san));

        assertThatThrownBy(() -> controller.issue(request)).isInstanceOf(FeatureDisabledException.class);
        verifyNoInteractions(certIssuanceService);
    }

    @Test
    void renew_ofACertificateLinkedToADnsCredential_neverReadsDnsCredentials() {
        when(certIssuanceService.renew(eq(ORG_ID), eq("cert-xref-1"), any())).thenReturn(cert("RENEWING"));

        assertThat(controller.renew("cert-xref-1", new CertRenewalRequest()).getStatusCode())
                .isEqualTo(HttpStatus.ACCEPTED);
        verifyNoInteractions(featureFlagResolver);
    }

    @Test
    void getCaProviders_returnsAvailabilityForEachCa() {
        when(featureFlagService.isEnabled(anyString(), eq(ORG_ID))).thenReturn(true, false, true, false);

        ResponseEntity<Map<String, Object>> resp = controller.getCaProviders();

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> providers = (List<Map<String, Object>>) resp.getBody().get("caProviders");
        assertThat(providers).extracting(p -> p.get("key"))
                .containsExactlyInAnyOrder("LETS_ENCRYPT", "DIGICERT", "GLOBALSIGN");
        assertThat(providers).allSatisfy(p -> {
            assertThat(p).containsKey("key");
            assertThat(p).containsKey("featureKey");
            assertThat(p).containsKey("available");
        });
    }

    @Test
    void renew_returnsAccepted() {
        when(certIssuanceService.renew(eq(ORG_ID), eq("cert-xref-1"), any()))
                .thenReturn(cert("RENEWING"));

        ResponseEntity<Map<String, Object>> resp = controller.renew("cert-xref-1", new CertRenewalRequest());

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(resp.getBody()).containsEntry("status", "RENEWING");
    }

    @Test
    void deploy_returnsAccepted() {
        when(certIssuanceService.deploy(eq(ORG_ID), eq("cert-xref-1"), any(CertDeployRequest.class)))
                .thenReturn(cert("ACTIVE"));

        ResponseEntity<Map<String, Object>> resp = controller.deploy("cert-xref-1", new CertDeployRequest());

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(resp.getBody()).containsEntry("status", "ACTIVE");
    }

    @Test
    void delete_returnsNoContentAndDelegates() {
        ResponseEntity<Void> resp = controller.delete("cert-xref-1");

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(certIssuanceService).delete(ORG_ID, "cert-xref-1");
    }

    @Test
    void deleteUserDomainCert_returnsNoContentAndDelegates() {
        ResponseEntity<Void> resp = controller.deleteUserDomainCert(99L);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(certIssuanceService).deleteUserDomainCert(ORG_ID, 99L);
    }

    @Test
    void revoke_withBody_usesProvidedReason() {
        RevokeRequest req = new RevokeRequest();
        req.setReason("KEY_COMPROMISE");
        when(certIssuanceService.revoke(eq(ORG_ID), eq("cert-xref-1"), any(RevokeRequest.class)))
                .thenReturn(cert("REVOKING"));

        ResponseEntity<Map<String, Object>> resp = controller.revoke("cert-xref-1", req);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(resp.getBody()).containsEntry("revokeReason", "KEY_COMPROMISE");
    }

    @Test
    void revoke_nullBody_usesDefaultReason() {
        when(certIssuanceService.revoke(eq(ORG_ID), eq("cert-xref-1"), any(RevokeRequest.class)))
                .thenReturn(cert("REVOKING"));

        ResponseEntity<Map<String, Object>> resp = controller.revoke("cert-xref-1", null);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(resp.getBody()).containsKey("revokeReason");
    }

    @Test
    void issueManual_returnsAccepted() {
        when(certManualIssuanceService.initiateManualIssuance(eq(ORG_ID), any(IssueManualRequest.class)))
                .thenReturn(cert("PENDING_DNS"));

        ResponseEntity<Map<String, Object>> resp = controller.issueManual(new IssueManualRequest());

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(resp.getBody()).containsEntry("status", "PENDING_DNS");
    }

    @Test
    void getTxtRecords_returnsRecordList() {
        List<TxtRecordDto> records = List.of(new TxtRecordDto());
        when(certManualIssuanceService.getTxtRecords("cert-xref-1", ORG_ID)).thenReturn(records);

        ResponseEntity<Map<String, Object>> resp = controller.getTxtRecords("cert-xref-1");

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resp.getBody()).containsEntry("txtRecords", records);
    }

    @Test
    void validateDns_returnsAcceptedAndDelegates() {
        ResponseEntity<Void> resp = controller.validateDns("cert-xref-1");

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        verify(certManualIssuanceService).triggerValidation("cert-xref-1", ORG_ID);
    }

    private static CredentialReferenceEntity dnsCredential(String xref, long organizationId, String provider) {
        CredentialReferenceEntity credential = new CredentialReferenceEntity();
        credential.setCredentialXref(xref);
        credential.setOrganizationId(organizationId);
        credential.setProvider(provider);
        credential.setType("DNS");
        credential.setStatus("ACTIVE");
        return credential;
    }
}
