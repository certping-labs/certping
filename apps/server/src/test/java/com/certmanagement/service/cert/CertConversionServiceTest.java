// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.dto.cert.ConvertToAutomatedRequest;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.repository.CertManualIssuanceStateRepository;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.service.deployment.CertDeploymentConfigService;
import com.certmanagement.service.deployment.KubernetesDeploymentConfigResolver;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.certmanagement.dto.cert.CertIssuanceRequest;

import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertConversionServiceTest {


    @Mock private CertificateRepository certificateRepository;
    @Mock private CertificateFeatureLocks featureLocks;
    @Mock private DomainCredentialConfigRepository domainCredentialConfigRepository;
    @Mock private RenewalScheduleRepository renewalScheduleRepository;
    @Mock private CertManualIssuanceStateRepository manualIssuanceStateRepository;
    @Mock private CertificateEventRepository certificateEventRepository;
    @Mock private CredentialReferenceService credentialReferenceService;
    @Mock private CertIssuanceService certIssuanceService;
    @Mock private CertDeploymentConfigService certDeploymentConfigService;
    @Mock private KubernetesDeploymentConfigResolver kubernetesDeploymentConfigResolver;

    private final CertificateStatusValidator certificateStatusValidator = new CertificateStatusValidator();
    private CertConversionService service;
    private long idCounter = 100;

    private static final Long ORGANIZATION_ID = 1L;
    private static final Long UDC_ID = 2L;

    @BeforeEach
    void setUp() {
        service = new CertConversionService(
                certificateRepository,
                domainCredentialConfigRepository,
                renewalScheduleRepository,
                manualIssuanceStateRepository,
                certificateEventRepository,
                credentialReferenceService,
                certIssuanceService,
                certificateStatusValidator,
                certDeploymentConfigService,
                kubernetesDeploymentConfigResolver,
                JsonMapper.builderWithJackson2Defaults().build(),
                featureLocks, org.mockito.Mockito.mock(com.certmanagement.service.audit.CertificateAuditRecorder.class));
    }

    @Test
    void convert_activeImmediate_updatesConfigAndTriggersRenewal() {
        CertificateEntity cert = buildCert("cert-1", "ACTIVE");
        cert.setValidTo(OffsetDateTime.now().plusDays(40));
        cert.setCertSecretHandle("https://kv/cert");

        DomainCredentialConfigEntity existingConfig = DomainCredentialConfigEntity.builder()
                .id(++idCounter)
                .userDomainCertId(UDC_ID)
                .dnsConfig(Map.of("example.com", "old-dns"))
                .deploymentTargets(List.of("old-deploy"))
                .build();

        RenewalScheduleEntity schedule = RenewalScheduleEntity.builder()
                .id(++idCounter)
                .certificateXref("cert-1")
                .domainCredentialConfigId(existingConfig.getId())
                .renewalWindowDays(30)
                .enabled(false)
                .caProvider(CaProvider.LETS_ENCRYPT)
                .validTo(OffsetDateTime.now().plusDays(20))
                .renewalEligibleAt(OffsetDateTime.now().plusDays(1))
                .build();

        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-1", ORGANIZATION_ID)).thenReturn(Optional.of(cert));
        when(domainCredentialConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.of(existingConfig));
        when(domainCredentialConfigRepository.save(any(DomainCredentialConfigEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(renewalScheduleRepository.findByCertificateXref("cert-1")).thenReturn(Optional.of(schedule));
        when(credentialReferenceService.getByXref(ORGANIZATION_ID, "cred-dns-1"))
                .thenReturn(credential("DNS", "ACTIVE"));
        when(credentialReferenceService.getByXref(ORGANIZATION_ID, "cred-deploy-1"))
                .thenReturn(credential("DEPLOYMENT", "ACTIVE"));
        when(certIssuanceService.renew(eq(ORGANIZATION_ID), eq("cert-1"), any())).thenReturn(cert);

        Map<String, Object> response = service.convertToAutomated(ORGANIZATION_ID, "cert-1",
                request(ConvertToAutomatedRequest.ActivationMode.IMMEDIATE,
                        ConvertToAutomatedRequest.InFlightPolicy.WAIT));

        assertThat(response.get("plannedAction")).isEqualTo("CONFIG_UPDATED_AND_RENEWAL_TRIGGERED");
        verify(certIssuanceService).renew(eq(ORGANIZATION_ID), eq("cert-1"), any());
        verify(certIssuanceService, never()).issue(eq(ORGANIZATION_ID), any());

        ArgumentCaptor<DomainCredentialConfigEntity> configCaptor = ArgumentCaptor.forClass(DomainCredentialConfigEntity.class);
        verify(domainCredentialConfigRepository).save(configCaptor.capture());
        assertThat(configCaptor.getValue().getDnsConfig()).containsEntry("example.com", "cred-dns-1");
        assertThat(configCaptor.getValue().getDeploymentTargets()).containsExactly("cred-deploy-1");
    }

    @Test
    void convert_manualInFlightWait_updatesConfigAndDefers() {
        CertificateEntity cert = buildCert("cert-2", "AWAITING_DNS");
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-2", ORGANIZATION_ID)).thenReturn(Optional.of(cert));
        when(domainCredentialConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());
        when(domainCredentialConfigRepository.save(any(DomainCredentialConfigEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(credentialReferenceService.getByXref(ORGANIZATION_ID, "cred-dns-1"))
                .thenReturn(credential("DNS", "ACTIVE"));
        when(credentialReferenceService.getByXref(ORGANIZATION_ID, "cred-deploy-1"))
                .thenReturn(credential("DEPLOYMENT", "ACTIVE"));

        Map<String, Object> response = service.convertToAutomated(ORGANIZATION_ID, "cert-2",
                request(ConvertToAutomatedRequest.ActivationMode.NEXT_RENEWAL,
                        ConvertToAutomatedRequest.InFlightPolicy.WAIT));

        assertThat(response.get("plannedAction")).isEqualTo("CONFIG_UPDATED_WAITING_MANUAL_COMPLETION");
        verify(certIssuanceService, never()).renew(any(), any(), any());
        verify(certIssuanceService, never()).issue(any(), any());
        verify(manualIssuanceStateRepository, never()).deleteByCertXref(any());
        verify(certificateRepository, never()).save(any());
    }

    @Test
    void convert_manualInFlightCancelAndReissue_cancelsManualAndTriggersIssue() {
        CertificateEntity cert = buildCert("cert-3", "VALIDATING");
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-3", ORGANIZATION_ID)).thenReturn(Optional.of(cert));
        when(certificateRepository.save(any(CertificateEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(domainCredentialConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());
        when(domainCredentialConfigRepository.save(any(DomainCredentialConfigEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(credentialReferenceService.getByXref(ORGANIZATION_ID, "cred-dns-1"))
                .thenReturn(credential("DNS", "ACTIVE"));
        when(credentialReferenceService.getByXref(ORGANIZATION_ID, "cred-deploy-1"))
                .thenReturn(credential("DEPLOYMENT", "ACTIVE"));

        CertificateEntity issued = buildCert("cert-new", "PENDING");
        when(certIssuanceService.issue(eq(ORGANIZATION_ID), any())).thenReturn(issued);

        Map<String, Object> response = service.convertToAutomated(ORGANIZATION_ID, "cert-3",
                request(ConvertToAutomatedRequest.ActivationMode.IMMEDIATE,
                        ConvertToAutomatedRequest.InFlightPolicy.CANCEL_AND_REISSUE));

        assertThat(response.get("plannedAction")).isEqualTo("MANUAL_CANCELLED_AND_ISSUANCE_TRIGGERED");
        assertThat(response.get("triggeredCertificateXref")).isEqualTo("cert-new");

        ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository).save(certCaptor.capture());
        assertThat(certCaptor.getValue().getStatus()).isEqualTo("CANCELLED_MANUAL");

        verify(manualIssuanceStateRepository).deleteByCertXref("cert-3");
        verify(certIssuanceService).issue(eq(ORGANIZATION_ID), any());
    }

    @Test
    void convert_failedCertificate_triggersAutomatedIssuance() {
        CertificateEntity cert = buildCert("cert-4", "FAILED");
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-4", ORGANIZATION_ID)).thenReturn(Optional.of(cert));
        when(domainCredentialConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());
        when(domainCredentialConfigRepository.save(any(DomainCredentialConfigEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(credentialReferenceService.getByXref(ORGANIZATION_ID, "cred-dns-1"))
                .thenReturn(credential("DNS", "ACTIVE"));
        when(credentialReferenceService.getByXref(ORGANIZATION_ID, "cred-deploy-1"))
                .thenReturn(credential("DEPLOYMENT", "ACTIVE"));
        when(certIssuanceService.issue(eq(ORGANIZATION_ID), any())).thenReturn(buildCert("cert-5", "PENDING"));

        Map<String, Object> response = service.convertToAutomated(ORGANIZATION_ID, "cert-4",
                request(ConvertToAutomatedRequest.ActivationMode.NEXT_RENEWAL,
                        ConvertToAutomatedRequest.InFlightPolicy.WAIT));

        assertThat(response.get("plannedAction")).isEqualTo("CONFIG_UPDATED_AND_ISSUANCE_TRIGGERED");
        verify(certIssuanceService).issue(eq(ORGANIZATION_ID), any());
        verify(certIssuanceService, never()).renew(any(), any(), any());
    }

    // ================================================================== //
    //  Canonical scenario — manual-to-automated SAN reconstruction
    // ================================================================== //

    /**
     * Proves that CANCEL_AND_REISSUE reconstructs a {@link CertIssuanceRequest} whose
     * SAN entries exactly match the five-domain canonical set stored in {@code san_domains},
     * grouped correctly by root domain — same as the original issuance would have sent.
     *
     * <p>The dnsMappings provide only root-domain keys ("example.pro", "example.tech"),
     * not the full primary domain ("auto.example.pro").
     */
    @Test
    void convert_cancelAndReissue_withCanonicalSanCert_reconstructsIssuanceRequestFromStoredSanDomains() {
        // Cert that was issued manually and has the canonical san_domains stored
        CertificateEntity cert = buildCanonicalSanCert("cert-manual", "VALIDATING");
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-manual", ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));
        when(certificateRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(domainCredentialConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());
        when(domainCredentialConfigRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        when(credentialReferenceService.getByXref(ORGANIZATION_ID, "cred-example"))
                .thenReturn(credential("DNS", "ACTIVE"));
        when(credentialReferenceService.getByXref(ORGANIZATION_ID, "cred-example"))
                .thenReturn(credential("DNS", "ACTIVE"));
        when(credentialReferenceService.getByXref(ORGANIZATION_ID, "cred-deploy-1"))
                .thenReturn(credential("DEPLOYMENT", "ACTIVE"));

        CertificateEntity issued = buildCert("cert-new", "PENDING");
        when(certIssuanceService.issue(eq(ORGANIZATION_ID), any())).thenReturn(issued);

        service.convertToAutomated(ORGANIZATION_ID, "cert-manual",
                canonicalConversionRequest(ConvertToAutomatedRequest.InFlightPolicy.CANCEL_AND_REISSUE));

        // Capture the CertIssuanceRequest passed to certIssuanceService.issue()
        ArgumentCaptor<CertIssuanceRequest> issuanceCaptor =
                ArgumentCaptor.forClass(CertIssuanceRequest.class);
        verify(certIssuanceService).issue(eq(ORGANIZATION_ID), issuanceCaptor.capture());
        CertIssuanceRequest reconstructed = issuanceCaptor.getValue();

        assertThat(reconstructed.getDomain()).isEqualTo("auto.example.pro");
        assertThat(reconstructed.getWildcard()).isTrue();
        assertThat(reconstructed.getSan()).isTrue();
        assertThat(reconstructed.getDnsCredentialXref()).isEqualTo("cred-example");

        // Two SAN entries — example group + example same-root extras
        assertThat(reconstructed.getSanDomainEntries()).hasSize(2);
        List<List<String>> allPatterns = reconstructed.getSanDomainEntries().stream()
                .map(CertIssuanceRequest.SanDomainEntry::getPatterns)
                .toList();
        assertThat(allPatterns).containsExactlyInAnyOrder(
                List.of("example.tech", "*.example.tech"),
                List.of("example.pro", "*.example.pro"));
    }

    @Test
    void convert_aMappingKeyNoNameUses_addsNoNameToTheReissuedCertificate() {
        ConvertToAutomatedRequest req = canonicalConversionRequest(ConvertToAutomatedRequest.InFlightPolicy.CANCEL_AND_REISSUE);
        req.setDnsMappings(withMapping(req, "unused.org", "cred-unused"));

        CertIssuanceRequest reconstructed = reissue(buildCanonicalSanCert("cert-manual", "VALIDATING"), req);

        assertThat(reconstructed.getSanDomainEntries())
                .extracting(CertIssuanceRequest.SanDomainEntry::getPatterns)
                .containsExactlyInAnyOrder(List.of("example.tech", "*.example.tech"), List.of("example.pro", "*.example.pro"));
        assertThat(reconstructed.getSanDomainEntries())
                .extracting(CertIssuanceRequest.SanDomainEntry::getDnsCredentialXref)
                .doesNotContain("cred-unused");
    }

    @Test
    void convert_aMappingKeyForASubdomainName_keepsThatNameUnderItsOwnCredential() {
        CertificateEntity cert = buildCanonicalSanCert("cert-manual", "VALIDATING");
        cert.setSanDomains(new String[]{"*.auto.example.pro", "example.pro", "example.tech", "shop.example.tech"});
        ConvertToAutomatedRequest req = canonicalConversionRequest(ConvertToAutomatedRequest.InFlightPolicy.CANCEL_AND_REISSUE);
        req.setDnsMappings(withMapping(req, "shop.example.tech", "cred-shop"));

        CertIssuanceRequest reconstructed = reissue(cert, req);

        assertThat(reconstructed.getSanDomainEntries())
                .extracting(entry -> entry.getDnsCredentialXref() + "=" + entry.getPatterns())
                .containsExactlyInAnyOrder("cred-example=[example.tech]", "cred-shop=[shop.example.tech]",
                        "cred-example=[example.pro]");
    }

    @Test
    void convert_aNameNoMappingCovers_isRefusedAndNothingIsReissued() {
        CertificateEntity cert = buildCanonicalSanCert("cert-manual", "VALIDATING");
        cert.setSanDomains(new String[]{"*.auto.example.pro", "example.tech", "api.example.net"});
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-manual", ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));
        lenient().when(certificateRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        lenient().when(domainCredentialConfigRepository.findByUserDomainCertId(UDC_ID))
                .thenReturn(Optional.empty());
        lenient().when(domainCredentialConfigRepository.save(any()))
                .thenAnswer(inv -> inv.getArgument(0));
        when(credentialReferenceService.getByXref(any(), any())).thenAnswer(inv ->
                credential("cred-deploy-1".equals(inv.getArgument(1)) ? "DEPLOYMENT" : "DNS", "ACTIVE"));

        assertThatThrownBy(() -> service.convertToAutomated(ORGANIZATION_ID, "cert-manual",
                canonicalConversionRequest(ConvertToAutomatedRequest.InFlightPolicy.CANCEL_AND_REISSUE)))
                .isInstanceOf(com.certmanagement.exception.BadRequestException.class)
                .hasMessageContaining("api.example.net");
        verify(certIssuanceService, never()).issue(any(), any());
    }

    @Test
    void convert_anActiveCertificateWithANameNoMappingCovers_isRefusedBeforeTheMappingsAreSaved() {
        CertificateEntity cert = buildCanonicalSanCert("cert-x", "ACTIVE");
        cert.setValidTo(OffsetDateTime.now().plusDays(40));
        cert.setSanDomains(new String[]{"*.auto.example.pro", "example.tech", "api.example.net"});
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-x", ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));
        when(credentialReferenceService.getByXref(any(), any())).thenAnswer(inv ->
                credential("cred-deploy-1".equals(inv.getArgument(1)) ? "DEPLOYMENT" : "DNS", "ACTIVE"));

        assertThatThrownBy(() -> service.convertToAutomated(ORGANIZATION_ID, "cert-x",
                canonicalConversionRequest(ConvertToAutomatedRequest.InFlightPolicy.WAIT)))
                .isInstanceOf(com.certmanagement.exception.BadRequestException.class)
                .hasMessageContaining("api.example.net");
        verify(domainCredentialConfigRepository, never()).save(any());
        verify(certIssuanceService, never()).renew(any(), any(), any());
        verify(certIssuanceService, never()).issue(any(), any());
    }

    private List<ConvertToAutomatedRequest.DnsCredentialMapping> withMapping(ConvertToAutomatedRequest req,
                                                                            String domain, String credentialXref) {
        ConvertToAutomatedRequest.DnsCredentialMapping extra = new ConvertToAutomatedRequest.DnsCredentialMapping();
        extra.setDomain(domain);
        extra.setCredentialXref(credentialXref);
        List<ConvertToAutomatedRequest.DnsCredentialMapping> mappings = new ArrayList<>(req.getDnsMappings());
        mappings.add(extra);
        return mappings;
    }

    /** Converts {@code cert} with CANCEL_AND_REISSUE and returns the issuance request the conversion built. */
    private CertIssuanceRequest reissue(CertificateEntity cert, ConvertToAutomatedRequest req) {
        when(certificateRepository.findByCertificateXrefAndOrganizationId(cert.getCertificateXref(), ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));
        when(certificateRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(domainCredentialConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());
        when(domainCredentialConfigRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(credentialReferenceService.getByXref(any(), any())).thenAnswer(inv ->
                credential("cred-deploy-1".equals(inv.getArgument(1)) ? "DEPLOYMENT" : "DNS", "ACTIVE"));
        when(certIssuanceService.issue(eq(ORGANIZATION_ID), any())).thenReturn(buildCert("cert-new", "PENDING"));

        service.convertToAutomated(ORGANIZATION_ID, cert.getCertificateXref(), req);

        ArgumentCaptor<CertIssuanceRequest> captor = ArgumentCaptor.forClass(CertIssuanceRequest.class);
        verify(certIssuanceService).issue(eq(ORGANIZATION_ID), captor.capture());
        return captor.getValue();
    }

    /**
     * Proves that buildValidatedDnsConfig accepts root-domain keys (e.g. "example.pro")
     * for a primary domain that is a subdomain (e.g. "auto.example.pro").
     */
    @Test
    void convert_dnsMapping_withRootDomainKeyForSubdomainPrimary_accepted() {
        CertificateEntity cert = buildCanonicalSanCert("cert-x", "ACTIVE");
        cert.setValidTo(OffsetDateTime.now().plusDays(40));
        cert.setCertSecretHandle("https://kv/cert");

        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-x", ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));
        when(domainCredentialConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());
        when(domainCredentialConfigRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(credentialReferenceService.getByXref(ORGANIZATION_ID, "cred-example"))
                .thenReturn(credential("DNS", "ACTIVE"));
        when(credentialReferenceService.getByXref(ORGANIZATION_ID, "cred-example"))
                .thenReturn(credential("DNS", "ACTIVE"));
        when(credentialReferenceService.getByXref(ORGANIZATION_ID, "cred-deploy-1"))
                .thenReturn(credential("DEPLOYMENT", "ACTIVE"));
        when(renewalScheduleRepository.findByCertificateXref("cert-x")).thenReturn(Optional.empty());
        when(certIssuanceService.renew(eq(ORGANIZATION_ID), eq("cert-x"), any())).thenReturn(cert);

        // Must not throw — "example.pro" is the root of primary "auto.example.pro"
        Map<String, Object> response = service.convertToAutomated(ORGANIZATION_ID, "cert-x",
                canonicalConversionRequest(ConvertToAutomatedRequest.InFlightPolicy.WAIT));

        assertThat(response).containsKey("plannedAction");

        // dns_config stored with root-domain keys
        ArgumentCaptor<DomainCredentialConfigEntity> configCaptor =
                ArgumentCaptor.forClass(DomainCredentialConfigEntity.class);
        verify(domainCredentialConfigRepository).save(configCaptor.capture());
        assertThat(configCaptor.getValue().getDnsConfig())
                .containsKey("example.pro")
                .containsKey("example.tech")
                .doesNotContainKey("auto.example.pro");
    }

    private CertificateEntity buildCanonicalSanCert(String xref, String status) {
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(UDC_ID).organizationId(ORGANIZATION_ID).domain("auto.example.pro").build();

        return CertificateEntity.builder()
                .id(++idCounter)
                .certificateXref(xref)
                .userDomainCertId(UDC_ID)
                .userDomainCert(udc)
                .caProvider(CaProvider.LETS_ENCRYPT)
                .status(status)
                .wildcard(true)
                .san(true)
                .sanDomains(new String[]{
                        "*.auto.example.pro",
                        "example.pro",
                        "*.example.pro",
                        "example.tech",
                        "*.example.tech"})
                .build();
    }

    private ConvertToAutomatedRequest canonicalConversionRequest(
            ConvertToAutomatedRequest.InFlightPolicy policy) {
        ConvertToAutomatedRequest req = new ConvertToAutomatedRequest();

        ConvertToAutomatedRequest.DnsCredentialMapping m1 = new ConvertToAutomatedRequest.DnsCredentialMapping();
        m1.setDomain("example.pro");        // root-domain key — covers "auto.example.pro"
        m1.setCredentialXref("cred-example");

        ConvertToAutomatedRequest.DnsCredentialMapping m2 = new ConvertToAutomatedRequest.DnsCredentialMapping();
        m2.setDomain("example.tech");
        m2.setCredentialXref("cred-example");

        req.setDnsMappings(List.of(m1, m2));
        req.setDeploymentTargets(List.of("cred-deploy-1"));
        req.setActivationMode(ConvertToAutomatedRequest.ActivationMode.IMMEDIATE);
        req.setInFlightPolicy(policy);
        return req;
    }

    private CertificateEntity buildCert(String xref, String status) {
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(UDC_ID)
                .organizationId(ORGANIZATION_ID)
                .domain("example.com")
                .build();

        return CertificateEntity.builder()
                .id(++idCounter)
                .certificateXref(xref)
                .userDomainCertId(UDC_ID)
                .userDomainCert(udc)
                .caProvider(CaProvider.LETS_ENCRYPT)
                .status(status)
                .wildcard(false)
                .san(false)
                .build();
    }

    private CredentialReferenceEntity credential(String type, String status) {
        return CredentialReferenceEntity.builder()
                .id(++idCounter)
                .credentialXref(String.valueOf(++idCounter))
                .organizationId(ORGANIZATION_ID)
                .type(type)
                .provider("AZURE_KV")
                .secretHandle("https://kv/path")
                .status(status)
                .build();
    }

    private ConvertToAutomatedRequest request(
            ConvertToAutomatedRequest.ActivationMode activationMode,
            ConvertToAutomatedRequest.InFlightPolicy inFlightPolicy) {
        ConvertToAutomatedRequest request = new ConvertToAutomatedRequest();

        ConvertToAutomatedRequest.DnsCredentialMapping mapping =
                new ConvertToAutomatedRequest.DnsCredentialMapping();
        mapping.setDomain("example.com");
        mapping.setCredentialXref("cred-dns-1");

        request.setDnsMappings(List.of(mapping));
        request.setDeploymentTargets(List.of("cred-deploy-1"));
        request.setActivationMode(activationMode);
        request.setInFlightPolicy(inFlightPolicy);
        return request;
    }
}
