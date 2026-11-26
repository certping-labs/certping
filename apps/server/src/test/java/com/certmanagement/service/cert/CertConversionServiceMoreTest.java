// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.dto.cert.ConvertToAutomatedRequest;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Supplementary coverage for {@link CertConversionService}: not-found / no-domain guards and the
 * dnsMappings / deploymentTargets validation error branches.
 */
@ExtendWith(MockitoExtension.class)
class CertConversionServiceMoreTest {


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

    private static final Long ORG_ID = 1L;
    private static final Long UDC_ID = 2L;

    @BeforeEach
    void setUp() {
        service = new CertConversionService(
                certificateRepository, domainCredentialConfigRepository, renewalScheduleRepository,
                manualIssuanceStateRepository, certificateEventRepository, credentialReferenceService,
                certIssuanceService, certificateStatusValidator, certDeploymentConfigService,
                kubernetesDeploymentConfigResolver, JsonMapper.builderWithJackson2Defaults().build(), featureLocks, org.mockito.Mockito.mock(com.certmanagement.service.audit.CertificateAuditRecorder.class));
    }

    private CertificateEntity cert(String xref, String status, String domain) {
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(UDC_ID).organizationId(ORG_ID).domain(domain).build();
        return CertificateEntity.builder()
                .id(99L).certificateXref(xref).userDomainCertId(UDC_ID).userDomainCert(udc)
                .caProvider(CaProvider.LETS_ENCRYPT).status(status).wildcard(false).san(false).build();
    }

    private CredentialReferenceEntity cred(String type, String status) {
        return CredentialReferenceEntity.builder()
                .credentialXref("cred-x").organizationId(ORG_ID).type(type).provider("AZURE_KV")
                .secretHandle("kv").status(status).build();
    }

    private ConvertToAutomatedRequest reqWithDns(String domain, String credXref) {
        ConvertToAutomatedRequest r = new ConvertToAutomatedRequest();
        ConvertToAutomatedRequest.DnsCredentialMapping m = new ConvertToAutomatedRequest.DnsCredentialMapping();
        m.setDomain(domain);
        m.setCredentialXref(credXref);
        r.setDnsMappings(new ArrayList<>(List.of(m)));
        r.setDeploymentTargets(List.of());
        return r;
    }

    @Test
    void convert_certNotFound_throws() {
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-x", ORG_ID))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.convertToAutomated(ORG_ID, "cert-x", new ConvertToAutomatedRequest()))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void convert_noPrimaryDomain_throws() {
        CertificateEntity c = cert("cert-1", "ACTIVE", null); // null domain
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-1", ORG_ID))
                .thenReturn(Optional.of(c));

        assertThatThrownBy(() -> service.convertToAutomated(ORG_ID, "cert-1", new ConvertToAutomatedRequest()))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("no resolvable primary domain");
    }

    @Test
    void convert_emptyDnsMappings_throws() {
        CertificateEntity c = cert("cert-1", "ACTIVE", "example.com");
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-1", ORG_ID))
                .thenReturn(Optional.of(c));
        ConvertToAutomatedRequest r = new ConvertToAutomatedRequest();
        r.setDnsMappings(List.of());

        assertThatThrownBy(() -> service.convertToAutomated(ORG_ID, "cert-1", r))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("at least one domain mapping");
    }

    @Test
    void convert_dnsMappingMissingFields_throws() {
        CertificateEntity c = cert("cert-1", "ACTIVE", "example.com");
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-1", ORG_ID))
                .thenReturn(Optional.of(c));
        ConvertToAutomatedRequest.DnsCredentialMapping m = new ConvertToAutomatedRequest.DnsCredentialMapping();
        m.setDomain("example.com"); // missing credentialXref
        ConvertToAutomatedRequest r = new ConvertToAutomatedRequest();
        r.setDnsMappings(List.of(m));

        assertThatThrownBy(() -> service.convertToAutomated(ORG_ID, "cert-1", r))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("requires domain and credentialXref");
    }

    @Test
    void convert_dnsCredentialWrongType_throws() {
        CertificateEntity c = cert("cert-1", "ACTIVE", "example.com");
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-1", ORG_ID))
                .thenReturn(Optional.of(c));
        when(credentialReferenceService.getByXref(ORG_ID, "cred-dns"))
                .thenReturn(cred("DEPLOYMENT", "ACTIVE")); // wrong type

        assertThatThrownBy(() -> service.convertToAutomated(ORG_ID, "cert-1", reqWithDns("example.com", "cred-dns")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("must be type DNS");
    }

    @Test
    void convert_dnsCredentialInactive_throws() {
        CertificateEntity c = cert("cert-1", "ACTIVE", "example.com");
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-1", ORG_ID))
                .thenReturn(Optional.of(c));
        when(credentialReferenceService.getByXref(ORG_ID, "cred-dns"))
                .thenReturn(cred("DNS", "INACTIVE"));

        assertThatThrownBy(() -> service.convertToAutomated(ORG_ID, "cert-1", reqWithDns("example.com", "cred-dns")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("is not ACTIVE");
    }

    @Test
    void convert_dnsMappingMissingPrimaryRoot_throws() {
        CertificateEntity c = cert("cert-1", "ACTIVE", "example.com");
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-1", ORG_ID))
                .thenReturn(Optional.of(c));
        when(credentialReferenceService.getByXref(ORG_ID, "cred-dns"))
                .thenReturn(cred("DNS", "ACTIVE"));

        // mapping for a different root than primary
        assertThatThrownBy(() -> service.convertToAutomated(ORG_ID, "cert-1", reqWithDns("other.org", "cred-dns")))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("must include a mapping for primary domain");
    }

    @Test
    void convert_blankDeploymentTarget_throws() {
        CertificateEntity c = cert("cert-1", "ACTIVE", "example.com");
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-1", ORG_ID))
                .thenReturn(Optional.of(c));
        when(credentialReferenceService.getByXref(ORG_ID, "cred-dns"))
                .thenReturn(cred("DNS", "ACTIVE"));
        ConvertToAutomatedRequest r = reqWithDns("example.com", "cred-dns");
        r.setDeploymentTargets(List.of("  "));

        assertThatThrownBy(() -> service.convertToAutomated(ORG_ID, "cert-1", r))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("cannot contain blank values");
    }

    @Test
    void convert_deploymentTargetWrongType_throws() {
        CertificateEntity c = cert("cert-1", "ACTIVE", "example.com");
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-1", ORG_ID))
                .thenReturn(Optional.of(c));
        when(credentialReferenceService.getByXref(ORG_ID, "cred-dns"))
                .thenReturn(cred("DNS", "ACTIVE"));
        when(credentialReferenceService.getByXref(ORG_ID, "cred-deploy"))
                .thenReturn(cred("DNS", "ACTIVE")); // wrong type for deployment
        ConvertToAutomatedRequest r = reqWithDns("example.com", "cred-dns");
        r.setDeploymentTargets(List.of("cred-deploy"));

        assertThatThrownBy(() -> service.convertToAutomated(ORG_ID, "cert-1", r))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("must be type DEPLOYMENT");
    }

    @Test
    void convert_inProgressAutomatedStatus_defersConfig() {
        CertificateEntity c = cert("cert-1", "PENDING", "example.com");
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-1", ORG_ID))
                .thenReturn(Optional.of(c));
        when(credentialReferenceService.getByXref(ORG_ID, "cred-dns"))
                .thenReturn(cred("DNS", "ACTIVE"));
        when(domainCredentialConfigRepository.findByUserDomainCertId(UDC_ID)).thenReturn(Optional.empty());
        when(domainCredentialConfigRepository.save(any(DomainCredentialConfigEntity.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        var resp = service.convertToAutomated(ORG_ID, "cert-1", reqWithDns("example.com", "cred-dns"));

        assertThat(resp.get("plannedAction")).isEqualTo("CONFIG_UPDATED_DEFERRED_IN_PROGRESS");
    }
}
