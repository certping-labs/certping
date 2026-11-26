// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.dto.cert.ConvertToAutomatedRequest;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.repository.CertManualIssuanceStateRepository;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.DeploymentRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.service.OrgTypeResolver;
import com.certmanagement.service.deployment.CertDeploymentConfigService;
import com.certmanagement.service.deployment.KubernetesDeploymentConfigResolver;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.context.ApplicationEventPublisher;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Clear-first on the certificate create paths: a new issuance and a conversion to automated take
 * their feature locks before writing anything and are refused (423) when a feature they need is off.
 */
class CertCreatePathFeatureLockTest {


    private static final long ORG = 1L;
    private static final long UDC = 2L;

    private final CertificateRepository certificates = mock(CertificateRepository.class);
    private final DomainCredentialConfigRepository credConfigs = mock(DomainCredentialConfigRepository.class);
    private final RenewalScheduleRepository schedules = mock(RenewalScheduleRepository.class);
    private final CertificateFeatureLocks featureLocks = mock(CertificateFeatureLocks.class);

    @Test
    void issuance_locksRenewalTooButRequiresOnlyIssuanceTheCaAndDeployment() {
        CertPersistenceService persistence = persistence();
        when(credConfigs.findByUserDomainCertId(UDC)).thenReturn(Optional.empty());
        when(credConfigs.save(any())).thenAnswer(call -> call.getArgument(0));

        persistence.persistIssuance(certificate("PENDING"), config(List.of("cred-kv")), new RenewalScheduleEntity(),
                "req-1", "corr-1");

        InOrder order = inOrder(featureLocks, credConfigs, certificates);
        order.verify(featureLocks).lockAndRequire(ORG,
                List.of("CERTIFICATE_ISSUANCE", "LETS_ENCRYPT", "CERTIFICATE_DEPLOYMENT"),
                List.of("CERTIFICATE_RENEWAL"), CertPersistenceService.DEPLOYMENT_OFF_MESSAGE);
        order.verify(credConfigs).findByUserDomainCertId(UDC);
        order.verify(certificates).save(any());
    }

    @Test
    void issuance_refusedWhileDeploymentIsOff_writesNothing() {
        CertPersistenceService persistence = persistence();
        doThrow(new FeatureDisabledException("CERTIFICATE_DEPLOYMENT", "FEATURE_DISABLED",
                CertPersistenceService.DEPLOYMENT_OFF_MESSAGE))
                .when(featureLocks).lockAndRequire(anyLong(), anyList(), anyList(), anyString());

        assertThatThrownBy(() -> persistence.persistIssuance(certificate("PENDING"), config(List.of("cred-kv")),
                new RenewalScheduleEntity(), "req-1", "corr-1"))
                .isInstanceOf(FeatureDisabledException.class)
                .hasMessage(CertPersistenceService.DEPLOYMENT_OFF_MESSAGE);
        verifyNoInteractions(credConfigs, schedules);
    }


    @Test
    void conversion_locksBeforeAnyRowLockOrWrite_andIsRefusedWhenRenewalIsOff() {
        CertConversionService conversion = conversion();
        when(certificates.findByCertificateXrefAndOrganizationId("cert-1", ORG))
                .thenReturn(Optional.of(certificate("ACTIVE")));
        doThrow(new FeatureDisabledException("CERTIFICATE_RENEWAL"))
                .when(featureLocks).lockAndRequire(anyLong(), anyList(), anyList(), anyString());

        assertThatThrownBy(() -> conversion.convertToAutomated(ORG, "cert-1", request(List.of("cred-kv"))))
                .isInstanceOf(FeatureDisabledException.class);

        InOrder order = inOrder(certificates, featureLocks);
        order.verify(certificates).findByCertificateXrefAndOrganizationId("cert-1", ORG);
        order.verify(featureLocks).lockAndRequire(ORG,
                List.of("CERTIFICATE_RENEWAL", "LETS_ENCRYPT", "CERTIFICATE_DEPLOYMENT"),
                List.of("CERTIFICATE_ISSUANCE"), CertConversionService.DEPLOYMENT_OFF_MESSAGE);
        verifyNoInteractions(credConfigs, schedules);
    }

    @Test
    void conversion_withoutTargets_doesNotNeedDeployment() {
        CertConversionService conversion = conversion();
        when(certificates.findByCertificateXrefAndOrganizationId("cert-1", ORG))
                .thenReturn(Optional.of(certificate("ACTIVE")));
        doThrow(new IllegalStateException("stop after the lock"))
                .when(featureLocks).lockAndRequire(anyLong(), anyList(), anyList(), anyString());

        assertThatThrownBy(() -> conversion.convertToAutomated(ORG, "cert-1", request(List.of())))
                .hasMessage("stop after the lock");
        org.mockito.Mockito.verify(featureLocks).lockAndRequire(ORG, List.of("CERTIFICATE_RENEWAL", "LETS_ENCRYPT"),
                List.of("CERTIFICATE_ISSUANCE"), CertConversionService.DEPLOYMENT_OFF_MESSAGE);
    }

    private CertPersistenceService persistence() {
        return new CertPersistenceService(certificates, mock(CertificateEventRepository.class), schedules,
                mock(DeploymentRepository.class), credConfigs, mock(CertManualIssuanceStateRepository.class),
                JsonMapper.builderWithJackson2Defaults().build(), mock(OrgTypeResolver.class),
                mock(ApplicationEventPublisher.class), featureLocks, org.mockito.Mockito.mock(com.certmanagement.service.audit.CertificateAuditRecorder.class));
    }

    private CertConversionService conversion() {
        return new CertConversionService(certificates, credConfigs, schedules,
                mock(CertManualIssuanceStateRepository.class), mock(CertificateEventRepository.class),
                mock(CredentialReferenceService.class), mock(CertIssuanceService.class),
                new CertificateStatusValidator(), mock(CertDeploymentConfigService.class),
                mock(KubernetesDeploymentConfigResolver.class), JsonMapper.builderWithJackson2Defaults().build(), featureLocks, org.mockito.Mockito.mock(com.certmanagement.service.audit.CertificateAuditRecorder.class));
    }

    private static CertificateEntity certificate(String status) {
        UserDomainCertEntity udc = UserDomainCertEntity.builder().id(UDC).organizationId(ORG)
                .domain("example.com").build();
        return CertificateEntity.builder().certificateXref("cert-1").userDomainCertId(UDC).userDomainCert(udc)
                .caProvider(CaProvider.LETS_ENCRYPT).status(status).build();
    }

    private static DomainCredentialConfigEntity config(List<String> targets) {
        return DomainCredentialConfigEntity.builder().userDomainCertId(UDC)
                .dnsConfig(Map.of("example.com", "cred-dns")).deploymentTargets(targets).build();
    }

    private static ConvertToAutomatedRequest request(List<String> targets) {
        ConvertToAutomatedRequest.DnsCredentialMapping mapping = new ConvertToAutomatedRequest.DnsCredentialMapping();
        mapping.setDomain("example.com");
        mapping.setCredentialXref("cred-dns-1");
        ConvertToAutomatedRequest request = new ConvertToAutomatedRequest();
        request.setDnsMappings(List.of(mapping));
        request.setDeploymentTargets(targets);
        return request;
    }
}
