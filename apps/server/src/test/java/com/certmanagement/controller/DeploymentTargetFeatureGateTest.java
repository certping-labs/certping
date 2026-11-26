// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.aspect.FeatureGatedAspect;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.dto.credconfig.AddDeploymentTargetRequest;
import com.certmanagement.dto.credconfig.EditDeploymentTargetRequest;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.exception.GlobalExceptionHandler;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.cert.CredentialReferenceService;
import com.certmanagement.service.cert.DnsCredentialAvailability;
import com.certmanagement.service.cert.DomainCredentialConfigService;
import com.certmanagement.service.deployment.CertDeploymentConfigService;
import com.certmanagement.service.lifecycle.FeatureLifecycleLock;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Adding and editing a deployment target need CERTIFICATE_DEPLOYMENT on, checked by the cached
 * {@code @FeatureGated} and again under the lifecycle lock; removing one never does, so targets can
 * still be cleared.
 */
class DeploymentTargetFeatureGateTest {

    private static final long ORG_ID = 77L;
    private static final String DOMAIN = "example.com";
    private static final String CRED_XREF = "cred-deploy-1";

    private final DomainCredentialConfigService configService = mock(DomainCredentialConfigService.class);
    private final FeatureFlagService featureFlagService = mock(FeatureFlagService.class);
    private DomainCredentialConfigController gated;

    @BeforeEach
    void setUp() {
        GatewayRequestContext.set(101, String.valueOf(ORG_ID), "req-1", "user@example.com");
        doThrow(new FeatureDisabledException(FeatureFlags.CERTIFICATE_DEPLOYMENT))
                .when(featureFlagService).assertEnabled(FeatureFlags.CERTIFICATE_DEPLOYMENT, ORG_ID);
        AspectJProxyFactory factory = new AspectJProxyFactory(new DomainCredentialConfigController(configService,
                mock(DnsCredentialAvailability.class)));
        factory.setProxyTargetClass(true);
        factory.addAspect(new FeatureGatedAspect(featureFlagService));
        gated = factory.getProxy();
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void addAndEdit_areRefusedWhileDeploymentIsOff() {
        assertThatThrownBy(() -> gated.addDeploymentTarget(DOMAIN, new AddDeploymentTargetRequest()))
                .isInstanceOf(FeatureDisabledException.class);
        assertThatThrownBy(() -> gated.editDeploymentTarget(DOMAIN, CRED_XREF, new EditDeploymentTargetRequest()))
                .isInstanceOf(FeatureDisabledException.class);
        verifyNoInteractions(configService);
    }

    @Test
    void remove_staysOpenWhileDeploymentIsOff() {
        when(configService.removeDeploymentTarget(ORG_ID, DOMAIN, CRED_XREF)).thenReturn(config());

        gated.removeDeploymentTarget(DOMAIN, CRED_XREF);

        verify(configService).removeDeploymentTarget(ORG_ID, DOMAIN, CRED_XREF);
    }

    /** The flag cache still said on, but a switch-off committed while the edit waited for the lock. */
    @Test
    void edit_afterASwitchOffTheCacheHasNotSeen_is423WithNothingRead() throws Exception {
        FeatureLifecycleLock lock = mock(FeatureLifecycleLock.class);
        doThrow(new FeatureDisabledException(FeatureFlags.CERTIFICATE_DEPLOYMENT))
                .when(lock).lockAndAssertEnabled(ORG_ID, FeatureFlags.CERTIFICATE_DEPLOYMENT);
        CredentialReferenceService credentials = mock(CredentialReferenceService.class);
        DomainCredentialConfigRepository configs = mock(DomainCredentialConfigRepository.class);
        CertDeploymentConfigService deploymentConfigs = mock(CertDeploymentConfigService.class);
        DomainCredentialConfigService service = new DomainCredentialConfigService(configs,
                mock(UserDomainCertRepository.class), credentials, deploymentConfigs,
                mock(RenewalScheduleRepository.class), lock,
                mock(com.certmanagement.repository.CredentialReferenceRepository.class),
                mock(com.certmanagement.service.audit.CredentialAuditRecorder.class));
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new DomainCredentialConfigController(service,
                mock(DnsCredentialAvailability.class)))
                .setControllerAdvice(new GlobalExceptionHandler(JsonMapper.builderWithJackson2Defaults().build()))
                .build();

        mvc.perform(put("/api/v1/certs/domains/{domain}/credential-config/deployment-targets/{xref}", DOMAIN, CRED_XREF)
                        .contentType(MediaType.APPLICATION_JSON).accept(MediaType.APPLICATION_JSON)
                        .content("{\"targets\":{\"vaults\":[]}}"))
                .andExpect(status().is(423))
                .andExpect(jsonPath("$.feature").value(FeatureFlags.CERTIFICATE_DEPLOYMENT));

        verifyNoInteractions(credentials, configs, deploymentConfigs);
    }

    private static DomainCredentialConfigEntity config() {
        return DomainCredentialConfigEntity.builder().id(1L).userDomainCertId(2L)
                .dnsConfig(Map.of()).deploymentTargets(List.of()).build();
    }
}
