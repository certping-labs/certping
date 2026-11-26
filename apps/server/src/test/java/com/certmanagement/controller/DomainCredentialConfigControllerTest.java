// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.dto.credconfig.AddDeploymentTargetRequest;
import com.certmanagement.dto.credconfig.EditDeploymentTargetRequest;
import com.certmanagement.dto.credconfig.PatchDnsCredentialRequest;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.cert.DnsCredentialAvailability;
import com.certmanagement.service.cert.DomainCredentialConfigService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DomainCredentialConfigControllerTest {

    @Mock
    private DomainCredentialConfigService configService;

    @Mock
    private FeatureFlagResolver featureFlagResolver;

    @Mock
    private CredentialReferenceRepository credentials;

    private DomainCredentialConfigController controller;

    private static final Long ORG_ID = 77L;

    @BeforeEach
    void setUp() {
        controller = new DomainCredentialConfigController(configService,
                new DnsCredentialAvailability(credentials, featureFlagResolver));
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void patchDnsCredential_forwardsRequestAndReturnsResponse() {
        GatewayRequestContext.set(101, String.valueOf(ORG_ID), "req-1", "user@example.com");
        PatchDnsCredentialRequest request = new PatchDnsCredentialRequest();
        request.setTargetDomain("example.com");
        request.setCredentialXref("cred-dns-1");

        DomainCredentialConfigEntity entity = buildConfig();
        when(configService.patchDnsCredential(ORG_ID, "example.com", "example.com", "cred-dns-1"))
                .thenReturn(entity);
        when(featureFlagResolver.resolveUncached(FeatureFlags.DNS_CREDENTIALS, ORG_ID)).thenReturn(true);

        ResponseEntity<com.certmanagement.dto.credconfig.DomainCredentialConfigResponse> response =
                controller.patchDnsCredential("example.com", request);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getId()).isEqualTo(entity.getId());
        assertThat(response.getBody().getDnsConfig()).isEqualTo(entity.getDnsConfig());
        verify(configService).patchDnsCredential(ORG_ID, "example.com", "example.com", "cred-dns-1");
    }

    @Test
    void patchDnsCredential_whileDnsCredentialsIsOff_isRefusedAndBindsNothing() {
        GatewayRequestContext.set(101, String.valueOf(ORG_ID), "req-1", "user@example.com");
        PatchDnsCredentialRequest request = new PatchDnsCredentialRequest();
        request.setTargetDomain("example.com");
        request.setCredentialXref("cred-dns-1");
        when(featureFlagResolver.resolveUncached(FeatureFlags.DNS_CREDENTIALS, ORG_ID)).thenReturn(false);

        assertThatThrownBy(() -> controller.patchDnsCredential("example.com", request))
                .isInstanceOf(FeatureDisabledException.class)
                .hasMessage("DNS credentials aren't available. Ask your CertPing administrator.")
                .extracting("code", "featureKey").containsExactly("FEATURE_DISABLED", FeatureFlags.DNS_CREDENTIALS);
        verifyNoInteractions(configService);
    }

    @Test
    void patchDnsCredential_toTheOrganizationsCertPingDnsCredentialWhileDnsCredentialsIsOff_goesThrough() {
        GatewayRequestContext.set(101, String.valueOf(ORG_ID), "req-1", "user@example.com");
        PatchDnsCredentialRequest request = new PatchDnsCredentialRequest();
        request.setTargetDomain("example.com");
        request.setCredentialXref("cred-certping");
        when(featureFlagResolver.resolveUncached(FeatureFlags.DNS_CREDENTIALS, ORG_ID)).thenReturn(false);
        when(credentials.findByCredentialXrefIn(Set.of("cred-certping"))).thenReturn(List.of(
                CredentialReferenceEntity.builder().credentialXref("cred-certping").organizationId(ORG_ID)
                        .provider("CERTPING").type("DNS").status("ACTIVE").build()));
        when(configService.patchDnsCredential(ORG_ID, "example.com", "example.com", "cred-certping"))
                .thenReturn(buildConfig());

        assertThat(controller.patchDnsCredential("example.com", request).getStatusCode().is2xxSuccessful()).isTrue();
    }

    @Test
    void addDeploymentTarget_forwardsRequestAndReturnsResponse() {
        GatewayRequestContext.set(101, String.valueOf(ORG_ID), "req-2", "user@example.com");
        AddDeploymentTargetRequest request = new AddDeploymentTargetRequest();
        request.setCredentialXref("cred-deploy-1");

        DomainCredentialConfigEntity entity = buildConfig();
        when(configService.addDeploymentTarget(ORG_ID, "example.com", request)).thenReturn(entity);

        ResponseEntity<com.certmanagement.dto.credconfig.DomainCredentialConfigResponse> response =
                controller.addDeploymentTarget("example.com", request);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getDeploymentTargets()).isEqualTo(entity.getDeploymentTargets());
        verify(configService).addDeploymentTarget(ORG_ID, "example.com", request);
    }

    @Test
    void editDeploymentTarget_forwardsRequestAndReturnsResponse() {
        GatewayRequestContext.set(101, String.valueOf(ORG_ID), "req-3", "user@example.com");
        EditDeploymentTargetRequest request = new EditDeploymentTargetRequest();

        DomainCredentialConfigEntity entity = buildConfig();
        when(configService.editDeploymentTarget(ORG_ID, "example.com", "cred-deploy-1", request))
                .thenReturn(entity);

        ResponseEntity<com.certmanagement.dto.credconfig.DomainCredentialConfigResponse> response =
                controller.editDeploymentTarget("example.com", "cred-deploy-1", request);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getDeploymentTargets()).contains("cred-deploy-1");
        verify(configService).editDeploymentTarget(ORG_ID, "example.com", "cred-deploy-1", request);
    }

    @Test
    void removeDeploymentTarget_forwardsRequestAndReturnsResponse() {
        GatewayRequestContext.set(101, String.valueOf(ORG_ID), "req-4", "user@example.com");

        DomainCredentialConfigEntity entity = buildConfig();
        when(configService.removeDeploymentTarget(ORG_ID, "example.com", "cred-deploy-1"))
                .thenReturn(entity);

        ResponseEntity<com.certmanagement.dto.credconfig.DomainCredentialConfigResponse> response =
                controller.removeDeploymentTarget("example.com", "cred-deploy-1");

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getId()).isEqualTo(entity.getId());
        verify(configService).removeDeploymentTarget(ORG_ID, "example.com", "cred-deploy-1");
    }

    private DomainCredentialConfigEntity buildConfig() {
        return DomainCredentialConfigEntity.builder()
                .id(9L)
                .userDomainCertId(101L)
                .dnsConfig(Map.of("example.com", "cred-dns-1"))
                .deploymentTargets(List.of("cred-deploy-1"))
                .updatedAt(OffsetDateTime.parse("2026-01-01T00:00:00Z"))
                .build();
    }
}
