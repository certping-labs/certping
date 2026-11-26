// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.exception.PermanentAgentException;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GcpCertificateMapDeployerTest {

    private static final String PROXY_MAP =
            "//certificatemanager.googleapis.com/projects/map-proj/locations/global/certificateMaps/m";
    private static final String PRIOR = "projects/map-proj/locations/global/certificates/api-prior";
    private static final String CREATED = "projects/map-proj/locations/global/certificates/api-new";
    private static final String ENTRY = "projects/map-proj/locations/global/certificateMaps/m/certificateMapEntries/api";

    @Mock private GcpCertificateManagerService certificateManagerService;

    private GcpCertificateMapDeployer deployer;
    private final GoogleCredentials credentials = GoogleCredentials.create(new AccessToken("test", null));
    private final CertificateBundle bundle =
            GcpCertificateManagerDeploymentAdapterTest.bundleWithHostnames(List.of("api.example.com", "www.example.com"));

    @BeforeEach
    void setUp() {
        deployer = new GcpCertificateMapDeployer(certificateManagerService);
    }

    @Test
    void firstDeploy_createsCertificateInTheMapsProjectAndRepointsEntries() {
        when(certificateManagerService.createCertificate(eq("map-proj"), eq("global"), anyString(), any(), any()))
                .thenReturn(CREATED);
        when(certificateManagerService.listEntriesByHostname("map-proj", "global", "m", credentials))
                .thenReturn(Map.of("api.example.com", ENTRY));
        when(certificateManagerService.updateMapEntryCertificates(ENTRY, CREATED, credentials)).thenReturn(ENTRY);
        when(certificateManagerService.createMapEntry(eq("map-proj"), eq("global"), eq("m"), anyString(),
                eq("www.example.com"), eq(CREATED), any())).thenReturn(ENTRY + "-www");

        GcpCertificateMapDeployer.MapDeployment result =
                deployer.deployToProxyMap(PROXY_MAP, "api-example-com", null, bundle, credentials);

        assertThat(result.certificateResourceName()).isEqualTo(CREATED);
        assertThat(result.certificateMap()).isEqualTo("projects/map-proj/locations/global/certificateMaps/m");
        assertThat(result.appliedEntries()).extracting(GcpCertificateMapDeployer.AppliedEntry::action)
                .containsExactly("updated", "created");
        verify(certificateManagerService, never()).deleteCertificate(anyString(), any());
    }

    @Test
    void renewalWithSameNames_updatesPriorInPlace() {
        when(certificateManagerService.updateCertificate(PRIOR, bundle, credentials)).thenReturn(true);
        when(certificateManagerService.listEntriesByHostname("map-proj", "global", "m", credentials))
                .thenReturn(Map.of("api.example.com", ENTRY, "www.example.com", ENTRY + "-www"));
        when(certificateManagerService.updateMapEntryCertificates(anyString(), eq(PRIOR), any())).thenReturn(ENTRY);

        GcpCertificateMapDeployer.MapDeployment result =
                deployer.deployToProxyMap(PROXY_MAP, "api-example-com", PRIOR, bundle, credentials);

        assertThat(result.certificateResourceName()).isEqualTo(PRIOR);
        verify(certificateManagerService, never()).createCertificate(any(), any(), any(), any(), any());
        verify(certificateManagerService, never()).deleteCertificate(anyString(), any());
    }

    @Test
    void renewalGcpCannotUpdate_createsNewAndDeletesPriorAfterEntriesMove() {
        when(certificateManagerService.updateCertificate(PRIOR, bundle, credentials)).thenReturn(false);
        when(certificateManagerService.createCertificate(eq("map-proj"), eq("global"), anyString(), any(), any()))
                .thenReturn(CREATED);
        when(certificateManagerService.listEntriesByHostname("map-proj", "global", "m", credentials))
                .thenReturn(Map.of("api.example.com", ENTRY, "www.example.com", ENTRY + "-www"));
        when(certificateManagerService.updateMapEntryCertificates(anyString(), eq(CREATED), any())).thenReturn(ENTRY);

        deployer.deployToProxyMap(PROXY_MAP, "api-example-com", PRIOR, bundle, credentials);

        org.mockito.InOrder inOrder = org.mockito.Mockito.inOrder(certificateManagerService);
        inOrder.verify(certificateManagerService).createCertificate(any(), any(), any(), any(), any());
        inOrder.verify(certificateManagerService, org.mockito.Mockito.times(2))
                .updateMapEntryCertificates(anyString(), eq(CREATED), any());
        inOrder.verify(certificateManagerService).deleteCertificate(PRIOR, credentials);
    }

    @Test
    void entryUpdateFails_deletesTheNewCertificateAndKeepsPrior() {
        when(certificateManagerService.updateCertificate(PRIOR, bundle, credentials)).thenReturn(false);
        when(certificateManagerService.createCertificate(any(), any(), any(), any(), any())).thenReturn(CREATED);
        PermanentAgentException failure = new PermanentAgentException("DEPLOY_GCP_CERT_MAP_ENTRY_FAILED", "denied");
        when(certificateManagerService.listEntriesByHostname(any(), any(), any(), any())).thenThrow(failure);

        assertThatThrownBy(() -> deployer.deployToProxyMap(PROXY_MAP, "api-example-com", PRIOR, bundle, credentials))
                .isSameAs(failure);
        verify(certificateManagerService).deleteCertificate(CREATED, credentials);
        verify(certificateManagerService, never()).deleteCertificate(PRIOR, credentials);
    }

    @Test
    void priorComputeCertificate_isNeitherUpdatedNorDeleted() {
        String computePrior = "https://www.googleapis.com/compute/v1/projects/p/global/sslCertificates/api-prior";
        when(certificateManagerService.createCertificate(any(), any(), any(), any(), any())).thenReturn(CREATED);
        when(certificateManagerService.listEntriesByHostname(any(), any(), any(), any())).thenReturn(Map.of());
        when(certificateManagerService.createMapEntry(any(), any(), any(), any(), any(), any(), any())).thenReturn(ENTRY);

        deployer.deployToProxyMap(PROXY_MAP, "api-example-com", computePrior, bundle, credentials);

        verify(certificateManagerService, never()).updateCertificate(any(), any(), any());
        verify(certificateManagerService, never()).deleteCertificate(anyString(), any());
    }

    @Test
    void unrecognisedMapReference_failsBeforeAnyCall() {
        assertThatThrownBy(() -> deployer.deployToProxyMap("not-a-map", "base", null, bundle, credentials))
                .isInstanceOf(PermanentAgentException.class)
                .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_GCP_PROXY_FAILED");
        verifyNoInteractions(certificateManagerService);
    }

    @Test
    void apexAndWildcard_getDistinctEntryIds() {
        CertificateBundle apexAndWildcard =
                GcpCertificateManagerDeploymentAdapterTest.bundleWithHostnames(List.of("example.com", "*.example.com"));
        when(certificateManagerService.createCertificate(any(), any(), any(), any(), any())).thenReturn(CREATED);
        when(certificateManagerService.listEntriesByHostname(any(), any(), any(), any())).thenReturn(Map.of());
        when(certificateManagerService.createMapEntry(any(), any(), any(), anyString(), anyString(), any(), any()))
                .thenReturn(ENTRY);

        deployer.deployToProxyMap(PROXY_MAP, "example-com", null, apexAndWildcard, credentials);

        verify(certificateManagerService).createMapEntry(eq("map-proj"), eq("global"), eq("m"), eq("example-com"),
                eq("example.com"), eq(CREATED), any());
        verify(certificateManagerService).createMapEntry(eq("map-proj"), eq("global"), eq("m"), eq("wildcard-example-com"),
                eq("*.example.com"), eq(CREATED), any());
    }
}
