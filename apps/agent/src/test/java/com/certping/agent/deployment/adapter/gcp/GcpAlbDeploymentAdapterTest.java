// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.DeploymentResult;
import com.certping.agent.deployment.cloud.gcp.GcpAuthMode;
import com.certping.agent.deployment.cloud.gcp.GcpAuthScope;
import com.certping.agent.deployment.cloud.gcp.GcpAuthSecret;
import com.certping.agent.deployment.cloud.gcp.GcpCloudCredentialResolver;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GcpAlbDeploymentAdapterTest {

    @Mock private SecretStore secretStore;
    @Mock private GcpComputeSslCertificateService computeSslCertificateService;
    @Mock private GcpTargetProxyService targetProxyService;
    @Mock private GcpCertificateMapDeployer certificateMapDeployer;
    @Mock private GcpCloudCredentialResolver credentialResolver;

    private GcpAlbDeploymentAdapter adapter;

    private static final String SCOPE_JSON =
            "{\"authMode\":\"WORKLOAD_IDENTITY\"," +
            "\"projectId\":\"proj-1\"," +
            "\"location\":\"global\"," +
            "\"targetProxy\":\"https-proxy-1\"}";

    @BeforeEach
    void setUp() {
        adapter = new GcpAlbDeploymentAdapter(secretStore, JsonMapper.builderWithJackson2Defaults().build(),
                computeSslCertificateService, targetProxyService, certificateMapDeployer, credentialResolver);
    }

    @Test
    void deploy_validScope_uploadsAndUpdatesProxy() {
        when(credentialResolver.resolve(any(GcpAuthMode.class), any(GcpAuthScope.class),
                any(GcpAuthSecret.class), anyString()))
                .thenReturn(GoogleCredentials.create(new AccessToken("test", null)));
        // Target HTTPS Proxies reject Certificate Manager certificate references on
        // setSslCertificates, so this adapter creates native compute SslCertificates — mock returns
        // the canonical full self-link form that GcpComputeSslCertificateService actually emits.
        when(computeSslCertificateService.createSslCertificate(
                eq("proj-1"), eq("global"), anyString(), any(), any()))
                .thenReturn("https://www.googleapis.com/compute/v1/projects/proj-1/global/sslCertificates/certping-api-v1");
        when(targetProxyService.fetchHttpsProxy(any(), any()))
                .thenReturn(noMap(List.of("https://www.googleapis.com/compute/v1/projects/proj-1/global/sslCertificates/old")));

        DeploymentResult result = adapter.deploy(buildBundle(), buildMessage(TargetType.GCP_ALB, SCOPE_JSON));

        assertThat(result.targetResourceId()).contains("https-proxy-1");
        assertThat(result.configJson()).contains("certificateName");
        assertThat(result.configJson()).doesNotContain("mode");
        assertThat(result.configJson()).doesNotContain("appliedProxies");

        ArgumentCaptor<List<String>> certs = ArgumentCaptor.forClass(List.class);
        verify(targetProxyService).applyHttpsProxyCertificates(any(), any(), certs.capture());
        assertThat(certs.getValue())
                .contains("https://www.googleapis.com/compute/v1/projects/proj-1/global/sslCertificates/certping-api-v1");
    }

    @Test
    void deploy_regionalProxy_createsCertificateInProxyRegion() {
        when(credentialResolver.resolve(any(GcpAuthMode.class), any(GcpAuthScope.class),
                any(GcpAuthSecret.class), anyString()))
                .thenReturn(GoogleCredentials.create(new AccessToken("test", null)));
        when(computeSslCertificateService.createSslCertificate(
                eq("proj-1"), eq("us-central1"), anyString(), any(), any()))
                .thenReturn("https://www.googleapis.com/compute/v1/projects/proj-1/regions/us-central1/sslCertificates/api-new");
        when(targetProxyService.fetchHttpsProxy(any(), any())).thenReturn(noMap(List.of()));

        String regionalScope = SCOPE_JSON.replace("\"location\":\"global\"", "\"location\":\"us-central1\"");
        adapter.deploy(buildBundle(), buildMessage(TargetType.GCP_ALB, regionalScope));

        ArgumentCaptor<List<String>> certs = ArgumentCaptor.forClass(List.class);
        verify(targetProxyService).applyHttpsProxyCertificates(any(), any(), certs.capture());
        assertThat(certs.getValue()).containsExactly(
                "https://www.googleapis.com/compute/v1/projects/proj-1/regions/us-central1/sslCertificates/api-new");
    }

    @Test
    void deploy_gcpCloudCdn_usesSameAlbPath() {
        when(credentialResolver.resolve(any(GcpAuthMode.class), any(GcpAuthScope.class),
                any(GcpAuthSecret.class), anyString()))
                .thenReturn(GoogleCredentials.create(new AccessToken("test", null)));
        when(computeSslCertificateService.createSslCertificate(any(), anyString(), anyString(), any(), any()))
                .thenReturn("https://www.googleapis.com/compute/v1/projects/proj-1/global/sslCertificates/cert-cdn");
        when(targetProxyService.fetchHttpsProxy(any(), any())).thenReturn(noMap(List.of()));

        DeploymentResult result = adapter.deploy(buildBundle(), buildMessage(TargetType.GCP_CLOUD_CDN, SCOPE_JSON));

        assertThat(result.targetResourceId()).isNotBlank();
    }

    @Test
    void deploy_gcpApiGateway_usesSameAlbAdapterPath() {
        when(credentialResolver.resolve(any(GcpAuthMode.class), any(GcpAuthScope.class),
                any(GcpAuthSecret.class), anyString()))
                .thenReturn(GoogleCredentials.create(new AccessToken("test", null)));
        when(computeSslCertificateService.createSslCertificate(any(), anyString(), anyString(), any(), any()))
                .thenReturn("https://www.googleapis.com/compute/v1/projects/proj-1/global/sslCertificates/cert-gw");
        when(targetProxyService.fetchHttpsProxy(any(), any())).thenReturn(noMap(List.of()));

        DeploymentResult result = adapter.deploy(buildBundle(), buildMessage(TargetType.GCP_API_GW, SCOPE_JSON));

        assertThat(result.targetResourceId()).isNotBlank();
    }

    @Test
    void deploy_missingScopeJson_throwsPermanentCredentialInvalid() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage(TargetType.GCP_ALB, null)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingTargetProxy_throwsPermanentCredentialInvalid() {
        String scopeNoProxy = SCOPE_JSON.replace("\"targetProxy\":\"https-proxy-1\"", "\"targetProxy\":\"\"");
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage(TargetType.GCP_ALB, scopeNoProxy)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("targetProxy");
    }

    @Test
    void deploy_withPriorResult_createsNewAndCleansUpAfterProxy() {
        // Compute SslCertificate is immutable — there is no in-place update path. Every deploy
        // creates a fresh versioned resource, swaps it onto the Target HTTPS Proxy, then deletes
        // the prior resource (cleanup after the swap so the proxy is never left referencing a
        // missing cert mid-deploy).
        when(credentialResolver.resolve(any(GcpAuthMode.class), any(GcpAuthScope.class),
                any(GcpAuthSecret.class), anyString()))
                .thenReturn(GoogleCredentials.create(new AccessToken("test", null)));
        when(computeSslCertificateService.createSslCertificate(any(), anyString(), anyString(), any(), any()))
                .thenReturn("https://www.googleapis.com/compute/v1/projects/proj-1/global/sslCertificates/api-new");
        when(targetProxyService.fetchHttpsProxy(any(), any()))
                .thenReturn(noMap(List.of(
                        "https://www.googleapis.com/compute/v1/projects/proj-1/global/sslCertificates/api-prior",
                        "https://www.googleapis.com/compute/v1/projects/proj-1/global/sslCertificates/other")));

        String priorResult = "{\"certificateName\":\"https://www.googleapis.com/compute/v1/projects/proj-1/global/sslCertificates/api-prior\"}";
        adapter.deploy(buildBundle(), buildMessage(TargetType.GCP_ALB, SCOPE_JSON, priorResult));

        // The proxy list applied should contain the new resource and the unrelated cert,
        // but NOT the prior resource (we're about to delete it).
        ArgumentCaptor<List<String>> certs = ArgumentCaptor.forClass(List.class);
        verify(targetProxyService).applyHttpsProxyCertificates(any(), any(), certs.capture());
        assertThat(certs.getValue())
                .contains("https://www.googleapis.com/compute/v1/projects/proj-1/global/sslCertificates/api-new")
                .contains("https://www.googleapis.com/compute/v1/projects/proj-1/global/sslCertificates/other")
                .doesNotContain("https://www.googleapis.com/compute/v1/projects/proj-1/global/sslCertificates/api-prior");

        // Strict ordering: create → re-read proxy → swap on proxy → delete prior. The re-read keeps
        // the read-modify-write window short; reversing the last two would leave the proxy briefly
        // pointing at a deleted resource.
        org.mockito.InOrder inOrder = org.mockito.Mockito.inOrder(
                computeSslCertificateService, targetProxyService);
        inOrder.verify(computeSslCertificateService).createSslCertificate(any(), anyString(), anyString(), any(), any());
        inOrder.verify(targetProxyService).fetchHttpsProxy(any(), any());
        inOrder.verify(targetProxyService).applyHttpsProxyCertificates(any(), any(), any());
        inOrder.verify(computeSslCertificateService).deleteSslCertificate(
                eq("https://www.googleapis.com/compute/v1/projects/proj-1/global/sslCertificates/api-prior"), any());
    }

    @Test
    void deploy_prunesAllStaleLineageVersionsFromSharedProxy() {
        // A proxy shared by many certs accumulates stale versions of THIS cert's lineage plus other
        // domains' certs. Every stale sibling of this lineage must be detached AND deleted; other
        // domains must be left untouched — even with no prior tracked in configJson.
        String prefix = "https://www.googleapis.com/compute/v1/projects/proj-1/global/sslCertificates/";
        String base = GcpNameUtils.deriveBaseName("api.example.com", "xref-1");
        String staleA = prefix + base + "-20260101010101";
        String staleB = prefix + base + "-20260202020202";
        String otherDomain = prefix + "example-project-20260617220126";

        when(credentialResolver.resolve(any(GcpAuthMode.class), any(GcpAuthScope.class),
                any(GcpAuthSecret.class), anyString()))
                .thenReturn(GoogleCredentials.create(new AccessToken("test", null)));
        when(computeSslCertificateService.createSslCertificate(any(), anyString(), anyString(), any(), any()))
                .thenReturn(prefix + "api-new");
        when(targetProxyService.fetchHttpsProxy(any(), any()))
                .thenReturn(noMap(List.of(staleA, staleB, otherDomain)));

        // No prior result — the single-prior path would leave both stale versions behind.
        adapter.deploy(buildBundle(), buildMessage(TargetType.GCP_ALB, SCOPE_JSON, null));

        ArgumentCaptor<List<String>> certs = ArgumentCaptor.forClass(List.class);
        verify(targetProxyService).applyHttpsProxyCertificates(any(), any(), certs.capture());
        assertThat(certs.getValue())
                .containsExactlyInAnyOrder(prefix + "api-new", otherDomain);

        verify(computeSslCertificateService).deleteSslCertificate(eq(staleA), any());
        verify(computeSslCertificateService).deleteSslCertificate(eq(staleB), any());
        verify(computeSslCertificateService, never()).deleteSslCertificate(eq(otherDomain), any());
    }

    @Test
    void deploy_proxyReadFails_createsNoCertificate() {
        when(credentialResolver.resolve(any(GcpAuthMode.class), any(GcpAuthScope.class),
                any(GcpAuthSecret.class), anyString()))
                .thenReturn(GoogleCredentials.create(new AccessToken("test", null)));
        when(targetProxyService.fetchHttpsProxy(any(), any()))
                .thenThrow(new PermanentAgentException("DEPLOY_GCP_PROXY_FAILED", "not found"));

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage(TargetType.GCP_ALB, SCOPE_JSON)))
                .isInstanceOf(PermanentAgentException.class)
                .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_GCP_PROXY_FAILED");
        verifyNoInteractions(computeSslCertificateService, certificateMapDeployer);
    }

    @Test
    void deploy_proxyWithCertificateMap_deploysIntoTheMapNotSslCertificates() {
        String map = "//certificatemanager.googleapis.com/projects/proj-1/locations/global/certificateMaps/m";
        String prior = "projects/proj-1/locations/global/certificates/api-prior";
        when(credentialResolver.resolve(any(GcpAuthMode.class), any(GcpAuthScope.class),
                any(GcpAuthSecret.class), anyString()))
                .thenReturn(GoogleCredentials.create(new AccessToken("test", null)));
        when(targetProxyService.fetchHttpsProxy(any(), any())).thenReturn(new GcpTargetProxyState(List.of(), map));
        when(certificateMapDeployer.deployToProxyMap(eq(map), anyString(), eq(prior), any(), any()))
                .thenReturn(new GcpCertificateMapDeployer.MapDeployment(
                        "projects/proj-1/locations/global/certificates/api-new",
                        "projects/proj-1/locations/global/certificateMaps/m",
                        List.of(new GcpCertificateMapDeployer.AppliedEntry(
                                "api.example.com", "projects/proj-1/locations/global/certificateMaps/m/certificateMapEntries/e", "updated"))));

        DeploymentResult result = adapter.deploy(buildBundle(), buildMessage(TargetType.GCP_ALB, SCOPE_JSON,
                "{\"certificateName\":\"" + prior + "\"}"));

        assertThat(result.configJson())
                .contains("\"certificateName\":\"projects/proj-1/locations/global/certificates/api-new\"")
                .contains("\"certificateMap\":\"projects/proj-1/locations/global/certificateMaps/m\"")
                .contains("api.example.com");
        verifyNoInteractions(computeSslCertificateService);
        verify(targetProxyService, never()).applyHttpsProxyCertificates(any(), any(), any());
    }

    @Test
    void deploy_priorFromDetachedMap_isNotPrunedAsComputeCertificate() {
        String priorCm = "projects/proj-1/locations/global/certificates/api-prior";
        when(credentialResolver.resolve(any(GcpAuthMode.class), any(GcpAuthScope.class),
                any(GcpAuthSecret.class), anyString()))
                .thenReturn(GoogleCredentials.create(new AccessToken("test", null)));
        when(computeSslCertificateService.createSslCertificate(any(), anyString(), anyString(), any(), any()))
                .thenReturn("https://www.googleapis.com/compute/v1/projects/proj-1/global/sslCertificates/api-new");
        when(targetProxyService.fetchHttpsProxy(any(), any())).thenReturn(noMap(List.of()));

        adapter.deploy(buildBundle(), buildMessage(TargetType.GCP_ALB, SCOPE_JSON,
                "{\"certificateName\":\"" + priorCm + "\"}"));

        verify(computeSslCertificateService, never()).deleteSslCertificate(eq(priorCm), any());
    }

    @Test
    void deploy_proxyUpdateFails_deletesNewCertificateAndKeepsTheError() {
        String prior = "https://www.googleapis.com/compute/v1/projects/proj-1/global/sslCertificates/api-prior";
        String created = "https://www.googleapis.com/compute/v1/projects/proj-1/global/sslCertificates/api-new";
        when(credentialResolver.resolve(any(GcpAuthMode.class), any(GcpAuthScope.class),
                any(GcpAuthSecret.class), anyString()))
                .thenReturn(GoogleCredentials.create(new AccessToken("test", null)));
        when(computeSslCertificateService.createSslCertificate(any(), anyString(), anyString(), any(), any()))
                .thenReturn(created);
        when(targetProxyService.fetchHttpsProxy(any(), any())).thenReturn(noMap(List.of(prior)));
        PermanentAgentException failure = new PermanentAgentException("DEPLOY_GCP_PROXY_FAILED", "rejected");
        doThrow(failure).when(targetProxyService).applyHttpsProxyCertificates(any(), any(), any());

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage(TargetType.GCP_ALB, SCOPE_JSON, "{\"certificateName\":\"" + prior + "\"}")))
                .isSameAs(failure);
        verify(computeSslCertificateService).deleteSslCertificate(eq(created), any());
        verify(computeSslCertificateService, never()).deleteSslCertificate(eq(prior), any());
    }

    @Test
    void validateScope_allFieldsPresent_doesNotThrow() {
        GcpProxyScope scope = new GcpProxyScope(
                "WORKLOAD_IDENTITY", "proj-1", "global", null,
                "https-proxy-1", null);
        adapter.validateScope(scope, "GCP ALB");
    }

    private CertDeploymentMessage buildMessage(TargetType type, String scopeJson) {
        return buildMessage(type, scopeJson, null);
    }

    private CertDeploymentMessage buildMessage(TargetType type, String scopeJson, String priorResultJson) {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setRequestId("req-1");
        msg.setOrganizationId("org-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("api.example.com");
        msg.setCertSecretHandle("https://kv/secrets/cert-xref-1");
        msg.setTargetType(type);
        msg.setCredentialScopeJson(scopeJson);
        msg.setTargetsJson("{}");
        msg.setConfigJson(priorResultJson);
        return msg;
    }

    private CertificateBundle buildBundle() {
        return new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg==\n-----END PRIVATE KEY-----",
                "-----BEGIN CERTIFICATE-----\nMIILeaf==\n-----END CERTIFICATE-----",
                "-----BEGIN CERTIFICATE-----\nMIIIntermediate==\n-----END CERTIFICATE-----",
                """
                -----BEGIN CERTIFICATE-----
                MIILeaf==
                -----END CERTIFICATE-----
                -----BEGIN CERTIFICATE-----
                MIIIntermediate==
                -----END CERTIFICATE-----"""
        );
    }

    private static GcpTargetProxyState noMap(List<String> sslCertificates) {
        return new GcpTargetProxyState(sslCertificates, null);
    }
}
