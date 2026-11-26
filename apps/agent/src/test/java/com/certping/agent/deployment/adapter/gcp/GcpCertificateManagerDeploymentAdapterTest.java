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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GcpCertificateManagerDeploymentAdapterTest {

    @Mock private SecretStore secretStore;
    @Mock private GcpCertificateManagerService certificateManagerService;
    @Mock private GcpCloudCredentialResolver credentialResolver;

    private GcpCertificateManagerDeploymentAdapter adapter;

    private static final String SCOPE_JSON =
            "{\"authMode\":\"WORKLOAD_IDENTITY\"," +
            "\"projectId\":\"proj-1\"," +
            "\"location\":\"global\"," +
            "\"certificateMap\":\"cert-map-prod\"}";

    private static final String TARGETS_JSON = "{}";

    @BeforeEach
    void setUp() {
        adapter = new GcpCertificateManagerDeploymentAdapter(
                secretStore, JsonMapper.builderWithJackson2Defaults().build(), certificateManagerService,
                new GcpCertificateMapDeployer(certificateManagerService), credentialResolver);
    }

    @Test
    void deploy_uploadsCert_andCreatesEntriesForUnmatchedHostnames() {
        when(credentialResolver.resolve(any(GcpAuthMode.class), any(GcpAuthScope.class),
                any(GcpAuthSecret.class), anyString()))
                .thenReturn(GoogleCredentials.create(new AccessToken("test", null)));
        when(certificateManagerService.createCertificate(
                eq("proj-1"), eq("global"), anyString(), any(), any()))
                .thenReturn("projects/proj-1/locations/global/certificates/certping-v1");
        // No existing entries on the map yet.
        when(certificateManagerService.listEntriesByHostname(
                eq("proj-1"), eq("global"), eq("cert-map-prod"), any()))
                .thenReturn(Map.of());
        when(certificateManagerService.createMapEntry(
                eq("proj-1"), eq("global"), eq("cert-map-prod"), anyString(),
                anyString(), anyString(), any()))
                .thenReturn("projects/proj-1/locations/global/certificateMaps/cert-map-prod/entries/api-example-com");

        CertificateBundle bundle = bundleWithHostnames(List.of("api.example.com", "*.example.com"));
        DeploymentResult result = adapter.deploy(bundle, buildMessage(SCOPE_JSON, TARGETS_JSON));

        assertThat(result.targetResourceId())
                .isEqualTo("projects/proj-1/locations/global/certificates/certping-v1");
        assertThat(result.configJson()).contains("certificateResourceName");
        assertThat(result.configJson()).contains("cert-map-prod");
        assertThat(result.configJson()).contains("api.example.com");
        assertThat(result.configJson()).contains("*.example.com");

        verify(certificateManagerService, times(2)).createMapEntry(
                anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), any());
        verify(certificateManagerService, never()).updateMapEntryCertificates(
                anyString(), anyString(), any());
    }

    @Test
    void deploy_updatesExistingEntries_forMatchedHostnames() {
        when(credentialResolver.resolve(any(GcpAuthMode.class), any(GcpAuthScope.class),
                any(GcpAuthSecret.class), anyString()))
                .thenReturn(GoogleCredentials.create(new AccessToken("test", null)));
        when(certificateManagerService.createCertificate(
                eq("proj-1"), eq("global"), anyString(), any(), any()))
                .thenReturn("projects/proj-1/locations/global/certificates/certping-v1");
        // api.example.com already has an entry; *.example.com does not.
        Map<String, String> existing = new LinkedHashMap<>();
        existing.put("api.example.com",
                "projects/proj-1/locations/global/certificateMaps/cert-map-prod/entries/operator-named");
        when(certificateManagerService.listEntriesByHostname(
                eq("proj-1"), eq("global"), eq("cert-map-prod"), any()))
                .thenReturn(existing);
        when(certificateManagerService.updateMapEntryCertificates(
                eq("projects/proj-1/locations/global/certificateMaps/cert-map-prod/entries/operator-named"),
                anyString(), any()))
                .thenReturn("projects/proj-1/locations/global/certificateMaps/cert-map-prod/entries/operator-named");
        when(certificateManagerService.createMapEntry(
                eq("proj-1"), eq("global"), eq("cert-map-prod"), anyString(),
                eq("*.example.com"), anyString(), any()))
                .thenReturn("projects/proj-1/locations/global/certificateMaps/cert-map-prod/entries/wildcard-example-com");

        CertificateBundle bundle = bundleWithHostnames(List.of("api.example.com", "*.example.com"));
        DeploymentResult result = adapter.deploy(bundle, buildMessage(SCOPE_JSON, TARGETS_JSON));

        assertThat(result.configJson()).contains("api.example.com");
        assertThat(result.configJson()).contains("*.example.com");

        // One existing entry updated, one new entry created.
        verify(certificateManagerService, times(1)).updateMapEntryCertificates(
                anyString(), anyString(), any());
        verify(certificateManagerService, times(1)).createMapEntry(
                anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), any());
    }

    @Test
    void deploy_certificateMapBlank_uploadsCertOnly_skipsEntries() {
        String scopeNoMap =
                "{\"authMode\":\"WORKLOAD_IDENTITY\"," +
                "\"projectId\":\"proj-1\"," +
                "\"location\":\"global\"}";
        when(credentialResolver.resolve(any(GcpAuthMode.class), any(GcpAuthScope.class),
                any(GcpAuthSecret.class), anyString()))
                .thenReturn(GoogleCredentials.create(new AccessToken("test", null)));
        when(certificateManagerService.createCertificate(
                eq("proj-1"), eq("global"), anyString(), any(), any()))
                .thenReturn("projects/proj-1/locations/global/certificates/certping-v1");

        DeploymentResult result = adapter.deploy(
                bundleWithHostnames(List.of("api.example.com")),
                buildMessage(scopeNoMap, TARGETS_JSON));

        assertThat(result.targetResourceId())
                .isEqualTo("projects/proj-1/locations/global/certificates/certping-v1");
        assertThat(result.configJson()).contains("certificateResourceName");
        assertThat(result.configJson()).doesNotContain("appliedEntries");

        verify(certificateManagerService, never()).listEntriesByHostname(
                anyString(), anyString(), anyString(), any());
        verify(certificateManagerService, never()).createMapEntry(
                anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), any());
    }

    @Test
    void deploy_missingScopeJson_throwsPermanentCredentialInvalid() {
        assertThatThrownBy(() -> adapter.deploy(bundleWithHostnames(List.of("api.example.com")),
                buildMessage(null, TARGETS_JSON)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingProjectId_throwsPermanentCredentialInvalid() {
        String scopeNoProject = SCOPE_JSON.replace("\"projectId\":\"proj-1\",", "");
        assertThatThrownBy(() -> adapter.deploy(
                bundleWithHostnames(List.of("api.example.com")),
                buildMessage(scopeNoProject, TARGETS_JSON)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("projectId");
    }

    @Test
    void deploy_invalidTargetsJson_throwsPermanentTargetsInvalid() {
        assertThatThrownBy(() -> adapter.deploy(bundleWithHostnames(List.of("api.example.com")),
                buildMessage(SCOPE_JSON, "not-json")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_TARGETS_INVALID"));
    }

    @Test
    void deploy_certificateWithoutHostnames_throwsCertInvalid() {
        when(credentialResolver.resolve(any(GcpAuthMode.class), any(GcpAuthScope.class),
                any(GcpAuthSecret.class), anyString()))
                .thenReturn(GoogleCredentials.create(new AccessToken("test", null)));
        when(certificateManagerService.createCertificate(
                eq("proj-1"), eq("global"), anyString(), any(), any()))
                .thenReturn("projects/proj-1/locations/global/certificates/certping-v1");

        // Empty leaf PEM → extractAllHostnames returns empty → cert invalid.
        CertificateBundle bundle = new CertificateBundle("k", "not-a-real-pem", "i", "not-a-real-pem");

        assertThatThrownBy(() -> adapter.deploy(bundle, buildMessage(SCOPE_JSON, TARGETS_JSON)))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CERT_INVALID"));
    }

    @Test
    void deploy_withPriorResult_updatesInPlace_andSkipsCleanup() {
        when(credentialResolver.resolve(any(GcpAuthMode.class), any(GcpAuthScope.class),
                any(GcpAuthSecret.class), anyString()))
                .thenReturn(GoogleCredentials.create(new AccessToken("test", null)));
        when(certificateManagerService.updateCertificate(eq("projects/proj-1/.../certificates/api-prior"),
                any(), any())).thenReturn(true);
        when(certificateManagerService.listEntriesByHostname(
                eq("proj-1"), eq("global"), eq("cert-map-prod"), any()))
                .thenReturn(Map.of());
        when(certificateManagerService.createMapEntry(
                anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), any()))
                .thenReturn("entry-name");

        String priorResult = "{\"certificateResourceName\":\"projects/proj-1/.../certificates/api-prior\"}";
        DeploymentResult result = adapter.deploy(
                bundleWithHostnames(List.of("api.example.com")),
                buildMessage(SCOPE_JSON, TARGETS_JSON, priorResult));

        assertThat(result.targetResourceId())
                .isEqualTo("projects/proj-1/.../certificates/api-prior");
        verify(certificateManagerService, never()).createCertificate(any(), any(), any(), any(), any());
        verify(certificateManagerService, never()).deleteCertificate(any(), any());
    }

    @Test
    void deploy_withPriorResult_updateRejected_fallsBackToCreate_andCleansUp() {
        when(credentialResolver.resolve(any(GcpAuthMode.class), any(GcpAuthScope.class),
                any(GcpAuthSecret.class), anyString()))
                .thenReturn(GoogleCredentials.create(new AccessToken("test", null)));
        when(certificateManagerService.updateCertificate(eq("projects/proj-1/.../certificates/api-prior"),
                any(), any())).thenReturn(false);
        when(certificateManagerService.createCertificate(
                eq("proj-1"), eq("global"), anyString(), any(), any()))
                .thenReturn("projects/proj-1/locations/global/certificates/api-new");
        when(certificateManagerService.listEntriesByHostname(
                eq("proj-1"), eq("global"), eq("cert-map-prod"), any()))
                .thenReturn(Map.of());
        when(certificateManagerService.createMapEntry(
                anyString(), anyString(), anyString(), anyString(), anyString(),
                eq("projects/proj-1/locations/global/certificates/api-new"), any()))
                .thenReturn("entry-name");

        String priorResult = "{\"certificateResourceName\":\"projects/proj-1/.../certificates/api-prior\"}";
        DeploymentResult result = adapter.deploy(
                bundleWithHostnames(List.of("api.example.com")),
                buildMessage(SCOPE_JSON, TARGETS_JSON, priorResult));

        assertThat(result.targetResourceId())
                .isEqualTo("projects/proj-1/locations/global/certificates/api-new");

        org.mockito.InOrder inOrder = org.mockito.Mockito.inOrder(certificateManagerService);
        inOrder.verify(certificateManagerService).updateCertificate(any(), any(), any());
        inOrder.verify(certificateManagerService).createCertificate(any(), any(), any(), any(), any());
        inOrder.verify(certificateManagerService).createMapEntry(
                any(), any(), any(), any(), any(), any(), any());
        inOrder.verify(certificateManagerService).deleteCertificate(
                eq("projects/proj-1/.../certificates/api-prior"), any());
    }

    @Test
    void deploy_operatorSuppliedCertName_usedLiterallyOnFirstDeploy() {
        when(credentialResolver.resolve(any(GcpAuthMode.class), any(GcpAuthScope.class),
                any(GcpAuthSecret.class), anyString()))
                .thenReturn(GoogleCredentials.create(new AccessToken("test", null)));
        when(certificateManagerService.createCertificate(
                eq("proj-1"), eq("global"), eq("my-stable-name"), any(), any()))
                .thenReturn("projects/proj-1/locations/global/certificates/my-stable-name");
        when(certificateManagerService.listEntriesByHostname(
                eq("proj-1"), eq("global"), eq("cert-map-prod"), any()))
                .thenReturn(Map.of());
        when(certificateManagerService.createMapEntry(
                anyString(), anyString(), anyString(), anyString(), anyString(), anyString(), any()))
                .thenReturn("entry");

        DeploymentResult result = adapter.deploy(
                bundleWithHostnames(List.of("api.example.com")),
                buildMessage(SCOPE_JSON, "{\"certificateName\":\"my-stable-name\"}"));

        assertThat(result.targetResourceId())
                .isEqualTo("projects/proj-1/locations/global/certificates/my-stable-name");
        // Verify the literal id (not a versioned `*-yyyyMMddHHmmss`) was passed.
        verify(certificateManagerService).createCertificate(
                eq("proj-1"), eq("global"), eq("my-stable-name"), any(), any());
    }

    @Test
    void validateScope_certificateMapOptional_doesNotThrow() {
        GcpCertManagerScope withMap = new GcpCertManagerScope(
                "WORKLOAD_IDENTITY", "proj-1", "global", null, "cert-map");
        adapter.validateScope(withMap);

        GcpCertManagerScope withoutMap = new GcpCertManagerScope(
                "WORKLOAD_IDENTITY", "proj-1", "global", null, null);
        adapter.validateScope(withoutMap);
    }

    private CertDeploymentMessage buildMessage(String scopeJson, String targetsJson) {
        return buildMessage(scopeJson, targetsJson, null);
    }

    private CertDeploymentMessage buildMessage(String scopeJson, String targetsJson, String priorResultJson) {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setRequestId("req-3");
        msg.setOrganizationId("org-1");
        msg.setCertificateXref("xref-3");
        msg.setDomain("api.example.com");
        msg.setCertSecretHandle("https://kv/secrets/cert-xref-3");
        msg.setTargetType(TargetType.GCP_CERT_MANAGER);
        msg.setCredentialScopeJson(scopeJson);
        msg.setTargetsJson(targetsJson);
        msg.setConfigJson(priorResultJson);
        return msg;
    }

    /**
     * Build a {@link CertificateBundle} whose leaf cert has the given DNS names as SANs
     * (and the first one as the CN). Self-signed, throwaway — only used so
     * {@code CertificateIdentityUtils.extractAllHostnames} can parse a real X.509.
     */
    static CertificateBundle bundleWithHostnames(List<String> hostnames) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            org.bouncycastle.asn1.x500.X500Name issuer =
                    new org.bouncycastle.asn1.x500.X500Name("CN=" + hostnames.get(0));
            java.math.BigInteger serial = java.math.BigInteger.valueOf(System.currentTimeMillis());
            Date notBefore = new Date(System.currentTimeMillis() - 60_000);
            Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

            org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder builder =
                    new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                            issuer, serial, notBefore, notAfter, issuer, kp.getPublic());

            org.bouncycastle.asn1.x509.GeneralName[] sans =
                    hostnames.stream().map(h -> new org.bouncycastle.asn1.x509.GeneralName(
                            org.bouncycastle.asn1.x509.GeneralName.dNSName, h))
                            .toArray(org.bouncycastle.asn1.x509.GeneralName[]::new);
            builder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false,
                    new org.bouncycastle.asn1.x509.GeneralNames(sans));

            org.bouncycastle.operator.ContentSigner signer =
                    new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());

            X509Certificate cert = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                    .getCertificate(builder.build(signer));

            String pem = "-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded())
                    + "\n-----END CERTIFICATE-----\n";
            String keyPem = "-----BEGIN PRIVATE KEY-----\n"
                    + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(kp.getPrivate().getEncoded())
                    + "\n-----END PRIVATE KEY-----\n";

            return new CertificateBundle(keyPem, pem, pem, pem);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
