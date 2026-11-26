// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.cloudflare;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.test.util.ReflectionTestUtils;

import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CloudflareEdgeDeploymentAdapterTest {

    @Mock private SecretStore secretStore;

    private CloudflareEdgeDeploymentAdapter adapter;

    private static final String SCOPE_JSON =
            "{\"zoneId\":\"zone-abc\"," +
            "\"bundleMethod\":\"ubiquitous\"," +
            "\"certType\":\"sni_custom\"}";

    @BeforeEach
    void setUp() {
        adapter = new CloudflareEdgeDeploymentAdapter(secretStore, JsonMapper.builderWithJackson2Defaults().build());
    }

    @Test
    void deploy_readsCredentialFromKv_evenWhenJsonInvalid() {
        when(secretStore.read(anyString())).thenReturn("not-valid-json");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class);

        verify(secretStore).read("https://kv-agent.vault.azure.net/secrets/cf-edge-cred");
    }

    @Test
    void deploy_invalidCredentialJson_throwsPermanentCredentialInvalid() {
        when(secretStore.read(anyString())).thenReturn("not-valid-json");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingApiToken_throwsPermanentCredentialInvalid() {
        String missingToken = "{\"zoneId\":\"023e105f4ecef8ad9ca31a8372d0c353\"}";
        when(secretStore.read(anyString())).thenReturn(missingToken);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingScopeJson_throwsPermanentCredentialInvalid() {
        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_invalidScopeJson_throwsPermanentCredentialInvalid() {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("not-valid-json");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingZoneIdInScope_throwsPermanentCredentialInvalid() {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("{\"authMode\":\"API_TOKEN\",\"accountId\":\"acct-1\"}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("zoneId");
    }

    @Test
    void deploy_missingPrivateKey_throwsPermanentCertInvalid() {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        CertificateBundle bundleNoKey = new CertificateBundle(
                "",
                "-----BEGIN CERTIFICATE-----\nMIILeaf==\n-----END CERTIFICATE-----",
                null, null);

        assertThatThrownBy(() -> adapter.deploy(bundleNoKey, msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CERT_INVALID"));
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void deploy_rateLimited_throwsRetryableWithDeployProviderThrottled() throws Exception {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        HttpClient mockHttp = mock(HttpClient.class);
        HttpResponse<String> mockResp = mock(HttpResponse.class);
        when(mockResp.statusCode()).thenReturn(429);
        when(mockResp.body()).thenReturn("rate limited");
        when(mockResp.headers()).thenReturn(
                HttpHeaders.of(Map.of("Retry-After", List.of("30")), (k, v) -> true));
        when(mockHttp.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockResp);
        ReflectionTestUtils.setField(adapter, "httpClient", mockHttp);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(ex -> {
                    RetryableAgentException r = (RetryableAgentException) ex;
                    assertThat(r.getErrorCode()).isEqualTo("DEPLOY_PROVIDER_THROTTLED");
                    assertThat(r.getRetryAfter()).isEqualTo(java.time.Duration.ofSeconds(30));
                });
    }

    @Test
    void validateScope_allFieldsPresent_doesNotThrow() {
        CloudflareScope scope = new CloudflareScope("zone-abc", "ubiquitous", "sni_custom");
        adapter.validateScope(scope);
    }

    @Test
    void validateScope_missingZoneId_throws() {
        CloudflareScope scope = new CloudflareScope(null, "ubiquitous", "sni_custom");

        assertThatThrownBy(() -> adapter.validateScope(scope))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("zoneId");
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void deploy_firstDeploy_postsAndPollsToActive() throws Exception {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        HttpClient mockHttp = mock(HttpClient.class);
        HttpResponse<String> postResp = mock(HttpResponse.class);
        when(postResp.statusCode()).thenReturn(200);
        when(postResp.body()).thenReturn("{\"success\":true,\"result\":{\"id\":\"cf-cert-1\"}}");

        HttpResponse<String> activeResp = mock(HttpResponse.class);
        when(activeResp.statusCode()).thenReturn(200);
        when(activeResp.body()).thenReturn("{\"success\":true,\"result\":{\"status\":\"active\"}}");

        when(mockHttp.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(postResp, activeResp);
        ReflectionTestUtils.setField(adapter, "httpClient", mockHttp);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        var result = adapter.deploy(buildBundle(), msg);
        assertThat(result.targetResourceId()).isEqualTo("cf-cert-1");
        assertThat(result.configJson()).contains("cf-cert-1");
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void deploy_rotation_patchesExistingCert() throws Exception {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        HttpClient mockHttp = mock(HttpClient.class);
        HttpResponse<String> patchResp = mock(HttpResponse.class);
        when(patchResp.statusCode()).thenReturn(200);
        when(patchResp.body()).thenReturn("{\"success\":true,\"result\":{\"id\":\"cf-cert-2\"}}");

        HttpResponse<String> pendingResp = mock(HttpResponse.class);
        when(pendingResp.statusCode()).thenReturn(200);
        when(pendingResp.body()).thenReturn("{\"success\":true,\"result\":{\"status\":\"pending_deployment\"}}");

        HttpResponse<String> activeResp = mock(HttpResponse.class);
        when(activeResp.statusCode()).thenReturn(200);
        when(activeResp.body()).thenReturn("{\"success\":true,\"result\":{\"status\":\"active\"}}");

        when(mockHttp.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(patchResp, pendingResp, activeResp);
        ReflectionTestUtils.setField(adapter, "httpClient", mockHttp);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);
        msg.setConfigJson("{\"certId\":\"prior-cert-id\"}");

        var result = adapter.deploy(buildBundle(), msg);
        assertThat(result.targetResourceId()).isEqualTo("cf-cert-2");
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void deploy_uploadReturns500_throwsTransient() throws Exception {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        HttpClient mockHttp = mock(HttpClient.class);
        HttpResponse<String> resp = mock(HttpResponse.class);
        when(resp.statusCode()).thenReturn(500);
        when(resp.body()).thenReturn("server error");
        when(mockHttp.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(resp);
        ReflectionTestUtils.setField(adapter, "httpClient", mockHttp);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(com.certping.agent.exception.TransientAgentException.class)
                .satisfies(e -> assertThat(
                        ((com.certping.agent.exception.TransientAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CLOUDFLARE_UPLOAD_FAILED"));
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void deploy_uploadReturns400_throwsPermanent() throws Exception {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        HttpClient mockHttp = mock(HttpClient.class);
        HttpResponse<String> resp = mock(HttpResponse.class);
        when(resp.statusCode()).thenReturn(400);
        when(resp.body()).thenReturn("bad request");
        when(mockHttp.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(resp);
        ReflectionTestUtils.setField(adapter, "httpClient", mockHttp);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CLOUDFLARE_UPLOAD_FAILED"));
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void deploy_apiReturnsSuccessFalse_throwsPermanent() throws Exception {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        HttpClient mockHttp = mock(HttpClient.class);
        HttpResponse<String> resp = mock(HttpResponse.class);
        when(resp.statusCode()).thenReturn(200);
        when(resp.body()).thenReturn("{\"success\":false,\"errors\":[{\"code\":\"1004\",\"message\":\"oops\"}]}");
        when(mockHttp.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(resp);
        ReflectionTestUtils.setField(adapter, "httpClient", mockHttp);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("1004");
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void deploy_apiResponseMissingCertId_throwsPermanent() throws Exception {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        HttpClient mockHttp = mock(HttpClient.class);
        HttpResponse<String> resp = mock(HttpResponse.class);
        when(resp.statusCode()).thenReturn(200);
        when(resp.body()).thenReturn("{\"success\":true,\"result\":{}}");
        when(mockHttp.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(resp);
        ReflectionTestUtils.setField(adapter, "httpClient", mockHttp);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("missing certificate id");
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void deploy_pollUnexpectedStatus_throwsPermanent() throws Exception {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        HttpClient mockHttp = mock(HttpClient.class);
        HttpResponse<String> postResp = mock(HttpResponse.class);
        when(postResp.statusCode()).thenReturn(200);
        when(postResp.body()).thenReturn("{\"success\":true,\"result\":{\"id\":\"cf-cert-x\"}}");

        HttpResponse<String> pollResp = mock(HttpResponse.class);
        when(pollResp.statusCode()).thenReturn(200);
        when(pollResp.body()).thenReturn("{\"success\":true,\"result\":{\"status\":\"revoked\"}}");

        when(mockHttp.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(postResp, pollResp);
        ReflectionTestUtils.setField(adapter, "httpClient", mockHttp);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CLOUDFLARE_POLL_FAILED"))
                .hasMessageContaining("revoked");
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void deploy_pollReturns500_throwsTransient() throws Exception {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        HttpClient mockHttp = mock(HttpClient.class);
        HttpResponse<String> postResp = mock(HttpResponse.class);
        when(postResp.statusCode()).thenReturn(200);
        when(postResp.body()).thenReturn("{\"success\":true,\"result\":{\"id\":\"cf-cert-y\"}}");

        HttpResponse<String> pollResp = mock(HttpResponse.class);
        when(pollResp.statusCode()).thenReturn(500);
        when(pollResp.body()).thenReturn("upstream down");

        when(mockHttp.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(postResp, pollResp);
        ReflectionTestUtils.setField(adapter, "httpClient", mockHttp);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(com.certping.agent.exception.TransientAgentException.class);
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void deploy_pollSuccessFalse_throwsPermanent() throws Exception {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        HttpClient mockHttp = mock(HttpClient.class);
        HttpResponse<String> postResp = mock(HttpResponse.class);
        when(postResp.statusCode()).thenReturn(200);
        when(postResp.body()).thenReturn("{\"success\":true,\"result\":{\"id\":\"cf-cert-z\"}}");

        HttpResponse<String> pollResp = mock(HttpResponse.class);
        when(pollResp.statusCode()).thenReturn(200);
        when(pollResp.body()).thenReturn("{\"success\":false,\"errors\":[{\"message\":\"nope\"}]}");

        when(mockHttp.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(postResp, pollResp);
        ReflectionTestUtils.setField(adapter, "httpClient", mockHttp);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CLOUDFLARE_POLL_FAILED"));
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void deploy_force_bundleMethod_usesFullChain() throws Exception {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        HttpClient mockHttp = mock(HttpClient.class);
        HttpResponse<String> postResp = mock(HttpResponse.class);
        when(postResp.statusCode()).thenReturn(200);
        when(postResp.body()).thenReturn("{\"success\":true,\"result\":{\"id\":\"cf-cert-f\"}}");
        HttpResponse<String> activeResp = mock(HttpResponse.class);
        when(activeResp.statusCode()).thenReturn(200);
        when(activeResp.body()).thenReturn("{\"success\":true,\"result\":{\"status\":\"active\"}}");
        when(mockHttp.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(postResp, activeResp);
        ReflectionTestUtils.setField(adapter, "httpClient", mockHttp);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("{\"zoneId\":\"zone-abc\",\"bundleMethod\":\"force\",\"certType\":\"legacy_custom\"}");

        var result = adapter.deploy(buildBundle(), msg);
        assertThat(result.targetResourceId()).isEqualTo("cf-cert-f");
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void deploy_defaultsApplied_whenBundleMethodAndCertTypeBlank() throws Exception {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        HttpClient mockHttp = mock(HttpClient.class);
        HttpResponse<String> postResp = mock(HttpResponse.class);
        when(postResp.statusCode()).thenReturn(200);
        when(postResp.body()).thenReturn("{\"success\":true,\"result\":{\"id\":\"cf-cert-d\"}}");
        HttpResponse<String> activeResp = mock(HttpResponse.class);
        when(activeResp.statusCode()).thenReturn(200);
        when(activeResp.body()).thenReturn("{\"success\":true,\"result\":{\"status\":\"active\"}}");
        when(mockHttp.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(postResp, activeResp);
        ReflectionTestUtils.setField(adapter, "httpClient", mockHttp);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("{\"zoneId\":\"zone-abc\"}");
        msg.setConfigJson("not-valid-json-prior");

        var result = adapter.deploy(buildBundle(), msg);
        assertThat(result.targetResourceId()).isEqualTo("cf-cert-d");
    }

    @Test
    void deploy_bundleMissingLeafAndChain_throwsPermanent() {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("{\"zoneId\":\"zone-abc\",\"bundleMethod\":\"force\"}");

        CertificateBundle noChain = new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\nMIIEvQ==\n-----END PRIVATE KEY-----",
                null, null, null);

        assertThatThrownBy(() -> adapter.deploy(noChain, msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CERT_INVALID"));
    }

    @Test
    void deploy_ubiquitous_fallsBackToFullChainWhenLeafBlank() throws Exception {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        @SuppressWarnings({"unchecked","rawtypes"})
        HttpClient mockHttp = mock(HttpClient.class);
        @SuppressWarnings({"unchecked","rawtypes"})
        HttpResponse<String> postResp = mock(HttpResponse.class);
        when(postResp.statusCode()).thenReturn(200);
        when(postResp.body()).thenReturn("{\"success\":true,\"result\":{\"id\":\"cf-cert-fc\"}}");
        @SuppressWarnings({"unchecked","rawtypes"})
        HttpResponse<String> activeResp = mock(HttpResponse.class);
        when(activeResp.statusCode()).thenReturn(200);
        when(activeResp.body()).thenReturn("{\"success\":true,\"result\":{\"status\":\"active\"}}");
        when(mockHttp.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(postResp, activeResp);
        ReflectionTestUtils.setField(adapter, "httpClient", mockHttp);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        CertificateBundle blankLeaf = new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\nMIIEvQ==\n-----END PRIVATE KEY-----",
                "",
                null,
                "-----BEGIN CERTIFICATE-----\nFULLCHAIN\n-----END CERTIFICATE-----");

        var result = adapter.deploy(blankLeaf, msg);
        assertThat(result.targetResourceId()).isEqualTo("cf-cert-fc");
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void deploy_503_throwsRetryableThrottled() throws Exception {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        HttpClient mockHttp = mock(HttpClient.class);
        HttpResponse<String> resp = mock(HttpResponse.class);
        when(resp.statusCode()).thenReturn(503);
        when(resp.body()).thenReturn("unavailable");
        when(resp.headers()).thenReturn(HttpHeaders.of(Map.of(), (k, v) -> true));
        when(mockHttp.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(resp);
        ReflectionTestUtils.setField(adapter, "httpClient", mockHttp);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_PROVIDER_THROTTLED"));
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void deploy_httpClientThrows_wrappedAsPermanent() throws Exception {
        when(secretStore.read(anyString())).thenReturn("{\"apiToken\":\"token\"}");

        HttpClient mockHttp = mock(HttpClient.class);
        when(mockHttp.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new java.io.IOException("network down"));
        ReflectionTestUtils.setField(adapter, "httpClient", mockHttp);

        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(SCOPE_JSON);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CLOUDFLARE_FAILED"));
    }

    private CertDeploymentMessage buildMessage() {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setRequestId("req-cf-1");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("example.com");
        msg.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert-xref-1");
        msg.setTargetType(TargetType.CLOUDFLARE_EDGE);
        msg.setDeploymentCredHandle("https://kv-agent.vault.azure.net/secrets/cf-edge-cred");
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
}
