// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.globalsign;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class GlobalSignAtlasClientTest {

    private GlobalSignAtlasClient client;
    private AgentProperties properties;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() throws Exception {
        properties = new AgentProperties();
        properties.getGlobalsign().setApiBaseUrl("https://emea.api.hvca.globalsign.com:8443/v2");
        properties.getGlobalsign().setApiKey("test-key");
        properties.getGlobalsign().setApiSecret("test-secret");
        properties.getGlobalsign().setStrictPolicyValidation(false);

        objectMapper = JsonMapper.builderWithJackson2Defaults().build();
        client = new GlobalSignAtlasClient(properties, objectMapper);

        // Short-circuit the login call: prime the bearer-token cache so most calls go
        // straight to sendAuthorized() and we only exercise the central send/assert2xx paths.
        setField(client, "cachedToken", "fake-bearer-token");
        setField(client, "tokenExpiresAt", Instant.now().plusSeconds(3600));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private HttpResponse<String> mockResponse(int status, String body) throws Exception {
        HttpResponse<String> resp = mock(HttpResponse.class);
        when(resp.statusCode()).thenReturn(status);
        when(resp.body()).thenReturn(body);
        return resp;
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<String> mockResponseWithHeaders(int status, String body, Map<String, List<String>> hdrs) throws Exception {
        HttpResponse<String> resp = mock(HttpResponse.class);
        when(resp.statusCode()).thenReturn(status);
        when(resp.body()).thenReturn(body);
        when(resp.headers()).thenReturn(HttpHeaders.of(hdrs, (k, v) -> true));
        return resp;
    }

    @SuppressWarnings("unchecked")
    private HttpClient injectMockHttpReturning(HttpResponse<String>... responses) throws Exception {
        HttpClient mockHttp = mock(HttpClient.class);
        if (responses.length == 1) {
            when(mockHttp.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenReturn(responses[0]);
        } else {
            HttpResponse<String> first = responses[0];
            HttpResponse<String>[] rest = new HttpResponse[responses.length - 1];
            System.arraycopy(responses, 1, rest, 0, rest.length);
            when(mockHttp.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenReturn(first, rest);
        }
        setField(client, "httpClient", mockHttp);
        return mockHttp;
    }

    private static void setField(Object target, String fieldName, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(target, value);
    }

    // ── Rate-limit ────────────────────────────────────────────────────────────

    @Test
    void send_429_throwsRetryableWithRetryAfter() throws Exception {
        HttpResponse<String> resp = mockResponseWithHeaders(429, "{\"error\":\"too many requests\"}",
                Map.of("retry-after", List.of("90")));
        injectMockHttpReturning(resp);

        assertThatThrownBy(() -> client.revokeCertificate("serial-xyz", "KEY_COMPROMISE"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> {
                    RetryableAgentException re = (RetryableAgentException) e;
                    assertThat(re.getErrorCode()).isEqualTo("CA_PROVIDER_THROTTLED");
                    assertThat(re.getRetryAfter()).isEqualTo(Duration.ofSeconds(90));
                });
    }

    @Test
    void send_503_withoutRetryAfter_throwsRetryableWithNullRetryAfter() throws Exception {
        HttpResponse<String> resp = mockResponseWithHeaders(503, "service unavailable", Map.of());
        injectMockHttpReturning(resp);

        assertThatThrownBy(() -> client.getCertificate("serial-1"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> {
                    RetryableAgentException re = (RetryableAgentException) e;
                    assertThat(re.getErrorCode()).isEqualTo("CA_PROVIDER_THROTTLED");
                    assertThat(re.getRetryAfter()).isNull();
                });
    }

    @Test
    void send_429_withoutRetryAfter_throwsRetryableWithNullRetryAfter() throws Exception {
        HttpResponse<String> resp = mockResponseWithHeaders(429, "throttled", Map.of());
        injectMockHttpReturning(resp);

        assertThatThrownBy(() -> client.getCertificate("serial-2"))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> assertThat(((RetryableAgentException) e).getRetryAfter()).isNull());
    }

    // ── Error mapping ─────────────────────────────────────────────────────────

    @Test
    void send_5xx_throwsTransient() throws Exception {
        HttpResponse<String> resp = mockResponse(500, "{\"error\":\"boom\"}");
        injectMockHttpReturning(resp);

        assertThatThrownBy(() -> client.getCertificate("serial-x"))
                .isInstanceOf(TransientAgentException.class)
                .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                        .isEqualTo("GLOBALSIGN_SERVER_ERROR"));
    }

    @Test
    void send_400_throwsPermanent() throws Exception {
        HttpResponse<String> resp = mockResponse(400, "{\"error\":\"bad\"}");
        injectMockHttpReturning(resp);

        assertThatThrownBy(() -> client.getCertificate("serial-x"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("GLOBALSIGN_API_ERROR"));
    }

    @Test
    void send_401_invalidatesTokenAndRetries() throws Exception {
        HttpResponse<String> first = mockResponse(401, "unauthorized");
        HttpResponse<String> second = mockResponse(200, "{\"serial\":\"S1\"}");
        // login() is invoked after invalidating — mock the login response too as the 2nd send.
        // sendAuthorized -> 401 -> invalidate -> getAccessToken (no cache) -> login send -> retry send.
        HttpResponse<String> loginResp = mockResponse(200, "{\"access_token\":\"new-token\"}");
        HttpClient mockHttp = injectMockHttpReturning(first, loginResp, second);

        JsonNode body = client.getCertificate("serial-401");
        assertThat(body.path("serial").asString()).isEqualTo("S1");
        verify(mockHttp, times(3)).send(any(), any());
    }

    @Test
    void send_403_invalidatesTokenAndRetries() throws Exception {
        HttpResponse<String> first = mockResponse(403, "forbidden");
        HttpResponse<String> loginResp = mockResponse(200, "{\"access_token\":\"new-token\"}");
        HttpResponse<String> second = mockResponse(200, "{}");
        injectMockHttpReturning(first, loginResp, second);

        // No exception => retry succeeded.
        client.verifyDomainDns("claim-1", "example.com");
    }

    // ── login() ───────────────────────────────────────────────────────────────

    @Test
    void login_missingApiKey_throwsPermanent() throws Exception {
        properties.getGlobalsign().setApiKey("");
        setField(client, "cachedToken", null);
        setField(client, "tokenExpiresAt", Instant.EPOCH);

        assertThatThrownBy(() -> client.getCertificate("s"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("GLOBALSIGN_CONFIG_MISSING"));
    }

    @Test
    void login_missingApiSecret_throwsPermanent() throws Exception {
        properties.getGlobalsign().setApiSecret("");
        setField(client, "cachedToken", null);
        setField(client, "tokenExpiresAt", Instant.EPOCH);

        assertThatThrownBy(() -> client.getValidationPolicy())
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("GLOBALSIGN_CONFIG_MISSING"));
    }

    @Test
    void login_responseMissingAccessToken_throwsPermanent() throws Exception {
        setField(client, "cachedToken", null);
        setField(client, "tokenExpiresAt", Instant.EPOCH);
        HttpResponse<String> loginResp = mockResponse(200, "{\"foo\":\"bar\"}");
        injectMockHttpReturning(loginResp);

        assertThatThrownBy(() -> client.getCertificate("s"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("GLOBALSIGN_AUTH_FAILED"));
    }

    @Test
    void login_happyPath_cachesToken() throws Exception {
        setField(client, "cachedToken", null);
        setField(client, "tokenExpiresAt", Instant.EPOCH);
        HttpResponse<String> loginResp = mockResponse(200, "{\"access_token\":\"tok-abc\"}");
        HttpResponse<String> dataResp = mockResponse(200, "{\"serial\":\"S\"}");
        injectMockHttpReturning(loginResp, dataResp);

        JsonNode body = client.getCertificate("serial-1");
        assertThat(body.path("serial").asString()).isEqualTo("S");
    }

    // ── getValidationPolicy ───────────────────────────────────────────────────

    @Test
    void getValidationPolicy_returnsParsedJson() throws Exception {
        HttpResponse<String> resp = mockResponse(200, "{\"signature\":{\"hash_algorithm\":{\"list\":[\"SHA-256\"]}}}");
        injectMockHttpReturning(resp);

        JsonNode policy = client.getValidationPolicy();
        assertThat(policy.path("signature").path("hash_algorithm").path("list").get(0).asString()).isEqualTo("SHA-256");
    }

    // ── findPendingClaim ──────────────────────────────────────────────────────

    @Test
    void findPendingClaim_returnsTheClaimWithItsToken() throws Exception {
        HttpResponse<String> resp = mockResponse(200,
                "[{\"id\":\"claim-7\",\"domain\":\"example.com\",\"status\":\"PENDING\",\"token\":\"tok-7\"}]");
        HttpClient http = injectMockHttpReturning(resp);

        GlobalSignAtlasClient.DomainClaim claim = client.findPendingClaim("example.com.");
        assertThat(claim.claimId()).isEqualTo("claim-7");
        assertThat(claim.token()).isEqualTo("tok-7");

        ArgumentCaptor<HttpRequest> cap = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).send(cap.capture(), any());
        assertThat(cap.getValue().uri().toString()).contains("domain=example.com").contains("status=PENDING");
    }

    @Test
    void findPendingClaim_noPendingClaim_returnsNull() throws Exception {
        injectMockHttpReturning(mockResponse(200,
                "[{\"id\":\"claim-8\",\"domain\":\"other.com\",\"status\":\"PENDING\",\"token\":\"tok\"}]"));

        assertThat(client.findPendingClaim("example.com")).isNull();
    }

    // ── initiateDomainClaim ───────────────────────────────────────────────────

    @Test
    void initiateDomainClaim_happyPath_returnsClaim() throws Exception {
        HttpResponse<String> resp = mockResponseWithHeaders(200,
                "{\"id\":\"claim-123\",\"token\":\"tok-xyz\"}", Map.of());
        HttpClient http = injectMockHttpReturning(resp);

        GlobalSignAtlasClient.DomainClaim claim = client.initiateDomainClaim("Example.COM");
        assertThat(claim.claimId()).isEqualTo("claim-123");
        assertThat(claim.token()).isEqualTo("tok-xyz");
        assertThat(claim.domain()).isEqualTo("example.com");

        ArgumentCaptor<HttpRequest> cap = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).send(cap.capture(), any());
        assertThat(cap.getValue().uri().toString()).endsWith("/claims/domains/example.com");
        assertThat(cap.getValue().method()).isEqualTo("POST");
    }

    @Test
    void initiateDomainClaim_blankDomain_throwsPermanent() {
        assertThatThrownBy(() -> client.initiateDomainClaim("  "))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("GLOBALSIGN_DOMAIN_INVALID"));
    }

    @Test
    void initiateDomainClaim_missingToken_throwsPermanent() throws Exception {
        HttpResponse<String> resp = mockResponseWithHeaders(200,
                "{\"id\":\"claim-1\"}", Map.of());
        injectMockHttpReturning(resp);

        assertThatThrownBy(() -> client.initiateDomainClaim("example.com"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("GLOBALSIGN_RESPONSE_INVALID"));
    }

    @Test
    void initiateDomainClaim_missingClaimId_throwsPermanent() throws Exception {
        HttpResponse<String> resp = mockResponseWithHeaders(200,
                "{\"token\":\"tok\"}", Map.of());
        injectMockHttpReturning(resp);

        assertThatThrownBy(() -> client.initiateDomainClaim("example.com"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("GLOBALSIGN_RESPONSE_INVALID"));
    }

    @Test
    void initiateDomainClaim_claimIdFromLocationHeader() throws Exception {
        HttpResponse<String> resp = mockResponseWithHeaders(201,
                "{\"token\":\"tok-xyz\"}",
                Map.of("Location", List.of("/claims/domains/loc-claim-999")));
        injectMockHttpReturning(resp);

        GlobalSignAtlasClient.DomainClaim claim = client.initiateDomainClaim("example.com");
        assertThat(claim.claimId()).isEqualTo("loc-claim-999");
    }

    @Test
    void initiateDomainClaim_claimIdFromClaimIdField() throws Exception {
        HttpResponse<String> resp = mockResponseWithHeaders(200,
                "{\"claim_id\":\"cid-42\",\"token\":\"tk\"}", Map.of());
        injectMockHttpReturning(resp);

        assertThat(client.initiateDomainClaim("example.com").claimId()).isEqualTo("cid-42");
    }

    // ── findVerifiedClaimId ───────────────────────────────────────────────────

    @Test
    void findVerifiedClaimId_arrayBody_matchesDomain() throws Exception {
        HttpResponse<String> resp = mockResponse(200,
                "[{\"id\":\"c1\",\"domain\":\"example.com.\",\"status\":\"VERIFIED\"}]");
        injectMockHttpReturning(resp);

        assertThat(client.findVerifiedClaimId("example.com")).isEqualTo("c1");
    }

    @Test
    void findVerifiedClaimId_objectBodyWithClaimsArray() throws Exception {
        HttpResponse<String> resp = mockResponse(200,
                "{\"claims\":[{\"id\":\"c2\",\"domain\":\"example.com\",\"status\":\"VERIFIED\"}]}");
        injectMockHttpReturning(resp);

        assertThat(client.findVerifiedClaimId("example.com")).isEqualTo("c2");
    }

    @Test
    void findVerifiedClaimId_noMatch_returnsNull() throws Exception {
        HttpResponse<String> resp = mockResponse(200,
                "{\"claims\":[{\"id\":\"c3\",\"domain\":\"other.com\",\"status\":\"VERIFIED\"}]}");
        injectMockHttpReturning(resp);

        assertThat(client.findVerifiedClaimId("example.com")).isNull();
    }

    @Test
    void findVerifiedClaimId_emptyArray_returnsNull() throws Exception {
        HttpResponse<String> resp = mockResponse(200, "[]");
        injectMockHttpReturning(resp);

        assertThat(client.findVerifiedClaimId("example.com")).isNull();
    }

    // ── verifyDomainDns ───────────────────────────────────────────────────────

    @Test
    void verifyDomainDns_postsExpectedPayload() throws Exception {
        HttpResponse<String> resp = mockResponse(200, "{}");
        HttpClient http = injectMockHttpReturning(resp);

        client.verifyDomainDns("claim-77", "auth.example.com");

        ArgumentCaptor<HttpRequest> cap = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).send(cap.capture(), any());
        assertThat(cap.getValue().uri().toString()).endsWith("/claims/domains/claim-77/dns");
        assertThat(cap.getValue().method()).isEqualTo("POST");
    }

    // ── getDomainClaim ────────────────────────────────────────────────────────

    @Test
    void getDomainClaim_returnsParsedBody() throws Exception {
        HttpResponse<String> resp = mockResponse(200,
                "{\"id\":\"c-9\",\"status\":\"PENDING\"}");
        HttpClient http = injectMockHttpReturning(resp);

        JsonNode body = client.getDomainClaim("c-9");
        assertThat(body.path("status").asString()).isEqualTo("PENDING");

        ArgumentCaptor<HttpRequest> cap = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).send(cap.capture(), any());
        assertThat(cap.getValue().uri().toString()).endsWith("/claims/domains/c-9");
        assertThat(cap.getValue().method()).isEqualTo("GET");
    }

    // ── getCertificate ────────────────────────────────────────────────────────

    @Test
    void getCertificate_returnsParsedBody() throws Exception {
        HttpResponse<String> resp = mockResponse(200,
                "{\"serial\":\"ABC123\",\"status\":\"ISSUED\"}");
        HttpClient http = injectMockHttpReturning(resp);

        JsonNode body = client.getCertificate("ABC123");
        assertThat(body.path("serial").asString()).isEqualTo("ABC123");

        ArgumentCaptor<HttpRequest> cap = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).send(cap.capture(), any());
        assertThat(cap.getValue().uri().toString()).endsWith("/certificates/ABC123");
    }

    // ── getTrustChainPem ──────────────────────────────────────────────────────

    @Test
    void getTrustChainPem_topLevelArrayFormat() throws Exception {
        HttpResponse<String> resp = mockResponse(200, "[\"PEM1\",\"PEM2\"]");
        injectMockHttpReturning(resp);

        assertThat(client.getTrustChainPem()).isEqualTo("PEM1\nPEM2");
    }

    @Test
    void getTrustChainPem_certificatesArrayFormat() throws Exception {
        HttpResponse<String> resp = mockResponse(200,
                "{\"certificates\":[\"PEMA\",\"PEMB\"]}");
        injectMockHttpReturning(resp);

        assertThat(client.getTrustChainPem()).isEqualTo("PEMA\nPEMB");
    }

    @Test
    void getTrustChainPem_trustChainArrayFormat() throws Exception {
        HttpResponse<String> resp = mockResponse(200,
                "{\"trust_chain\":[\"P1\",\"P2\",\"P3\"]}");
        injectMockHttpReturning(resp);

        assertThat(client.getTrustChainPem()).isEqualTo("P1\nP2\nP3");
    }

    @Test
    void getTrustChainPem_unrecognizedFormat_throwsPermanent() throws Exception {
        HttpResponse<String> resp = mockResponse(200, "{\"foo\":\"bar\"}");
        injectMockHttpReturning(resp);

        assertThatThrownBy(() -> client.getTrustChainPem())
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("GLOBALSIGN_RESPONSE_INVALID"));
    }

    // ── revokeCertificate ─────────────────────────────────────────────────────

    @Test
    void revokeCertificate_sendsPatchToCorrectPath() throws Exception {
        HttpResponse<String> resp = mockResponse(200, "{}");
        HttpClient http = injectMockHttpReturning(resp);

        client.revokeCertificate("serial-rev", "SUPERSEDED");

        ArgumentCaptor<HttpRequest> cap = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).send(cap.capture(), any());
        assertThat(cap.getValue().uri().toString()).endsWith("/certificates/serial-rev");
        assertThat(cap.getValue().method()).isEqualTo("PATCH");
    }

    @Test
    void revokeCertificate_unknownReason_mapsToUnspecified() throws Exception {
        HttpResponse<String> resp = mockResponse(200, "{}");
        injectMockHttpReturning(resp);
        // Just exercise the default-branch of mapRevocationReason — no exception expected.
        client.revokeCertificate("s", "WHATEVER");
        client.revokeCertificate("s", null);
    }

    // ── issueCertificate ──────────────────────────────────────────────────────

    @Test
    void issueCertificate_happyPath_returnsSerial() throws Exception {
        // issueCertificate(domain, sans, csr) first fetches validation policy then POSTs.
        HttpResponse<String> policyResp = mockResponse(200, "{}");
        HttpResponse<String> issueResp = mockResponseWithHeaders(200,
                "{\"serial\":\"NEW-SERIAL-1\"}", Map.of());
        injectMockHttpReturning(policyResp, issueResp);

        GlobalSignAtlasClient.IssueResult res = client.issueCertificate(
                "example.com", List.of("www.example.com"), "----CSR----");
        assertThat(res.serial()).isEqualTo("NEW-SERIAL-1");
    }

    @Test
    void issueCertificate_withPolicy_happyPath() throws Exception {
        HttpResponse<String> issueResp = mockResponseWithHeaders(200,
                "{\"certificate\":{\"serial_number\":\"FROM-CERT-OBJ\"}}", Map.of());
        injectMockHttpReturning(issueResp);

        JsonNode policy = objectMapper.readTree("{}");
        GlobalSignAtlasClient.IssueResult res = client.issueCertificate(
                "example.com", List.of(), "csr", policy);
        assertThat(res.serial()).isEqualTo("FROM-CERT-OBJ");
    }

    @Test
    void issueCertificate_serialFromLocationHeader() throws Exception {
        HttpResponse<String> issueResp = mockResponseWithHeaders(201,
                "{}",
                Map.of("Location", List.of("/certificates/LOC-SERIAL-42")));
        injectMockHttpReturning(issueResp);

        JsonNode policy = objectMapper.readTree("{}");
        GlobalSignAtlasClient.IssueResult res = client.issueCertificate(
                "example.com", List.of(), "csr", policy);
        assertThat(res.serial()).isEqualTo("LOC-SERIAL-42");
    }

    @Test
    void issueCertificate_missingSerial_throwsPermanent() throws Exception {
        HttpResponse<String> issueResp = mockResponseWithHeaders(200, "{}", Map.of());
        injectMockHttpReturning(issueResp);

        JsonNode policy = objectMapper.readTree("{}");
        assertThatThrownBy(() -> client.issueCertificate("example.com", List.of(), "csr", policy))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("GLOBALSIGN_RESPONSE_INVALID"));
    }

    @Test
    void issueCertificate_policyFetchFails_fallsBackToDefaultsAndStillIssues() throws Exception {
        // 1st send (policy fetch) returns 500 → swallowed by issueCertificate, then proceeds with null policy.
        HttpResponse<String> policyResp = mockResponse(500, "boom");
        HttpResponse<String> issueResp = mockResponseWithHeaders(200,
                "{\"serial\":\"S-DEF\"}", Map.of());
        injectMockHttpReturning(policyResp, issueResp);

        GlobalSignAtlasClient.IssueResult res = client.issueCertificate(
                "example.com", List.of("a.example.com"), "csr");
        assertThat(res.serial()).isEqualTo("S-DEF");
    }

    @Test
    void issueCertificate_serialFromCertificateTextual() throws Exception {
        HttpResponse<String> issueResp = mockResponseWithHeaders(200,
                "{\"certificate\":\"TEXTUAL-SERIAL\"}", Map.of());
        injectMockHttpReturning(issueResp);

        JsonNode policy = objectMapper.readTree("{}");
        GlobalSignAtlasClient.IssueResult res = client.issueCertificate(
                "example.com", null, "csr", policy);
        assertThat(res.serial()).isEqualTo("TEXTUAL-SERIAL");
    }

    @Test
    void issueCertificate_serialNumberTopLevel() throws Exception {
        HttpResponse<String> issueResp = mockResponseWithHeaders(200,
                "{\"serial_number\":\"SN-TOP\"}", Map.of());
        injectMockHttpReturning(issueResp);

        JsonNode policy = objectMapper.readTree("{}");
        assertThat(client.issueCertificate("example.com", List.of(), "csr", policy).serial())
                .isEqualTo("SN-TOP");
    }

    // ── Response parsing edge case ────────────────────────────────────────────

    @Test
    void send_invalidJsonBody_throwsPermanent() throws Exception {
        HttpResponse<String> resp = mockResponse(200, "not-json{{{");
        injectMockHttpReturning(resp);

        assertThatThrownBy(() -> client.getCertificate("s"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("GLOBALSIGN_RESPONSE_INVALID"));
    }

    // ── Policy-driven payload builders (reflection) ───────────────────────────

    @SuppressWarnings("unchecked")
    private Object invokePrivate(String methodName, Class<?>[] paramTypes, Object... args) throws Exception {
        Method m = GlobalSignAtlasClient.class.getDeclaredMethod(methodName, paramTypes);
        m.setAccessible(true);
        try {
            return m.invoke(client, args);
        } catch (InvocationTargetException ite) {
            if (ite.getCause() instanceof RuntimeException re) throw re;
            throw ite;
        }
    }

    private JsonNode tree(String json) throws Exception {
        return objectMapper.readTree(json);
    }

    // buildSignaturePayloadFromPolicy

    @Test
    @SuppressWarnings("unchecked")
    void buildSignaturePayload_nullPolicy_defaultsSha256() throws Exception {
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildSignaturePayloadFromPolicy", new Class<?>[]{JsonNode.class}, new Object[]{null});
        assertThat(result).containsEntry("hash_algorithm", "SHA-256");
        assertThat(result).doesNotContainKey("algorithm");
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildSignaturePayload_picksHashFromList() throws Exception {
        JsonNode policy = tree("{\"signature\":{\"hash_algorithm\":{\"list\":[\"SHA-512\"]}}}");
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildSignaturePayloadFromPolicy", new Class<?>[]{JsonNode.class}, policy);
        assertThat(result).containsEntry("hash_algorithm", "SHA-512");
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildSignaturePayload_requiredAlgorithm_includesRsa() throws Exception {
        JsonNode policy = tree("{\"signature\":{\"hash_algorithm\":{\"list\":[\"SHA-256\"]},"
                + "\"algorithm\":{\"presence\":\"REQUIRED\",\"list\":[\"RSA\",\"ECDSA\"]}}}");
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildSignaturePayloadFromPolicy", new Class<?>[]{JsonNode.class}, policy);
        assertThat(result).containsEntry("algorithm", "RSA");
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildSignaturePayload_algorithmForbidden_omitted() throws Exception {
        JsonNode policy = tree("{\"signature\":{\"algorithm\":{\"presence\":\"FORBIDDEN\",\"list\":[\"RSA\"]}}}");
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildSignaturePayloadFromPolicy", new Class<?>[]{JsonNode.class}, policy);
        assertThat(result).doesNotContainKey("algorithm");
    }

    // buildSubjectDnPayloadFromPolicy

    @Test
    @SuppressWarnings("unchecked")
    void buildSubjectDn_nullPolicy_setsCommonName() throws Exception {
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildSubjectDnPayloadFromPolicy", new Class<?>[]{JsonNode.class, String.class},
                null, "example.com");
        assertThat(result).containsEntry("common_name", "example.com");
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildSubjectDn_commonNameRequired_included() throws Exception {
        JsonNode policy = tree("{\"subject_dn\":{\"common_name\":{\"presence\":\"REQUIRED\"}}}");
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildSubjectDnPayloadFromPolicy", new Class<?>[]{JsonNode.class, String.class},
                policy, "acme.com");
        assertThat(result).containsEntry("common_name", "acme.com");
    }

    @Test
    void buildSubjectDn_commonNameForbidden_throwsPermanent() throws Exception {
        JsonNode policy = tree("{\"subject_dn\":{\"common_name\":{\"presence\":\"FORBIDDEN\"}}}");
        assertThatThrownBy(() -> invokePrivate(
                "buildSubjectDnPayloadFromPolicy", new Class<?>[]{JsonNode.class, String.class},
                policy, "acme.com"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildSubjectDn_staticCnIsNotEmitted() throws Exception {
        JsonNode policy = tree("{\"subject_dn\":{\"common_name\":{\"presence\":\"STATIC\"}}}");
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildSubjectDnPayloadFromPolicy", new Class<?>[]{JsonNode.class, String.class},
                policy, "acme.com");
        assertThat(result).doesNotContainKey("common_name");
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildSubjectDn_requiredOrgWithOverride_included() throws Exception {
        properties.getGlobalsign().setSubjectDnJson("{\"organization\":\"Example Org\"}");
        JsonNode policy = tree("{\"subject_dn\":{\"common_name\":{\"presence\":\"OPTIONAL\"},"
                + "\"organization\":{\"presence\":\"REQUIRED\"}}}");
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildSubjectDnPayloadFromPolicy", new Class<?>[]{JsonNode.class, String.class},
                policy, "x.com");
        assertThat(result).containsEntry("organization", "Example Org");
    }

    @Test
    void buildSubjectDn_requiredFieldMissing_throwsPermanent() throws Exception {
        JsonNode policy = tree("{\"subject_dn\":{\"common_name\":{\"presence\":\"OPTIONAL\"},"
                + "\"organization\":{\"presence\":\"REQUIRED\"}}}");
        assertThatThrownBy(() -> invokePrivate(
                "buildSubjectDnPayloadFromPolicy", new Class<?>[]{JsonNode.class, String.class},
                policy, "x.com"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildSubjectDn_staticOrgIsNotEmitted() throws Exception {
        properties.getGlobalsign().setSubjectDnJson("{\"organization\":\"Should-Not-Be-Sent\"}");
        JsonNode policy = tree("{\"subject_dn\":{\"common_name\":{\"presence\":\"OPTIONAL\"},"
                + "\"organization\":{\"presence\":\"STATIC\"}}}");
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildSubjectDnPayloadFromPolicy", new Class<?>[]{JsonNode.class, String.class},
                policy, "x.com");
        assertThat(result).doesNotContainKey("organization");
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildSubjectDn_ouList_withPolicy() throws Exception {
        properties.getGlobalsign().setSubjectDnJson("{\"organizational_unit\":[\"IT\"]}");
        JsonNode policy = tree("{\"subject_dn\":{\"common_name\":{\"presence\":\"OPTIONAL\"},"
                + "\"organizational_unit\":{\"mincount\":0,\"maxcount\":3}}}");
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildSubjectDnPayloadFromPolicy", new Class<?>[]{JsonNode.class, String.class},
                policy, "x.com");
        assertThat((List<String>) result.get("organizational_unit")).containsExactly("IT");
    }

    // buildSanPayloadFromPolicy

    @Test
    @SuppressWarnings("unchecked")
    void buildSan_nullPolicy_setsDnsNames() throws Exception {
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildSanPayloadFromPolicy", new Class<?>[]{JsonNode.class, List.class},
                null, List.of("a.com", "b.com"));
        assertThat((List<String>) result.get("dns_names")).containsExactly("a.com", "b.com");
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildSan_withPolicyDnsList_passesThrough() throws Exception {
        JsonNode policy = tree("{\"san\":{\"dns_names\":{\"mincount\":0,\"maxcount\":5}}}");
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildSanPayloadFromPolicy", new Class<?>[]{JsonNode.class, List.class},
                policy, List.of("acme.com"));
        assertThat((List<String>) result.get("dns_names")).containsExactly("acme.com");
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildSan_otherNames_passedFromOverrides() throws Exception {
        properties.getGlobalsign().setSanJson("{\"other_names\":{\"type_and_value\":\"x\"}}");
        JsonNode policy = tree("{\"san\":{}}");
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildSanPayloadFromPolicy", new Class<?>[]{JsonNode.class, List.class},
                policy, List.of("a.com"));
        assertThat(result).containsKey("other_names");
    }

    // buildExtendedKeyUsagesFromPolicy

    @Test
    @SuppressWarnings("unchecked")
    void buildExtendedKeyUsages_nullPolicy_defaults() throws Exception {
        List<String> result = (List<String>) invokePrivate(
                "buildExtendedKeyUsagesFromPolicy", new Class<?>[]{JsonNode.class}, new Object[]{null});
        assertThat(result).contains("1.3.6.1.5.5.7.3.1");
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildExtendedKeyUsages_policyList_filtered() throws Exception {
        JsonNode policy = tree("{\"extended_key_usages\":{\"ekus\":{\"list\":[\"1.3.6.1.5.5.7.3.1\"],\"mincount\":0,\"maxcount\":3}}}");
        List<String> result = (List<String>) invokePrivate(
                "buildExtendedKeyUsagesFromPolicy", new Class<?>[]{JsonNode.class}, policy);
        assertThat(result).contains("1.3.6.1.5.5.7.3.1");
    }

    @Test
    void buildExtendedKeyUsages_mincountUnmet_throwsPermanent() throws Exception {
        JsonNode policy = tree("{\"extended_key_usages\":{\"ekus\":{\"list\":[],\"mincount\":2}}}");
        assertThatThrownBy(() -> invokePrivate(
                "buildExtendedKeyUsagesFromPolicy", new Class<?>[]{JsonNode.class}, policy))
                .isInstanceOf(PermanentAgentException.class);
    }

    // buildKeyUsagesFromPolicy

    @Test
    @SuppressWarnings("unchecked")
    void buildKeyUsages_nullPolicy_empty() throws Exception {
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildKeyUsagesFromPolicy", new Class<?>[]{JsonNode.class}, new Object[]{null});
        assertThat(result).isEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildKeyUsages_nullPolicyWithOverrides_includesOverrides() throws Exception {
        properties.getGlobalsign().setKeyUsagesJson("{\"digital_signature\":true,\"key_encipherment\":true}");
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildKeyUsagesFromPolicy", new Class<?>[]{JsonNode.class}, new Object[]{null});
        assertThat(result).containsEntry("digital_signature", true)
                .containsEntry("key_encipherment", true);
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildKeyUsages_optionalWithOverride_included() throws Exception {
        properties.getGlobalsign().setKeyUsagesJson("{\"digital_signature\":true}");
        JsonNode policy = tree("{\"key_usages\":{\"digital_signature\":\"OPTIONAL\","
                + "\"key_encipherment\":\"STATIC_TRUE\"}}");
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildKeyUsagesFromPolicy", new Class<?>[]{JsonNode.class}, policy);
        assertThat(result).containsEntry("digital_signature", true);
        // STATIC_TRUE is applied by the CA, never echoed
        assertThat(result).doesNotContainKey("key_encipherment");
    }

    // applyListPolicy

    @Test
    @SuppressWarnings("unchecked")
    void applyListPolicy_nullSpec_returnsRequested() throws Exception {
        List<String> result = (List<String>) invokePrivate(
                "applyListPolicy", new Class<?>[]{JsonNode.class, List.class, String.class},
                null, List.of("A", "B"), "fld");
        assertThat(result).containsExactly("A", "B");
    }

    @Test
    @SuppressWarnings("unchecked")
    void applyListPolicy_staticTrue_emitsPolicyList() throws Exception {
        JsonNode spec = tree("{\"static\":true,\"list\":[\"X\",\"Y\"],\"mincount\":0,\"maxcount\":5}");
        List<String> result = (List<String>) invokePrivate(
                "applyListPolicy", new Class<?>[]{JsonNode.class, List.class, String.class},
                spec, List.of("REQ"), "fld");
        assertThat(result).containsExactly("X", "Y");
    }

    @Test
    void applyListPolicy_overflowMaxcount_throwsPermanent() throws Exception {
        JsonNode spec = tree("{\"mincount\":0,\"maxcount\":1}");
        assertThatThrownBy(() -> invokePrivate(
                "applyListPolicy", new Class<?>[]{JsonNode.class, List.class, String.class},
                spec, List.of("A", "B"), "fld"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void applyListPolicy_belowMincount_throwsPermanent() throws Exception {
        JsonNode spec = tree("{\"mincount\":2}");
        assertThatThrownBy(() -> invokePrivate(
                "applyListPolicy", new Class<?>[]{JsonNode.class, List.class, String.class},
                spec, List.of("only-one"), "fld"))
                .isInstanceOf(PermanentAgentException.class);
    }

    // validateUnsupportedPolicyRequirements

    @Test
    void validatePolicy_strictWithSubjectDaRequired_throwsPermanent() throws Exception {
        properties.getGlobalsign().setStrictPolicyValidation(true);
        JsonNode policy = tree("{\"subject_da\":{\"date_of_birth\":{\"presence\":\"REQUIRED\"}}}");
        assertThatThrownBy(() -> invokePrivate(
                "validateUnsupportedPolicyRequirements", new Class<?>[]{JsonNode.class}, policy))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void validatePolicy_strictWithQualifiedStatementsRequired_throwsPermanent() throws Exception {
        properties.getGlobalsign().setStrictPolicyValidation(true);
        JsonNode policy = tree("{\"qualified_statements\":{\"semantics\":{\"presence\":\"REQUIRED\"}}}");
        assertThatThrownBy(() -> invokePrivate(
                "validateUnsupportedPolicyRequirements", new Class<?>[]{JsonNode.class}, policy))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void validatePolicy_nonStrict_doesNotThrow() throws Exception {
        properties.getGlobalsign().setStrictPolicyValidation(false);
        JsonNode policy = tree("{\"subject_da\":{\"date_of_birth\":{\"presence\":\"REQUIRED\"}}}");
        // Should not throw with strict=false
        invokePrivate("validateUnsupportedPolicyRequirements", new Class<?>[]{JsonNode.class}, policy);
    }

    @Test
    void validatePolicy_nullPolicy_returnsCleanly() throws Exception {
        properties.getGlobalsign().setStrictPolicyValidation(true);
        invokePrivate("validateUnsupportedPolicyRequirements", new Class<?>[]{JsonNode.class}, new Object[]{null});
    }

    @Test
    void validatePolicy_publicKeySignatureRequired_throwsPermanent() throws Exception {
        properties.getGlobalsign().setStrictPolicyValidation(true);
        JsonNode policy = tree("{\"public_key_signature\":\"REQUIRED\"}");
        assertThatThrownBy(() -> invokePrivate(
                "validateUnsupportedPolicyRequirements", new Class<?>[]{JsonNode.class}, policy))
                .isInstanceOf(PermanentAgentException.class);
    }

    // matchesAnyPolicyPattern

    @Test
    void matchesAnyPolicyPattern_emptyPatterns_matchesAnything() throws Exception {
        boolean result = (boolean) invokePrivate(
                "matchesAnyPolicyPattern", new Class<?>[]{String.class, List.class},
                "any.value", List.of());
        assertThat(result).isTrue();
    }

    @Test
    void matchesAnyPolicyPattern_exactMatch() throws Exception {
        boolean result = (boolean) invokePrivate(
                "matchesAnyPolicyPattern", new Class<?>[]{String.class, List.class},
                "foo", List.of("foo", "bar"));
        assertThat(result).isTrue();
    }

    @Test
    void matchesAnyPolicyPattern_regexAnchored() throws Exception {
        boolean result = (boolean) invokePrivate(
                "matchesAnyPolicyPattern", new Class<?>[]{String.class, List.class},
                "1.3.6.1", List.of("^1\\..*$"));
        assertThat(result).isTrue();
    }

    @Test
    void matchesAnyPolicyPattern_noMatch_false() throws Exception {
        boolean result = (boolean) invokePrivate(
                "matchesAnyPolicyPattern", new Class<?>[]{String.class, List.class},
                "x.y", List.of("a", "b"));
        assertThat(result).isFalse();
    }

    // buildSubjectDaPayload / buildQualifiedStatementsPayload / etc.

    @Test
    @SuppressWarnings("unchecked")
    void buildSubjectDaPayload_noPolicySection_returnsEmpty() throws Exception {
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildSubjectDaPayload", new Class<?>[]{JsonNode.class}, new Object[]{null});
        assertThat(result).isEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildSubjectDaPayload_withSectionAndOverride_returnsMap() throws Exception {
        properties.getGlobalsign().setSubjectDaJson("{\"date_of_birth\":\"2000-01-01\"}");
        JsonNode policy = tree("{\"subject_da\":{}}");
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildSubjectDaPayload", new Class<?>[]{JsonNode.class}, policy);
        assertThat(result).containsEntry("date_of_birth", "2000-01-01");
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildQualifiedStatementsPayload_noSection_empty() throws Exception {
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildQualifiedStatementsPayload", new Class<?>[]{JsonNode.class}, new Object[]{null});
        assertThat(result).isEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildMsExtensionTemplatePayload_noSection_empty() throws Exception {
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildMsExtensionTemplatePayload", new Class<?>[]{JsonNode.class}, new Object[]{null});
        assertThat(result).isEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildCustomExtensionsPayload_noSection_empty() throws Exception {
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildCustomExtensionsPayload", new Class<?>[]{JsonNode.class}, new Object[]{null});
        assertThat(result).isEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildCustomExtensionsPayload_withSection_returnsMap() throws Exception {
        properties.getGlobalsign().setCustomExtensionsJson("{\"1.2.3\":\"value\"}");
        JsonNode policy = tree("{\"custom_extensions\":{}}");
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildCustomExtensionsPayload", new Class<?>[]{JsonNode.class}, policy);
        assertThat(result).containsEntry("1.2.3", "value");
    }

    // parseJsonEnv

    @Test
    void parseJsonEnv_blank_returnsNull() throws Exception {
        Object result = invokePrivate(
                "parseJsonEnv", new Class<?>[]{String.class, String.class},
                "", "TEST_ENV");
        assertThat(result).isNull();
    }

    @Test
    void parseJsonEnv_null_returnsNull() throws Exception {
        Object result = invokePrivate(
                "parseJsonEnv", new Class<?>[]{String.class, String.class},
                null, "TEST_ENV");
        assertThat(result).isNull();
    }

    @Test
    void parseJsonEnv_validJson_returnsNode() throws Exception {
        JsonNode result = (JsonNode) invokePrivate(
                "parseJsonEnv", new Class<?>[]{String.class, String.class},
                "{\"a\":1}", "TEST_ENV");
        assertThat(result.path("a").asInt()).isEqualTo(1);
    }

    @Test
    void parseJsonEnv_malformed_returnsNullAndLogs() throws Exception {
        // The implementation swallows errors and returns null (logs a warning).
        Object result = invokePrivate(
                "parseJsonEnv", new Class<?>[]{String.class, String.class},
                "not-json{{{", "TEST_ENV");
        assertThat(result).isNull();
    }

    // buildValidityPayloadFromPolicy

    @Test
    @SuppressWarnings("unchecked")
    void buildValidity_nullOverride_setsNotAfterZero() throws Exception {
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildValidityPayloadFromPolicy",
                new Class<?>[]{JsonNode.class, long.class, Integer.class},
                null, 1000L, null);
        assertThat(result).containsEntry("not_before", 1000L)
                .containsEntry("not_after", 0);
    }

    @Test
    @SuppressWarnings("unchecked")
    void buildValidity_withOverride_computesNotAfter() throws Exception {
        Map<String, Object> result = (Map<String, Object>) invokePrivate(
                "buildValidityPayloadFromPolicy",
                new Class<?>[]{JsonNode.class, long.class, Integer.class},
                null, 1000L, 30);
        assertThat(result).containsEntry("not_after", 1000L + 30L * 86400L);
    }

    // ── buildMutualTlsContextIfPresent / parseCertificates / chain helpers ───

    @Test
    void buildMutualTls_noConfig_returnsNull() throws Exception {
        // both pem fields blank => returns null
        properties.getGlobalsign().setClientCertPemBase64("");
        properties.getGlobalsign().setClientPrivateKeyPemBase64("");
        Object out = invokePrivate("buildMutualTlsContextIfPresent", new Class<?>[]{});
        assertThat(out).isNull();
    }

    @Test
    void buildMutualTls_keyConfiguredButCertMissing_returnsNull() throws Exception {
        // Only one half configured → still null (both must be present).
        properties.getGlobalsign().setClientCertPemBase64("");
        properties.getGlobalsign().setClientPrivateKeyPemBase64(
                java.util.Base64.getEncoder().encodeToString("blob".getBytes()));
        Object out = invokePrivate("buildMutualTlsContextIfPresent", new Class<?>[]{});
        assertThat(out).isNull();
    }

    @Test
    void buildMutualTls_invalidCertPem_throwsPermanent() throws Exception {
        properties.getGlobalsign().setClientCertPemBase64(
                java.util.Base64.getEncoder().encodeToString("not a cert".getBytes()));
        properties.getGlobalsign().setClientPrivateKeyPemBase64(
                java.util.Base64.getEncoder().encodeToString("garbage key".getBytes()));
        assertThatThrownBy(() -> invokePrivate("buildMutualTlsContextIfPresent", new Class<?>[]{}))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("GLOBALSIGN_MTLS_CONFIG_INVALID"));
    }

    @Test
    void buildMutualTls_validRsaCertAndKey_returnsSslContext() throws Exception {
        java.security.KeyPair kp = java.security.KeyPairGenerator.getInstance("RSA").generateKeyPair();
        java.security.cert.X509Certificate cert = makeSelfSignedCert(kp);
        String certPem = "-----BEGIN CERTIFICATE-----\n"
                + java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
        String keyPem = "-----BEGIN PRIVATE KEY-----\n"
                + java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(kp.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";

        properties.getGlobalsign().setClientCertPemBase64(
                java.util.Base64.getEncoder().encodeToString(certPem.getBytes()));
        properties.getGlobalsign().setClientPrivateKeyPemBase64(
                java.util.Base64.getEncoder().encodeToString(keyPem.getBytes()));

        Object ctx = invokePrivate("buildMutualTlsContextIfPresent", new Class<?>[]{});
        assertThat(ctx).isInstanceOf(javax.net.ssl.SSLContext.class);
    }

    @Test
    void parseCertificates_singleCert_returnsOne() throws Exception {
        java.security.KeyPair kp = java.security.KeyPairGenerator.getInstance("RSA").generateKeyPair();
        java.security.cert.X509Certificate cert = makeSelfSignedCert(kp);
        String certPem = "-----BEGIN CERTIFICATE-----\n"
                + java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
        @SuppressWarnings("unchecked")
        List<java.security.cert.X509Certificate> certs = (List<java.security.cert.X509Certificate>) invokePrivate(
                "parseCertificates", new Class<?>[]{String.class}, certPem);
        assertThat(certs).hasSize(1);
    }

    @Test
    void isSelfSigned_selfSignedCert_returnsTrue() throws Exception {
        java.security.KeyPair kp = java.security.KeyPairGenerator.getInstance("RSA").generateKeyPair();
        java.security.cert.X509Certificate cert = makeSelfSignedCert(kp);
        Object out = invokePrivate("isSelfSigned",
                new Class<?>[]{java.security.cert.X509Certificate.class}, cert);
        assertThat(out).isEqualTo(true);
    }

    @Test
    void orderChainLeafFirst_filtersSelfSignedRoot() throws Exception {
        java.security.KeyPair kp = java.security.KeyPairGenerator.getInstance("RSA").generateKeyPair();
        java.security.cert.X509Certificate selfSigned = makeSelfSignedCert(kp);
        @SuppressWarnings("unchecked")
        List<java.security.cert.X509Certificate> ordered = (List<java.security.cert.X509Certificate>) invokePrivate(
                "orderChainLeafFirst", new Class<?>[]{List.class}, List.of(selfSigned));
        // Single self-signed cert: stays as leaf (the only entry).
        assertThat(ordered).hasSize(1);
    }

    private static java.security.cert.X509Certificate makeSelfSignedCert(java.security.KeyPair kp) throws Exception {
        javax.security.auth.x500.X500Principal subject = new javax.security.auth.x500.X500Principal("CN=test-mtls");
        java.util.Date notBefore = new java.util.Date();
        java.util.Date notAfter = new java.util.Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);
        var builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                subject, java.math.BigInteger.valueOf(System.currentTimeMillis()),
                notBefore, notAfter, subject, kp.getPublic());
        var signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256WithRSA")
                .build(kp.getPrivate());
        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                .getCertificate(builder.build(signer));
    }

    // ── applyListPolicy STATIC with FORBIDDEN values present ───────────────

    @Test
    @SuppressWarnings("unchecked")
    void applyListPolicy_emptyRequested_emptyResult() throws Exception {
        JsonNode spec = tree("{\"mincount\":0,\"maxcount\":5}");
        List<String> result = (List<String>) invokePrivate(
                "applyListPolicy", new Class<?>[]{JsonNode.class, List.class, String.class},
                spec, List.of(), "fld");
        assertThat(result).isEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    void applyListPolicy_nullRequested_emptyOk() throws Exception {
        JsonNode spec = tree("{\"mincount\":0,\"maxcount\":5}");
        List<String> result = (List<String>) invokePrivate(
                "applyListPolicy", new Class<?>[]{JsonNode.class, List.class, String.class},
                spec, null, "fld");
        assertThat(result).isEmpty();
    }

    // ── assert2xx variations: 4xx with empty body & 4xx json body ─────────

    @Test
    void send_4xx_emptyBody_throwsPermanent() throws Exception {
        HttpResponse<String> resp = mockResponse(400, "");
        injectMockHttpReturning(resp);
        assertThatThrownBy(() -> client.getCertificate("s"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void send_4xx_nullBody_throwsPermanent() throws Exception {
        @SuppressWarnings("unchecked")
        HttpResponse<String> resp = mock(HttpResponse.class);
        when(resp.statusCode()).thenReturn(400);
        when(resp.body()).thenReturn(null);
        when(resp.headers()).thenReturn(HttpHeaders.of(Map.of(), (k, v) -> true));
        injectMockHttpReturning(resp);
        assertThatThrownBy(() -> client.getCertificate("s"))
                .isInstanceOf(PermanentAgentException.class);
    }

    // ── parseJsonEnv array→list, jsonNodeToList null/string variants ────

    @Test
    void jsonNodeToList_nullNode_returnsEmpty() throws Exception {
        @SuppressWarnings("unchecked")
        List<String> result = (List<String>) invokePrivate("jsonNodeToList",
                new Class<?>[]{JsonNode.class}, new Object[]{null});
        assertThat(result).isEmpty();
    }

    @Test
    void jsonNodeToList_arrayNode_returnsList() throws Exception {
        @SuppressWarnings("unchecked")
        List<String> result = (List<String>) invokePrivate("jsonNodeToList",
                new Class<?>[]{JsonNode.class}, tree("[\"a\",\"b\"]"));
        assertThat(result).containsExactly("a", "b");
    }

    @Test
    void jsonNodeToList_csvString_splitsAndTrims() throws Exception {
        @SuppressWarnings("unchecked")
        List<String> result = (List<String>) invokePrivate("jsonNodeToList",
                new Class<?>[]{JsonNode.class}, tree("\" foo , bar \""));
        assertThat(result).containsExactly("foo", "bar");
    }

    @Test
    void jsonNodeToList_blankString_returnsEmpty() throws Exception {
        @SuppressWarnings("unchecked")
        List<String> result = (List<String>) invokePrivate("jsonNodeToList",
                new Class<?>[]{JsonNode.class}, tree("\"   \""));
        assertThat(result).isEmpty();
    }

    @Test
    void jsonNodeToMap_nonObject_returnsEmpty() throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) invokePrivate("jsonNodeToMap",
                new Class<?>[]{JsonNode.class}, tree("[1,2,3]"));
        assertThat(result).isEmpty();
    }

    @Test
    void jsonNodeToMap_nullNode_returnsEmpty() throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) invokePrivate("jsonNodeToMap",
                new Class<?>[]{JsonNode.class}, new Object[]{null});
        assertThat(result).isEmpty();
    }

    // ── matchesAnyPolicyPattern - blank pattern skipped, $-anchored pattern ─

    @Test
    void matchesAnyPolicyPattern_blankPatternSkipped_returnsFalse() throws Exception {
        boolean result = (boolean) invokePrivate("matchesAnyPolicyPattern",
                new Class<?>[]{String.class, List.class}, "x", java.util.Arrays.asList("", "  "));
        assertThat(result).isFalse();
    }

    @Test
    void matchesAnyPolicyPattern_dollarAnchored() throws Exception {
        boolean result = (boolean) invokePrivate("matchesAnyPolicyPattern",
                new Class<?>[]{String.class, List.class}, "abc.example", List.of(".*example$"));
        assertThat(result).isTrue();
    }

    // ── validateUnsupportedPolicyRequirements additional arms ─────────────

    @Test
    void validatePolicy_strictWithMsExtensionRequired_throws() throws Exception {
        properties.getGlobalsign().setStrictPolicyValidation(true);
        JsonNode policy = tree("{\"ms_extension_template\":{\"x\":{\"presence\":\"REQUIRED\"}}}");
        assertThatThrownBy(() -> invokePrivate(
                "validateUnsupportedPolicyRequirements", new Class<?>[]{JsonNode.class}, policy))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void validatePolicy_strictWithCustomExtensionsRequired_throws() throws Exception {
        properties.getGlobalsign().setStrictPolicyValidation(true);
        JsonNode policy = tree("{\"custom_extensions\":{\"x\":{\"presence\":\"REQUIRED\"}}}");
        assertThatThrownBy(() -> invokePrivate(
                "validateUnsupportedPolicyRequirements", new Class<?>[]{JsonNode.class}, policy))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void validatePolicy_strictWithSanOtherNamesRequired_throws() throws Exception {
        properties.getGlobalsign().setStrictPolicyValidation(true);
        JsonNode policy = tree("{\"san\":{\"other_names\":{\"a\":{\"presence\":\"REQUIRED\"}}}}");
        assertThatThrownBy(() -> invokePrivate(
                "validateUnsupportedPolicyRequirements", new Class<?>[]{JsonNode.class}, policy))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void validatePolicy_strictWithSanOtherNamesProvided_passes() throws Exception {
        properties.getGlobalsign().setStrictPolicyValidation(true);
        properties.getGlobalsign().setSanJson("{\"other_names\":{\"foo\":\"bar\"}}");
        JsonNode policy = tree("{\"san\":{\"other_names\":{\"a\":{\"presence\":\"REQUIRED\"}}}}");
        invokePrivate("validateUnsupportedPolicyRequirements", new Class<?>[]{JsonNode.class}, policy);
    }

    @Test
    void validatePolicy_subjectDaProvided_doesNotThrow() throws Exception {
        properties.getGlobalsign().setStrictPolicyValidation(true);
        properties.getGlobalsign().setSubjectDaJson("{\"date_of_birth\":\"2000-01-01\"}");
        JsonNode policy = tree("{\"subject_da\":{\"date_of_birth\":{\"presence\":\"REQUIRED\"}}}");
        invokePrivate("validateUnsupportedPolicyRequirements", new Class<?>[]{JsonNode.class}, policy);
    }

    // ── sectionRequiresHandling — exercise primitive arms ──────────────────

    @Test
    void sectionRequiresHandling_textualStatic_true() throws Exception {
        boolean r = (boolean) invokePrivate("sectionRequiresHandling",
                new Class<?>[]{JsonNode.class}, tree("\"STATIC\""));
        assertThat(r).isTrue();
    }

    @Test
    void sectionRequiresHandling_textualForbidden_false() throws Exception {
        boolean r = (boolean) invokePrivate("sectionRequiresHandling",
                new Class<?>[]{JsonNode.class}, tree("\"FORBIDDEN\""));
        assertThat(r).isFalse();
    }

    @Test
    void sectionRequiresHandling_booleanTrue_true() throws Exception {
        boolean r = (boolean) invokePrivate("sectionRequiresHandling",
                new Class<?>[]{JsonNode.class}, tree("true"));
        assertThat(r).isTrue();
    }

    @Test
    void sectionRequiresHandling_numberPositive_true() throws Exception {
        boolean r = (boolean) invokePrivate("sectionRequiresHandling",
                new Class<?>[]{JsonNode.class}, tree("5"));
        assertThat(r).isTrue();
    }

    @Test
    void sectionRequiresHandling_numberZero_false() throws Exception {
        boolean r = (boolean) invokePrivate("sectionRequiresHandling",
                new Class<?>[]{JsonNode.class}, tree("0"));
        assertThat(r).isFalse();
    }

    @Test
    void sectionRequiresHandling_arrayWithRequired_true() throws Exception {
        boolean r = (boolean) invokePrivate("sectionRequiresHandling",
                new Class<?>[]{JsonNode.class}, tree("[\"FORBIDDEN\",\"REQUIRED\"]"));
        assertThat(r).isTrue();
    }

    @Test
    void sectionRequiresHandling_objectMincount_true() throws Exception {
        boolean r = (boolean) invokePrivate("sectionRequiresHandling",
                new Class<?>[]{JsonNode.class}, tree("{\"mincount\":3}"));
        assertThat(r).isTrue();
    }

    @Test
    void sectionRequiresHandling_objectCritical_true() throws Exception {
        boolean r = (boolean) invokePrivate("sectionRequiresHandling",
                new Class<?>[]{JsonNode.class}, tree("{\"critical\":true}"));
        assertThat(r).isTrue();
    }

    @Test
    void sectionRequiresHandling_null_false() throws Exception {
        boolean r = (boolean) invokePrivate("sectionRequiresHandling",
                new Class<?>[]{JsonNode.class}, new Object[]{null});
        assertThat(r).isFalse();
    }

    // ── resolveUri error/edge cases ─────────────────────────────────────────

    @Test
    void resolveUri_blankBase_throwsPermanent() throws Exception {
        properties.getGlobalsign().setApiBaseUrl("");
        assertThatThrownBy(() -> invokePrivate("resolveUri",
                new Class<?>[]{String.class}, "/x"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void resolveUri_absolutePath_passesThrough() throws Exception {
        Object out = invokePrivate("resolveUri",
                new Class<?>[]{String.class}, "https://other.example.com/abs");
        assertThat(out.toString()).isEqualTo("https://other.example.com/abs");
    }

    @Test
    void resolveUri_baseTrailingSlash_normalized() throws Exception {
        properties.getGlobalsign().setApiBaseUrl("https://api.example.com/v2/");
        Object out = invokePrivate("resolveUri",
                new Class<?>[]{String.class}, "x/y");
        assertThat(out.toString()).isEqualTo("https://api.example.com/v2/x/y");
    }

    // ── extractSerial location header trailing-slash edge ──────────────────

    @Test
    void issueCertificate_locationHeaderTrailingSlash_returnsEmptyTail_fallsBackToBody() throws Exception {
        HttpResponse<String> issueResp = mockResponseWithHeaders(201,
                "{\"serial\":\"BODY-SN\"}",
                Map.of("Location", List.of("/certificates/")));
        injectMockHttpReturning(issueResp);
        JsonNode policy = objectMapper.readTree("{}");
        GlobalSignAtlasClient.IssueResult res = client.issueCertificate(
                "example.com", List.of(), "csr", policy);
        // Trailing slash → idx == length-1 → skip and fall through to body lookup.
        assertThat(res.serial()).isEqualTo("BODY-SN");
    }

    @Test
    void issueCertificate_certificateObjectWithSerialField() throws Exception {
        HttpResponse<String> issueResp = mockResponseWithHeaders(200,
                "{\"certificate\":{\"serial\":\"OBJ-SR\"}}", Map.of());
        injectMockHttpReturning(issueResp);
        JsonNode policy = objectMapper.readTree("{}");
        assertThat(client.issueCertificate("example.com", List.of(), "csr", policy).serial())
                .isEqualTo("OBJ-SR");
    }

    // ── revocation reasons coverage ────────────────────────────────────────

    @Test
    void revokeCertificate_cessationReason_works() throws Exception {
        HttpResponse<String> resp = mockResponse(200, "{}");
        injectMockHttpReturning(resp);
        client.revokeCertificate("s", "CESSATION_OF_OPERATION");
    }

    @Test
    void revokeCertificate_affiliationChangedReason_works() throws Exception {
        HttpResponse<String> resp = mockResponse(200, "{}");
        injectMockHttpReturning(resp);
        client.revokeCertificate("s", "AFFILIATION_CHANGED");
    }

    @Test
    void revokeCertificate_blankReason_works() throws Exception {
        HttpResponse<String> resp = mockResponse(200, "{}");
        injectMockHttpReturning(resp);
        client.revokeCertificate("s", "");
    }
}
