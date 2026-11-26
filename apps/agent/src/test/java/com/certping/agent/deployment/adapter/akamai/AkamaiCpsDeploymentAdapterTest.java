// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.akamai;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.DeploymentResult;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.shredzone.acme4j.util.KeyPairUtils;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AkamaiCpsDeploymentAdapterTest {

    @Mock private SecretStore secretStore;

    private AkamaiCpsDeploymentAdapter adapter;

    private static final String SCOPE_JSON =
            "{\"host\":\"akab-host.luna.akamaiapis.net\"," +
            "\"enrollmentId\":\"12345\"}";

    @BeforeEach
    void setUp() {
        ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
        AkamaiCpsAuthService authService = new AkamaiCpsAuthService(secretStore, objectMapper);
        adapter = new AkamaiCpsDeploymentAdapter(authService, objectMapper);
    }

    @Test
    void deploy_missingScopeJson_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson(null);

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_invalidScopeJson_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("not-valid-json");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingHost_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("{\"enrollmentId\":\"12345\"}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("scope.host");
    }

    @Test
    void deploy_missingEnrollmentId_throwsPermanentCredentialInvalid() {
        CertDeploymentMessage msg = buildMessage();
        msg.setCredentialScopeJson("{\"host\":\"akab-host.luna.akamaiapis.net\"}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), msg))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("enrollmentId");
    }

    @Test
    void deploy_invalidCredentialJson_throwsPermanentCredentialInvalid() {
        when(secretStore.read(anyString())).thenReturn("not-valid-json");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void deploy_missingClientToken_throwsPermanentCredentialInvalid() {
        when(secretStore.read(anyString())).thenReturn(
                "{\"accessToken\":\"akab-access\",\"clientSecret\":\"secret123\"}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("clientToken");
    }

    @Test
    void deploy_missingAccessToken_throwsPermanentCredentialInvalid() {
        when(secretStore.read(anyString())).thenReturn(
                "{\"clientToken\":\"akab-token\",\"clientSecret\":\"secret123\"}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("accessToken");
    }

    @Test
    void deploy_missingClientSecret_throwsPermanentCredentialInvalid() {
        when(secretStore.read(anyString())).thenReturn(
                "{\"clientToken\":\"akab-token\",\"accessToken\":\"akab-access\"}");

        assertThatThrownBy(() -> adapter.deploy(buildBundle(), buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("clientSecret");
    }

    @Test
    void deploy_rateLimited_throwsRetryableWithDeployProviderThrottled() throws Exception {
        // Build a fresh adapter with a mocked AkamaiCpsAuthService so we can short-circuit
        // the credential KV lookup AND inject a CloseableHttpClient that returns 429 + Retry-After.
        ObjectMapper om = JsonMapper.builderWithJackson2Defaults().build();
        AkamaiCpsAuthService mockAuth = mock(AkamaiCpsAuthService.class);
        AkamaiCpsDeploymentAdapter rlAdapter = new AkamaiCpsDeploymentAdapter(mockAuth, om);

        AkamaiKvSecret kv = new AkamaiKvSecret("akab-tok", "akab-acc", "secret");
        when(mockAuth.parseKvSecret(anyString())).thenReturn(kv);
        when(mockAuth.baseUrl(anyString())).thenReturn("https://akab-host.luna.akamaiapis.net");

        CloseableHttpClient mockHttp = mock(CloseableHttpClient.class);
        when(mockAuth.buildClient(any(AkamaiKvSecret.class), anyString())).thenReturn(mockHttp);

        CloseableHttpResponse mockResp = mock(CloseableHttpResponse.class);
        when(mockResp.getCode()).thenReturn(429);
        HttpEntity entity = new StringEntity("rate limited");
        when(mockResp.getEntity()).thenReturn(entity);
        Header retryAfter = mock(Header.class);
        when(retryAfter.getValue()).thenReturn("45");
        when(mockResp.getFirstHeader("Retry-After")).thenReturn(retryAfter);

        when(mockHttp.execute(any())).thenReturn(mockResp);

        CertDeploymentMessage msg = buildMessage();

        assertThatThrownBy(() -> rlAdapter.deploy(buildBundle(), msg))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(ex -> {
                    RetryableAgentException r = (RetryableAgentException) ex;
                    assertThat(r.getErrorCode()).isEqualTo("DEPLOY_PROVIDER_THROTTLED");
                    assertThat(r.getRetryAfter()).isEqualTo(java.time.Duration.ofSeconds(45));
                });
    }

    @Test
    void validateScope_allFieldsPresent_doesNotThrow() {
        AkamaiScope scope = new AkamaiScope(
                "akab-host.luna.akamaiapis.net", "12345", 300, 480, "complete");
        adapter.validateScope(scope);
    }

    @Test
    void validateScope_missingHost_throws() {
        AkamaiScope scope = new AkamaiScope(null, "12345", null, null, null);

        assertThatThrownBy(() -> adapter.validateScope(scope))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("host");
    }

    @Test
    void validateScope_missingEnrollmentId_throws() {
        AkamaiScope scope = new AkamaiScope(
                "akab-host.luna.akamaiapis.net", null, null, null, null);

        assertThatThrownBy(() -> adapter.validateScope(scope))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"))
                .hasMessageContaining("enrollmentId");
    }

    private CertDeploymentMessage buildMessage() {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setRequestId("req-akamai-1");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-akamai-1");
        msg.setDomain("api.example.com");
        msg.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert-xref-1");
        msg.setTargetType(TargetType.AKAMAI_CPS);
        msg.setDeploymentCredHandle("https://kv-agent.vault.azure.net/secrets/akamai-cred");
        msg.setCredentialScopeJson(SCOPE_JSON);
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

    // ───────────────────── Real PEM (intermediate + self-signed root) ─────────────────────
    // The adapter parses chain certs through X509 to detect self-signed roots; tests that
    // reach buildTrustChain need real PEM blocks.

    private static String REAL_INTERMEDIATE_PEM;  // issuer != subject
    private static String REAL_ROOT_PEM;          // self-signed

    @BeforeAll
    static void buildRealPem() throws Exception {
        KeyPair rootKp = KeyPairUtils.createKeyPair(2048);
        KeyPair leafKp = KeyPairUtils.createKeyPair(2048);
        X500Principal rootDn = new X500Principal("CN=Test Root CA");
        X500Principal leafDn = new X500Principal("CN=Test Intermediate");
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 86_400_000L);

        var rootBuilder = new JcaX509v3CertificateBuilder(
                rootDn, BigInteger.valueOf(1), notBefore, notAfter, rootDn, rootKp.getPublic());
        X509Certificate rootCert = new JcaX509CertificateConverter().getCertificate(
                rootBuilder.build(new JcaContentSignerBuilder("SHA256WithRSA").build(rootKp.getPrivate())));

        var intBuilder = new JcaX509v3CertificateBuilder(
                rootDn, BigInteger.valueOf(2), notBefore, notAfter, leafDn, leafKp.getPublic());
        X509Certificate intCert = new JcaX509CertificateConverter().getCertificate(
                intBuilder.build(new JcaContentSignerBuilder("SHA256WithRSA").build(rootKp.getPrivate())));

        REAL_ROOT_PEM = pem(rootCert);
        REAL_INTERMEDIATE_PEM = pem(intCert);
    }

    private static String pem(X509Certificate cert) throws Exception {
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
    }

    private CertificateBundle realChainBundle() {
        // Chain: intermediate (kept) + root (filtered out as self-signed)
        return new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\nMIIEvQ==\n-----END PRIVATE KEY-----",
                "-----BEGIN CERTIFICATE-----\nMIILEAF==\n-----END CERTIFICATE-----",
                REAL_INTERMEDIATE_PEM,
                REAL_INTERMEDIATE_PEM + "\n" + REAL_ROOT_PEM);
    }

    private CertificateBundle rootOnlyChainBundle() {
        // Chain has only a self-signed root → buildTrustChain should reject
        return new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\nMIIEvQ==\n-----END PRIVATE KEY-----",
                "-----BEGIN CERTIFICATE-----\nMIILEAF==\n-----END CERTIFICATE-----",
                REAL_ROOT_PEM,
                REAL_ROOT_PEM);
    }

    // ───────────────────── Mock-auth adapter wiring ─────────────────────

    private record MockAuthSetup(AkamaiCpsDeploymentAdapter adapter, CloseableHttpClient http) {}

    private MockAuthSetup buildMockAuthAdapter() throws Exception {
        ObjectMapper om = JsonMapper.builderWithJackson2Defaults().build();
        AkamaiCpsAuthService mockAuth = mock(AkamaiCpsAuthService.class);
        AkamaiKvSecret kv = new AkamaiKvSecret("akab-tok", "akab-acc", "secret");
        when(mockAuth.parseKvSecret(anyString())).thenReturn(kv);
        when(mockAuth.baseUrl(anyString())).thenReturn("https://akab-host.luna.akamaiapis.net");
        CloseableHttpClient mockHttp = mock(CloseableHttpClient.class);
        when(mockAuth.buildClient(any(AkamaiKvSecret.class), anyString())).thenReturn(mockHttp);
        return new MockAuthSetup(new AkamaiCpsDeploymentAdapter(mockAuth, om), mockHttp);
    }

    private static CloseableHttpResponse mockResp(int status, String body) throws Exception {
        CloseableHttpResponse resp = mock(CloseableHttpResponse.class);
        org.mockito.Mockito.doReturn(status).when(resp).getCode();
        HttpEntity ent = body == null ? null : new StringEntity(body);
        org.mockito.Mockito.doReturn(ent).when(resp).getEntity();
        return resp;
    }

    /** Stubs http.execute() to return the given responses sequentially. Builds resp mocks
     *  OUTSIDE the thenReturn chain to avoid Mockito's UnfinishedStubbing trap. */
    private void stubExec(CloseableHttpClient http, int[] statuses, String[] bodies) throws Exception {
        CloseableHttpResponse[] arr = new CloseableHttpResponse[statuses.length];
        for (int i = 0; i < statuses.length; i++) {
            arr[i] = mockResp(statuses[i], bodies[i]);
        }
        org.mockito.stubbing.OngoingStubbing<CloseableHttpResponse> stub =
                when(http.execute(any(HttpUriRequest.class)));
        for (CloseableHttpResponse r : arr) {
            stub = stub.thenReturn(r);
        }
    }

    private CertDeploymentMessage msgWithScope(String scope) {
        CertDeploymentMessage m = buildMessage();
        m.setCredentialScopeJson(scope);
        return m;
    }

    // ───────────────────── Happy path & HTTP branches ─────────────────────

    @Test
    void deploy_happyPath_returnsDeploymentResultAndTouchesAllSteps() throws Exception {
        MockAuthSetup s = buildMockAuthAdapter();

        String enrollmentResp = "{\"pendingChanges\":[\"/cps/v2/enrollments/12345/changes/789\"]}";
        String uploadResp = "{\"change\":\"/cps/v2/enrollments/12345/changes/789\"}";
        String warningsResp = "{\"warnings\":[{\"messageCode\":\"CERTIFICATE_VALIDITY\"}]}";
        String ackResp = "{\"change\":\"/cps/v2/enrollments/12345/changes/789\"}";
        String pollResp = "{\"statusInfo\":{\"status\":\"complete\"}}";

        stubExec(s.http,
                new int[]{200, 200, 200, 200, 200},
                new String[]{enrollmentResp, uploadResp, warningsResp, ackResp, pollResp});

        CertDeploymentMessage msg = msgWithScope(
                "{\"host\":\"akab-host.luna.akamaiapis.net\",\"enrollmentId\":\"12345\","
                        + "\"pollIntervalSeconds\":1,\"pollTimeoutMinutes\":5,\"waitForStatus\":\"complete\"}");

        DeploymentResult result = s.adapter.deploy(realChainBundle(), msg);

        assertThat(result).isNotNull();
        assertThat(result.targetResourceId()).contains("/cps/v2/enrollments/12345/changes/789");
        assertThat(result.configJson()).contains("\"lastChange\"").contains("\"changeId\":\"789\"");
    }

    @Test
    void deploy_happyPath_noWarnings_skipsAcknowledge() throws Exception {
        MockAuthSetup s = buildMockAuthAdapter();
        stubExec(s.http,
                new int[]{200, 200, 200, 200},
                new String[]{
                        "{\"pendingChanges\":[\"/cps/v2/enrollments/12345/changes/789\"]}",
                        "{}",
                        "{\"warnings\":[]}",
                        "{\"statusInfo\":{\"status\":\"complete\"}}"});

        DeploymentResult result = s.adapter.deploy(realChainBundle(), msgWithScope(
                "{\"host\":\"akab-host.luna.akamaiapis.net\",\"enrollmentId\":\"12345\","
                        + "\"pollIntervalSeconds\":1,\"pollTimeoutMinutes\":5}"));
        assertThat(result).isNotNull();
    }

    @Test
    void deploy_warningsPresentButNoMessageCodes_skipsAcknowledge() throws Exception {
        MockAuthSetup s = buildMockAuthAdapter();
        stubExec(s.http,
                new int[]{200, 200, 200, 200},
                new String[]{
                        "{\"pendingChanges\":[\"/cps/v2/enrollments/12345/changes/789\"]}",
                        "{}",
                        "{\"warnings\":[{\"messageCode\":\"\"},{\"other\":\"x\"}]}",
                        "{\"statusInfo\":{\"status\":\"complete\"}}"});

        DeploymentResult result = s.adapter.deploy(realChainBundle(), msgWithScope(
                "{\"host\":\"akab-host.luna.akamaiapis.net\",\"enrollmentId\":\"12345\","
                        + "\"pollIntervalSeconds\":1,\"pollTimeoutMinutes\":5}"));
        assertThat(result).isNotNull();
    }

    @Test
    void deploy_noPendingChanges_throwsPermanentNoChange() throws Exception {
        MockAuthSetup s = buildMockAuthAdapter();
        stubExec(s.http, new int[]{200}, new String[]{"{\"pendingChanges\":[]}"});

        assertThatThrownBy(() -> s.adapter.deploy(realChainBundle(), buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_AKAMAI_NO_CHANGE"));
    }

    @Test
    void deploy_pendingChangesMissingField_throwsPermanentNoChange() throws Exception {
        MockAuthSetup s = buildMockAuthAdapter();
        stubExec(s.http, new int[]{200}, new String[]{"{}"});

        assertThatThrownBy(() -> s.adapter.deploy(realChainBundle(), buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_AKAMAI_NO_CHANGE"));
    }

    @Test
    void deploy_pendingChangeUrlEndsWithSlash_throwsPermanentNoChange() throws Exception {
        MockAuthSetup s = buildMockAuthAdapter();
        stubExec(s.http, new int[]{200},
                new String[]{"{\"pendingChanges\":[\"/cps/v2/enrollments/12345/changes/\"]}"});

        assertThatThrownBy(() -> s.adapter.deploy(realChainBundle(), buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_AKAMAI_NO_CHANGE"));
    }

    @Test
    void deploy_enrollmentFetch5xx_throwsTransient() throws Exception {
        MockAuthSetup s = buildMockAuthAdapter();
        stubExec(s.http, new int[]{500}, new String[]{"boom"});

        assertThatThrownBy(() -> s.adapter.deploy(realChainBundle(), buildMessage()))
                .isInstanceOf(TransientAgentException.class)
                .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_AKAMAI_ENROLLMENT"));
    }

    @Test
    void deploy_enrollmentFetch4xx_throwsPermanent() throws Exception {
        MockAuthSetup s = buildMockAuthAdapter();
        stubExec(s.http, new int[]{404}, new String[]{"{\"error\":\"not found\"}"});

        assertThatThrownBy(() -> s.adapter.deploy(realChainBundle(), buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_AKAMAI_ENROLLMENT"));
    }

    @Test
    void deploy_503WithoutRetryAfter_stillThrowsRetryable() throws Exception {
        MockAuthSetup s = buildMockAuthAdapter();
        CloseableHttpResponse resp = mockResp(503, "busy");
        org.mockito.Mockito.doReturn(null).when(resp).getFirstHeader("Retry-After");
        org.mockito.Mockito.doReturn(resp).when(s.http).execute(any(HttpUriRequest.class));

        assertThatThrownBy(() -> s.adapter.deploy(realChainBundle(), buildMessage()))
                .isInstanceOf(RetryableAgentException.class)
                .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_PROVIDER_THROTTLED"));
    }

    @Test
    void deploy_pollReturnsErrorStatus_throwsPermanent() throws Exception {
        MockAuthSetup s = buildMockAuthAdapter();
        stubExec(s.http,
                new int[]{200, 200, 200, 200},
                new String[]{
                        "{\"pendingChanges\":[\"/cps/v2/enrollments/12345/changes/789\"]}",
                        "{}",
                        "{\"warnings\":[]}",
                        "{\"statusInfo\":{\"status\":\"error\"}}"});

        assertThatThrownBy(() -> s.adapter.deploy(realChainBundle(), msgWithScope(
                "{\"host\":\"akab-host.luna.akamaiapis.net\",\"enrollmentId\":\"12345\","
                        + "\"pollIntervalSeconds\":1,\"pollTimeoutMinutes\":5}")))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_AKAMAI_ERROR"));
    }

    @Test
    void deploy_pollTimesOut_throwsTransientTimeout() throws Exception {
        MockAuthSetup s = buildMockAuthAdapter();
        // Provide enough "in progress" responses + first 3 setup responses
        CloseableHttpResponse enroll = mockResp(200, "{\"pendingChanges\":[\"/cps/v2/enrollments/12345/changes/789\"]}");
        CloseableHttpResponse upload = mockResp(200, "{}");
        CloseableHttpResponse warn = mockResp(200, "{\"warnings\":[]}");
        CloseableHttpResponse inProg = mockResp(200, "{\"statusInfo\":{\"status\":\"in-progress\"}}");
        org.mockito.Mockito.doReturn(enroll, upload, warn, inProg, inProg, inProg, inProg)
                .when(s.http).execute(any(HttpUriRequest.class));

        // timeoutMinutes=0 → deadline already in the past → loop body never executes → timeout thrown
        // But we still need polling step to enter; with timeout=0 the while-loop exits immediately,
        // so we hit the throw TransientAgentException("DEPLOY_AKAMAI_TIMEOUT") directly.
        assertThatThrownBy(() -> s.adapter.deploy(realChainBundle(), msgWithScope(
                "{\"host\":\"akab-host.luna.akamaiapis.net\",\"enrollmentId\":\"12345\","
                        + "\"pollIntervalSeconds\":1,\"pollTimeoutMinutes\":0}")))
                .isInstanceOf(TransientAgentException.class)
                .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_AKAMAI_TIMEOUT"));
    }

    @Test
    void deploy_missingLeafCert_throwsPermanentCertInvalid() throws Exception {
        MockAuthSetup s = buildMockAuthAdapter();
        stubExec(s.http, new int[]{200},
                new String[]{"{\"pendingChanges\":[\"/cps/v2/enrollments/12345/changes/789\"]}"});

        CertificateBundle bundle = new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\nMIIEvQ==\n-----END PRIVATE KEY-----",
                "  ",
                REAL_INTERMEDIATE_PEM,
                REAL_INTERMEDIATE_PEM);

        assertThatThrownBy(() -> s.adapter.deploy(bundle, buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CERT_INVALID"));
    }

    @Test
    void deploy_missingTrustChain_throwsPermanentCertInvalid() throws Exception {
        MockAuthSetup s = buildMockAuthAdapter();
        stubExec(s.http, new int[]{200},
                new String[]{"{\"pendingChanges\":[\"/cps/v2/enrollments/12345/changes/789\"]}"});

        CertificateBundle bundle = new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\nMIIEvQ==\n-----END PRIVATE KEY-----",
                "-----BEGIN CERTIFICATE-----\nMIILEAF==\n-----END CERTIFICATE-----",
                "",
                "");

        assertThatThrownBy(() -> s.adapter.deploy(bundle, buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CERT_INVALID"));
    }

    @Test
    void deploy_trustChainOnlyRoot_throwsPermanentCertInvalid() throws Exception {
        MockAuthSetup s = buildMockAuthAdapter();
        stubExec(s.http, new int[]{200},
                new String[]{"{\"pendingChanges\":[\"/cps/v2/enrollments/12345/changes/789\"]}"});

        assertThatThrownBy(() -> s.adapter.deploy(rootOnlyChainBundle(), buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CERT_INVALID"))
                .hasMessageContaining("root certificate");
    }

    @Test
    void deploy_genericIOException_wrappedAsDeployAkamaiFailed() throws Exception {
        MockAuthSetup s = buildMockAuthAdapter();
        org.mockito.Mockito.doThrow(new java.io.IOException("connection reset"))
                .when(s.http).execute(any(HttpUriRequest.class));

        assertThatThrownBy(() -> s.adapter.deploy(realChainBundle(), buildMessage()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_AKAMAI_FAILED"));
    }

    @Test
    void deploy_customWaitForStatus_returnsWhenMatched() throws Exception {
        MockAuthSetup s = buildMockAuthAdapter();
        stubExec(s.http,
                new int[]{200, 200, 200, 200},
                new String[]{
                        "{\"pendingChanges\":[\"/cps/v2/enrollments/12345/changes/789\"]}",
                        "{}",
                        "{\"warnings\":[]}",
                        "{\"statusInfo\":{\"status\":\"wait-review-third-party-cert\"}}"});

        DeploymentResult result = s.adapter.deploy(realChainBundle(), msgWithScope(
                "{\"host\":\"akab-host.luna.akamaiapis.net\",\"enrollmentId\":\"12345\","
                        + "\"pollIntervalSeconds\":1,\"pollTimeoutMinutes\":5,"
                        + "\"waitForStatus\":\"wait-review-third-party-cert\"}"));
        assertThat(result).isNotNull();
    }

    @Test
    void deploy_blankWaitForStatus_treatedAsComplete() throws Exception {
        MockAuthSetup s = buildMockAuthAdapter();
        stubExec(s.http,
                new int[]{200, 200, 200, 200},
                new String[]{
                        "{\"pendingChanges\":[\"/cps/v2/enrollments/12345/changes/789\"]}",
                        "{}",
                        "{\"warnings\":[]}",
                        "{\"statusInfo\":{\"status\":\"complete\"}}"});

        DeploymentResult result = s.adapter.deploy(realChainBundle(), msgWithScope(
                "{\"host\":\"akab-host.luna.akamaiapis.net\",\"enrollmentId\":\"12345\","
                        + "\"pollIntervalSeconds\":1,\"pollTimeoutMinutes\":5,\"waitForStatus\":\"  \"}"));
        assertThat(result).isNotNull();
    }
}
