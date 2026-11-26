// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.CaOrderPendingException;
import com.certping.agent.exception.CheckpointRecorder;
import com.certping.agent.exception.IssuanceCheckpoint;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.ssl.digicert.DigiCertIssuanceService;
import com.certping.agent.ssl.dns.DnsProvider;
import com.certping.agent.ssl.dns.DnsProviderSelector;
import com.certping.agent.ssl.dns.DnsTxtCleanupService;
import com.certping.agent.ssl.dns.DnsValidationDomainService;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DigiCertIssuanceServiceTest {

    @Mock private CsrKeyPairService csrKeyPairService;
    @Mock private SecretStore secretStore;
    @Mock private DnsProvider dnsProvider;
        @Mock private DnsProvider sanDnsProvider;

    private AgentProperties properties;
    private DigiCertIssuanceService service;

    private static String SELF_SIGNED_CERT_PEM;

    @BeforeAll
    static void generateTestCert() throws Exception {
        KeyPair kp = KeyPairUtils.createKeyPair(2048);
        X500Principal subject = new X500Principal("CN=test.example.com");
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);
        var certBuilder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.valueOf(System.currentTimeMillis()), notBefore, notAfter, subject, kp.getPublic());
        var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
        String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded());
        SELF_SIGNED_CERT_PEM = "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
    }

    @BeforeEach
    void setUp() {
        properties = new AgentProperties();
        properties.getDigicert().setApiBaseUrl("https://www.digicert.com/services/v2");
        properties.getDigicert().setOrderPollMaxAttempts(2);
        properties.getDigicert().setOrderPollIntervalMs(10);
        service = new DigiCertIssuanceService(
                csrKeyPairService,
                secretStore,
                properties,
                JsonMapper.builderWithJackson2Defaults().build(),
                new DnsProviderSelector(),
                new DnsTxtCleanupService(),
                new DnsValidationDomainService(),
                new com.certping.agent.ssl.KeyStagingHelper(secretStore));
    }

    // ── auth failure ──────────────────────────────────────────────────────────

    @Test
    void issue_orderReturns401_throwsPermanent() {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        givenValidCsr();

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(anyString(), eq(HttpMethod.POST), any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenThrow(HttpClientErrorException.create(
                                    HttpStatus.UNAUTHORIZED, "Unauthorized", null, null, null));
                })) {
            assertThatThrownBy(() -> service.issue("xref-1", "example.com", List.of(),
                    dnsProvider, Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("CA_AUTH_FAILED"));
        }
    }

    @Test
    void issue_orderReturns403_throwsPermanent() {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        givenValidCsr();

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(anyString(), eq(HttpMethod.POST), any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenThrow(HttpClientErrorException.create(
                                    HttpStatus.FORBIDDEN, "Forbidden", null, null, null));
                })) {
            assertThatThrownBy(() -> service.issue("xref-1", "example.com", List.of(),
                    dnsProvider, Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", null))
                    .isInstanceOf(PermanentAgentException.class);
        }
    }

    // ── rate-limit ────────────────────────────────────────────────────────────

    @Test
    void issue_429_throwsRetryableWithRetryAfter() {
        // DigiCert rate-limits via standard HTTP 429 + Retry-After header. The order POST is the
        // first call out, so triggering the throttle there is enough to exercise the catch block
        // that funnels through RateLimitClassifier.
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        givenValidCsr();

        org.springframework.http.HttpHeaders responseHeaders = new org.springframework.http.HttpHeaders();
        responseHeaders.add("Retry-After", "75");

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(anyString(), eq(HttpMethod.POST), any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenThrow(HttpClientErrorException.create(
                                    HttpStatus.TOO_MANY_REQUESTS, "Too Many Requests",
                                    responseHeaders, new byte[0], StandardCharsets.UTF_8));
                })) {
            assertThatThrownBy(() -> service.issue("xref-1", "example.com", List.of(),
                    dnsProvider, Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", null))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(e -> {
                        RetryableAgentException re = (RetryableAgentException) e;
                        assertThat(re.getErrorCode()).isEqualTo("CA_PROVIDER_THROTTLED");
                        assertThat(re.getRetryAfter()).isEqualTo(Duration.ofSeconds(75));
                    });
        }
    }

    // ── order timeout ─────────────────────────────────────────────────────────

    @Test
    void issue_orderNeverIssued_throwsPermanent() throws Exception {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("record-id-1");

        ObjectNode orderBody = buildOrderResponse(9001, "_digicert-dcv", "dcv-token-abc");
        ObjectNode pendingBody = JsonNodeFactory.instance.objectNode();
        pendingBody.put("status", "pending");

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(contains("/ssl_dv_sha2"), eq(HttpMethod.POST),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(orderBody));
                    when(mock.exchange(contains("/check-dcv"), eq(HttpMethod.PUT),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(JsonNodeFactory.instance.objectNode()));
                    when(mock.exchange(anyString(), eq(HttpMethod.GET),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(pendingBody));
                })) {
            assertThatThrownBy(() -> service.issue("xref-1", "example.com", List.of(),
                    dnsProvider, Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("CA_ORDER_TIMEOUT"));
            verify(dnsProvider).deleteTxtRecord(anyString(), anyString());
        }
    }

    // ── order rejected ────────────────────────────────────────────────────────

    @Test
    void issue_orderRejected_throwsPermanent() throws Exception {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("record-id-1");

        ObjectNode orderBody = buildOrderResponse(9002, "_digicert-dcv", "dcv-token-abc");
        ObjectNode rejectedBody = JsonNodeFactory.instance.objectNode();
        rejectedBody.put("status", "rejected");

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(contains("/ssl_dv_sha2"), eq(HttpMethod.POST),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(orderBody));
                    when(mock.exchange(contains("/check-dcv"), eq(HttpMethod.PUT),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(JsonNodeFactory.instance.objectNode()));
                    when(mock.exchange(anyString(), eq(HttpMethod.GET),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(rejectedBody));
                })) {
            assertThatThrownBy(() -> service.issue("xref-1", "example.com", List.of(),
                    dnsProvider, Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("CA_ORDER_REJECTED"));
        }
    }

    // ── happy path ────────────────────────────────────────────────────────────

    @Test
    void issue_successPath_storesCertAndReturnsResult() throws Exception {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("record-id-1");
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-1");

        ObjectNode orderBody = buildOrderResponse(9003, "_digicert-dcv", "dcv-token-abc");
        ObjectNode issuedBody = JsonNodeFactory.instance.objectNode();
        issuedBody.put("status", "issued");
        ObjectNode certRef = JsonNodeFactory.instance.objectNode();
        certRef.put("id", "cert-id-999");
        issuedBody.set("certificate", certRef);

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(contains("/ssl_dv_sha2"), eq(HttpMethod.POST),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(orderBody));
                    when(mock.exchange(contains("/check-dcv"), eq(HttpMethod.PUT),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(JsonNodeFactory.instance.objectNode()));
                    when(mock.exchange(anyString(), eq(HttpMethod.GET),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(issuedBody));
                    when(mock.exchange(contains("/download"), eq(HttpMethod.GET),
                            any(), eq(String.class)))
                            .thenReturn(ResponseEntity.ok(SELF_SIGNED_CERT_PEM));
                })) {

            IssuanceResult result = service.issue("xref-1", "example.com", List.of(),
                    dnsProvider, Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", null);

            assertThat(result.certSecretHandle()).isEqualTo("https://kv-agent.vault.azure.net/secrets/cert-xref-1");
            assertThat(result.acmeAccountHandle()).isNull();
            assertThat(result.orderId()).isEqualTo("9003");
            verify(secretStore).create(eq("xref-1"), anyString());
            verify(dnsProvider).deleteTxtRecord(anyString(), anyString());
        }
    }

    @Test
    void issue_withSanDomains_publishesTxtUsingPerDomainProviderSelection() throws Exception {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("root-record-id");
        when(sanDnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("san-record-id");
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-1");

        ObjectNode orderBody = buildOrderResponse(9004, "_digicert.example.com", "dcv-token-xyz");
        ObjectNode issuedBody = JsonNodeFactory.instance.objectNode();
        issuedBody.put("status", "issued");
        ObjectNode certRef = JsonNodeFactory.instance.objectNode();
        certRef.put("id", "cert-id-123");
        issuedBody.set("certificate", certRef);

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(contains("/ssl_dv_sha2"), eq(HttpMethod.POST),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(orderBody));
                    when(mock.exchange(contains("/check-dcv"), eq(HttpMethod.PUT),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(JsonNodeFactory.instance.objectNode()));
                    when(mock.exchange(anyString(), eq(HttpMethod.GET),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(issuedBody));
                    when(mock.exchange(contains("/download"), eq(HttpMethod.GET),
                            any(), eq(String.class)))
                            .thenReturn(ResponseEntity.ok(SELF_SIGNED_CERT_PEM));
                })) {

            IssuanceResult result = service.issue("xref-1", "example.com", List.of("api.example.com"),
                    dnsProvider, Map.of("api.example.com", sanDnsProvider), "https://kv.vault.azure.net/secrets/dc-api-key", null);

            assertThat(result.certSecretHandle()).isEqualTo("https://kv-agent.vault.azure.net/secrets/cert-xref-1");
            assertThat(result.orderId()).isEqualTo("9004");
            verify(dnsProvider).addTxtRecord(eq("_digicert.example.com"), eq("dcv-token-xyz"));
            verify(sanDnsProvider).addTxtRecord(eq("_digicert.api.example.com"), eq("dcv-token-xyz"));
            verify(dnsProvider).deleteTxtRecord(eq("_digicert.example.com"), eq("root-record-id"));
            verify(sanDnsProvider).deleteTxtRecord(eq("_digicert.api.example.com"), eq("san-record-id"));
        }
    }

    @Test
    void issue_withWildcardSan_normalizesRecordNameWithoutAsterisk() throws Exception {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("root-record-id");
        when(sanDnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("san-record-id");
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-1");

        ObjectNode orderBody = buildOrderResponse(9005, "_digicert.example.com", "dcv-token-xyz");
        ObjectNode issuedBody = JsonNodeFactory.instance.objectNode();
        issuedBody.put("status", "issued");
        ObjectNode certRef = JsonNodeFactory.instance.objectNode();
        certRef.put("id", "cert-id-555");
        issuedBody.set("certificate", certRef);

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(contains("/ssl_dv_sha2"), eq(HttpMethod.POST),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(orderBody));
                    when(mock.exchange(contains("/check-dcv"), eq(HttpMethod.PUT),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(JsonNodeFactory.instance.objectNode()));
                    when(mock.exchange(anyString(), eq(HttpMethod.GET),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(issuedBody));
                    when(mock.exchange(contains("/download"), eq(HttpMethod.GET),
                            any(), eq(String.class)))
                            .thenReturn(ResponseEntity.ok(SELF_SIGNED_CERT_PEM));
                })) {

            IssuanceResult result = service.issue("xref-1", "example.com", List.of("*.example.com"),
                    dnsProvider, Map.of("*.example.com", sanDnsProvider), "https://kv.vault.azure.net/secrets/dc-api-key", null);

            assertThat(result.certSecretHandle()).isEqualTo("https://kv-agent.vault.azure.net/secrets/cert-xref-1");
            assertThat(result.orderId()).isEqualTo("9005");
                        verify(dnsProvider).addTxtRecord(eq("_digicert.example.com"), eq("dcv-token-xyz"));
                        verify(sanDnsProvider).addTxtRecord(eq("_digicert.example.com"), eq("dcv-token-xyz"));

                        // Record name must be normalized and never contain '*'.
                        verify(dnsProvider, never()).addTxtRecord(eq("_digicert.*.example.com"), anyString());
                        verify(sanDnsProvider, never()).addTxtRecord(eq("_digicert.*.example.com"), anyString());

                        verify(dnsProvider).deleteTxtRecord(eq("_digicert.example.com"), eq("root-record-id"));
                        verify(sanDnsProvider).deleteTxtRecord(eq("_digicert.example.com"), eq("san-record-id"));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void givenValidCsr() {
        when(csrKeyPairService.generateCsrAndKeyPair(anyString(), any()))
                .thenReturn(new CsrKeyPairService.CsrKeyPairResult(
                        new byte[]{1, 2, 3},
                        "-----BEGIN CERTIFICATE REQUEST-----\nMIICVD==\n-----END CERTIFICATE REQUEST-----",
                        "-----BEGIN PRIVATE KEY-----\nMIIEvg==\n-----END PRIVATE KEY-----"
                ));
    }

    private ObjectNode buildOrderResponse(int orderId, String dcvName, String dcvValue) {
        ObjectNode dcvToken = JsonNodeFactory.instance.objectNode();
        dcvToken.put("name", dcvName);
        dcvToken.put("value", dcvValue);

        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("id", orderId);
        body.set("dcv_token", dcvToken);
        return body;
    }

    // ── Resume with checkpoint skips POST /order/certificate ──────────────────

    @Test
    void issue_resumeWithCheckpoint_skipsPostCertificate() throws Exception {
        when(secretStore.read(eq("https://kv.vault.azure.net/secrets/dc-api-key")))
                .thenReturn("dc-api-key-12345");
        // Staged key+CSR — same packed format KeyStagingHelper writes.
        String stagingPath = "https://kv-agent.vault.azure.net/secrets/xref-resume-key-staging";
        String packed = """
                -----BEGIN PRIVATE KEY MARKER-----
                -----BEGIN PRIVATE KEY-----
                MIIEvg==
                -----END PRIVATE KEY-----
                -----END PRIVATE KEY MARKER-----
                -----BEGIN CERTIFICATE REQUEST-----
                MIICVD==
                -----END CERTIFICATE REQUEST-----""";
        when(secretStore.read(eq(stagingPath))).thenReturn(packed);
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-resume");

        ObjectNode issuedBody = JsonNodeFactory.instance.objectNode();
        issuedBody.put("status", "issued");
        ObjectNode certRef = JsonNodeFactory.instance.objectNode();
        certRef.put("id", "cert-id-resume");
        issuedBody.set("certificate", certRef);

        com.certping.agent.exception.IssuanceCheckpoint resume =
                new com.certping.agent.exception.IssuanceCheckpoint(
                        "DIGICERT",
                        com.certping.agent.exception.IssuanceCheckpoint.Step.ORDER_CREATED,
                        "9999", null, stagingPath);

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    // poll: GET /order/certificate/{id} — only call we expect on resume.
                    when(mock.exchange(anyString(), eq(HttpMethod.GET),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(issuedBody));
                    when(mock.exchange(contains("/download"), eq(HttpMethod.GET),
                            any(), eq(String.class)))
                            .thenReturn(ResponseEntity.ok(SELF_SIGNED_CERT_PEM));
                })) {

            IssuanceResult result = service.issue("xref-resume", "example.com", List.of(),
                    dnsProvider, Map.of(),
                    "https://kv.vault.azure.net/secrets/dc-api-key", null, resume, CheckpointRecorder.NONE);

            assertThat(result.certSecretHandle())
                    .isEqualTo("https://kv-agent.vault.azure.net/secrets/cert-xref-resume");
            assertThat(result.orderId()).isEqualTo("9999");

            // The whole point: key was read from KV, never generated; no DCV publish;
            // staging slot purged on terminal success.
            verify(secretStore).read(eq(stagingPath));
            verify(secretStore).delete(eq(stagingPath));
            verifyNoInteractions(csrKeyPairService);
            verify(dnsProvider, never()).addTxtRecord(anyString(), anyString());
        }
    }

    @Test
    void issue_collectOfAnUnvalidatedOrder_validatesThenWaits() throws Exception {
        when(secretStore.read(eq("https://kv.vault.azure.net/secrets/dc-api-key"))).thenReturn("dc-api-key-12345");
        String stagingPath = "https://kv-agent.vault.azure.net/secrets/xref-resume-key-staging";
        when(secretStore.read(eq(stagingPath))).thenReturn(stagedKeyAndCsr());
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("record-id-2");
        CheckpointRecorder recorder = mock(CheckpointRecorder.class);
        Instant placedAt = Instant.now().minusSeconds(20);
        IssuanceCheckpoint resume = new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_CREATED,
                "9999", null, stagingPath, null, null, "_dnsauth\ndcv-token-abc", placedAt);

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(contains("/check-dcv"), eq(HttpMethod.PUT),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(JsonNodeFactory.instance.objectNode()));
                    when(mock.exchange(anyString(), eq(HttpMethod.GET),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(pendingBody()));
                })) {

            assertThatThrownBy(() -> service.issue("xref-resume", "example.com", List.of(), dnsProvider, Map.of(),
                    "https://kv.vault.azure.net/secrets/dc-api-key", null, resume, recorder))
                    .isInstanceOfSatisfying(CaOrderPendingException.class, e -> {
                        assertThat(e.getOrderRef()).isEqualTo("9999");
                        assertThat(e.getRetryAfter()).isEqualTo(Duration.ofSeconds(15));
                        assertThat(e.getCheckpoint().step()).isEqualTo(IssuanceCheckpoint.Step.ORDER_FINALIZED);
                        assertThat(e.getCheckpoint().orderPlacedAt()).isEqualTo(placedAt);
                    });

            RestTemplate rest = ignored.constructed().get(0);
            verify(rest, never()).exchange(anyString(), eq(HttpMethod.POST), any(), eq(tools.jackson.databind.JsonNode.class));
            verify(rest).exchange(contains("/order/certificate/9999/check-dcv"), eq(HttpMethod.PUT), any(),
                    eq(tools.jackson.databind.JsonNode.class));
            verify(rest, times(2)).exchange(anyString(), eq(HttpMethod.GET), any(), eq(tools.jackson.databind.JsonNode.class));
            verify(dnsProvider).addTxtRecord(eq("_dnsauth"), eq("dcv-token-abc"));
            verify(dnsProvider).deleteTxtRecord(anyString(), eq("record-id-2"));
            verify(recorder).recordAnswered(argThat(c -> c.step() == IssuanceCheckpoint.Step.ORDER_FINALIZED));
            verifyNoInteractions(csrKeyPairService);
            verify(secretStore, never()).delete(anyString());
        }
    }

    @Test
    void issue_collectOfAnUnvalidatedOrderAlreadyIssued_storesWithoutValidating() throws Exception {
        when(secretStore.read(eq("https://kv.vault.azure.net/secrets/dc-api-key"))).thenReturn("dc-api-key-12345");
        String stagingPath = "https://kv-agent.vault.azure.net/secrets/xref-resume-key-staging";
        when(secretStore.read(eq(stagingPath))).thenReturn(stagedKeyAndCsr());
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-resume");
        IssuanceCheckpoint resume = new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_CREATED,
                "9999", null, stagingPath, null, null, "_dnsauth\ndcv-token-abc", Instant.now().minusSeconds(45));
        ObjectNode issuedBody = JsonNodeFactory.instance.objectNode();
        issuedBody.put("status", "issued");
        issuedBody.set("certificate", JsonNodeFactory.instance.objectNode().put("id", "cert-id-resume"));

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(anyString(), eq(HttpMethod.GET),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(issuedBody));
                    when(mock.exchange(contains("/download"), eq(HttpMethod.GET), any(), eq(String.class)))
                            .thenReturn(ResponseEntity.ok(SELF_SIGNED_CERT_PEM));
                })) {

            IssuanceResult result = service.issue("xref-resume", "example.com", List.of(), dnsProvider, Map.of(),
                    "https://kv.vault.azure.net/secrets/dc-api-key", null, resume, CheckpointRecorder.NONE);

            assertThat(result.orderId()).isEqualTo("9999");
            verifyNoInteractions(dnsProvider);
            verify(ignored.constructed().get(0), never()).exchange(contains("/check-dcv"), eq(HttpMethod.PUT), any(),
                    eq(tools.jackson.databind.JsonNode.class));
        }
    }

    @Test
    void issueWithExternalCsr_withARecorder_placesValidatesAndWaitsLikeAnyOrder() throws Exception {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("record-id-1");
        CheckpointRecorder recorder = mock(CheckpointRecorder.class);

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(contains("/ssl_dv_sha2"), eq(HttpMethod.POST),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(buildOrderResponse(9101, "_dnsauth", "dcv-token-abc")));
                    when(mock.exchange(contains("/check-dcv"), eq(HttpMethod.PUT),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(JsonNodeFactory.instance.objectNode()));
                    when(mock.exchange(anyString(), eq(HttpMethod.GET),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(pendingBody()));
                })) {
            assertThatThrownBy(() -> service.issueWithExternalCsr("xref-ext", "example.com", List.of(), dnsProvider,
                    Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", "-----BEGIN CERTIFICATE REQUEST-----\nMIICVD==\n-----END CERTIFICATE REQUEST-----",
                    null, null, recorder))
                    .isInstanceOfSatisfying(CaOrderPendingException.class, e -> {
                        assertThat(e.getOrderRef()).isEqualTo("9101");
                        assertThat(e.getCheckpoint().step()).isEqualTo(IssuanceCheckpoint.Step.ORDER_FINALIZED);
                        assertThat(e.getCheckpoint().privateKeyKvPath()).isNull();
                    });

            verify(recorder).recordAnswered(argThat(c -> c.step() == IssuanceCheckpoint.Step.ORDER_CREATED
                    && "9101".equals(c.orderRef())));
            verifyNoInteractions(csrKeyPairService);
            verify(secretStore, never()).create(anyString(), anyString());
        }
    }

    @Test
    void issueWithExternalCsr_collectOfAnIssuedOrder_storesTheChainOnlyAndNeverReorders() throws Exception {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-ext");
        IssuanceCheckpoint resume = new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_FINALIZED,
                "9101", null, null, null, null, "_dnsauth\ndcv-token-abc", Instant.now().minusSeconds(45));
        ObjectNode issuedBody = JsonNodeFactory.instance.objectNode();
        issuedBody.put("status", "issued");
        issuedBody.set("certificate", JsonNodeFactory.instance.objectNode().put("id", "cert-id-ext"));

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(anyString(), eq(HttpMethod.GET),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(issuedBody));
                    when(mock.exchange(contains("/download"), eq(HttpMethod.GET), any(), eq(String.class)))
                            .thenReturn(ResponseEntity.ok(SELF_SIGNED_CERT_PEM));
                })) {
            IssuanceResult result = service.issueWithExternalCsr("xref-ext", "example.com", List.of(), dnsProvider,
                    Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", "-----BEGIN CERTIFICATE REQUEST-----\nMIICVD==\n-----END CERTIFICATE REQUEST-----",
                    null, resume, CheckpointRecorder.NONE);

            assertThat(result.orderId()).isEqualTo("9101");
            assertThat(result.keyCustody()).isEqualTo(com.certping.agent.ssl.KeyCustody.CUSTOMER_HELD);
            RestTemplate rest = ignored.constructed().get(0);
            verify(rest, never()).exchange(anyString(), eq(HttpMethod.POST), any(), eq(tools.jackson.databind.JsonNode.class));
            var bundle = org.mockito.ArgumentCaptor.forClass(String.class);
            verify(secretStore).create(eq("xref-ext"), bundle.capture());
            assertThat(bundle.getValue()).doesNotContain("PRIVATE KEY");
            verify(secretStore, never()).delete(anyString());
            verifyNoInteractions(dnsProvider);
        }
    }

    @Test
    void issue_firstAttempt_placesValidatesAndWaitsForTheOrder() throws Exception {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        givenValidCsr();
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/xref-1-key-staging");
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("record-id-1");
        CheckpointRecorder recorder = mock(CheckpointRecorder.class);

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(contains("/ssl_dv_sha2"), eq(HttpMethod.POST),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(buildOrderResponse(9001, "_dnsauth", "dcv-token-abc")));
                    when(mock.exchange(contains("/check-dcv"), eq(HttpMethod.PUT),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(JsonNodeFactory.instance.objectNode()));
                    when(mock.exchange(anyString(), eq(HttpMethod.GET),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(pendingBody()));
                })) {
            assertThatThrownBy(() -> service.issue("xref-1", "example.com", List.of(), dnsProvider, Map.of(),
                    "https://kv.vault.azure.net/secrets/dc-api-key", null, null, recorder))
                    .isInstanceOfSatisfying(CaOrderPendingException.class, e -> {
                        assertThat(e.getProvider()).isEqualTo("DIGICERT");
                        assertThat(e.getOrderRef()).isEqualTo("9001");
                        assertThat(e.getRetryAfter()).isEqualTo(Duration.ofSeconds(15));
                        assertThat(e.getCheckpoint().step()).isEqualTo(IssuanceCheckpoint.Step.ORDER_FINALIZED);
                        assertThat(e.getCheckpoint().privateKeyKvPath()).endsWith("xref-1-key-staging");
                    });

            RestTemplate rest = ignored.constructed().get(0);
            verify(rest, times(1)).exchange(anyString(), eq(HttpMethod.GET), any(), eq(tools.jackson.databind.JsonNode.class));
            verify(dnsProvider).deleteTxtRecord(anyString(), eq("record-id-1"));
            verify(secretStore, never()).delete(anyString());
            var captor = org.mockito.ArgumentCaptor.forClass(IssuanceCheckpoint.class);
            verify(recorder, times(2)).recordAnswered(captor.capture());
            assertThat(captor.getAllValues()).extracting(IssuanceCheckpoint::step)
                    .containsExactly(IssuanceCheckpoint.Step.ORDER_CREATED, IssuanceCheckpoint.Step.ORDER_FINALIZED);
        }
    }

    @Test
    void issue_collectOfAValidatedOrder_checksStatusOnlyAndBacksOff() throws Exception {
        when(secretStore.read(eq("https://kv.vault.azure.net/secrets/dc-api-key"))).thenReturn("dc-api-key-12345");
        String stagingPath = "https://kv-agent.vault.azure.net/secrets/xref-resume-key-staging";
        when(secretStore.read(eq(stagingPath))).thenReturn(stagedKeyAndCsr());
        IssuanceCheckpoint resume = new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_FINALIZED,
                "9999", null, stagingPath, null, null, "_dnsauth\ndcv-token-abc", Instant.now().minusSeconds(120));

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> when(mock.exchange(anyString(), eq(HttpMethod.GET),
                        any(), eq(tools.jackson.databind.JsonNode.class)))
                        .thenReturn(ResponseEntity.ok(pendingBody())))) {

            assertThatThrownBy(() -> service.issue("xref-resume", "example.com", List.of(), dnsProvider, Map.of(),
                    "https://kv.vault.azure.net/secrets/dc-api-key", null, resume, CheckpointRecorder.NONE))
                    .isInstanceOfSatisfying(CaOrderPendingException.class,
                            e -> assertThat(e.getRetryAfter()).isEqualTo(Duration.ofSeconds(30)));

            RestTemplate rest = ignored.constructed().get(0);
            verify(rest, times(1)).exchange(anyString(), any(HttpMethod.class), any(), eq(tools.jackson.databind.JsonNode.class));
            verifyNoInteractions(dnsProvider);
        }
    }

    @Test
    void issue_collectPastTheDeadline_givesTheOrderUp() throws Exception {
        when(secretStore.read(eq("https://kv.vault.azure.net/secrets/dc-api-key"))).thenReturn("dc-api-key-12345");
        String stagingPath = "https://kv-agent.vault.azure.net/secrets/xref-resume-key-staging";
        when(secretStore.read(eq(stagingPath))).thenReturn(stagedKeyAndCsr());
        IssuanceCheckpoint resume = new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_FINALIZED,
                "9999", null, stagingPath, null, null, null, Instant.now().minusSeconds(301));

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> when(mock.exchange(anyString(), eq(HttpMethod.GET),
                        any(), eq(tools.jackson.databind.JsonNode.class)))
                        .thenReturn(ResponseEntity.ok(pendingBody())))) {

            assertThatThrownBy(() -> service.issue("xref-resume", "example.com", List.of(), dnsProvider, Map.of(),
                    "https://kv.vault.azure.net/secrets/dc-api-key", null, resume, CheckpointRecorder.NONE))
                    .isInstanceOfSatisfying(PermanentAgentException.class, e -> {
                        assertThat(e.getErrorCode()).isEqualTo("CA_ORDER_TIMEOUT");
                        assertThat(e.getMessage()).contains("order 9999").contains("deadline 300 s");
                    });
        }
    }

    @Test
    void issue_collectOfAnIssuedOrder_storesWithoutValidatingAgain() throws Exception {
        when(secretStore.read(eq("https://kv.vault.azure.net/secrets/dc-api-key"))).thenReturn("dc-api-key-12345");
        String stagingPath = "https://kv-agent.vault.azure.net/secrets/xref-resume-key-staging";
        when(secretStore.read(eq(stagingPath))).thenReturn(stagedKeyAndCsr());
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-resume");
        IssuanceCheckpoint resume = new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_FINALIZED,
                "9999", null, stagingPath, null, null, "_dnsauth\ndcv-token-abc", Instant.now().minusSeconds(45));
        ObjectNode issuedBody = JsonNodeFactory.instance.objectNode();
        issuedBody.put("status", "issued");
        issuedBody.set("certificate", JsonNodeFactory.instance.objectNode().put("id", "cert-id-resume"));

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(anyString(), eq(HttpMethod.GET),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(issuedBody));
                    when(mock.exchange(contains("/download"), eq(HttpMethod.GET), any(), eq(String.class)))
                            .thenReturn(ResponseEntity.ok(SELF_SIGNED_CERT_PEM));
                })) {

            IssuanceResult result = service.issue("xref-resume", "example.com", List.of(), dnsProvider, Map.of(),
                    "https://kv.vault.azure.net/secrets/dc-api-key", null, resume, CheckpointRecorder.NONE);

            assertThat(result.orderId()).isEqualTo("9999");
            assertThat(result.certSecretHandle()).endsWith("cert-xref-resume");
            verify(secretStore).delete(eq(stagingPath));
            verifyNoInteractions(dnsProvider, csrKeyPairService);
        }
    }

    private static ObjectNode pendingBody() {
        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("status", "pending");
        return body;
    }

    @Test
    void issue_recordsTheDcvTokenOnTheOrderCheckpoint() throws Exception {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("record-id-1");
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/xref-1-key-staging");
        ObjectNode pendingBody = JsonNodeFactory.instance.objectNode();
        pendingBody.put("status", "pending");
        CheckpointRecorder recorder = mock(CheckpointRecorder.class);

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(contains("/ssl_dv_sha2"), eq(HttpMethod.POST),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(buildOrderResponse(9001, "_dnsauth", "dcv-token-abc")));
                    when(mock.exchange(contains("/check-dcv"), eq(HttpMethod.PUT),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(JsonNodeFactory.instance.objectNode()));
                    when(mock.exchange(anyString(), eq(HttpMethod.GET),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(pendingBody));
                })) {
            assertThatThrownBy(() -> service.issue("xref-1", "example.com", List.of(), dnsProvider, Map.of(),
                    "https://kv.vault.azure.net/secrets/dc-api-key", null, null, recorder))
                    .isInstanceOf(CaOrderPendingException.class);
        }

        var captor = org.mockito.ArgumentCaptor.forClass(com.certping.agent.exception.IssuanceCheckpoint.class);
        verify(recorder, times(2)).recordAnswered(captor.capture());
        com.certping.agent.exception.IssuanceCheckpoint order = captor.getAllValues().get(0);
        assertThat(order.step()).isEqualTo(com.certping.agent.exception.IssuanceCheckpoint.Step.ORDER_CREATED);
        assertThat(order.orderRef()).isEqualTo("9001");
        assertThat(DigiCertIssuanceService.DcvToken.parse(order.dcv()))
                .isEqualTo(new DigiCertIssuanceService.DcvToken("_dnsauth", "dcv-token-abc"));
        assertThat(order.orderPlacedAt()).isNotNull();
    }

    @Test
    void dcvToken_roundTripsAndRejectsWhatIsNotOne() {
        DigiCertIssuanceService.DcvToken token = new DigiCertIssuanceService.DcvToken("_dnsauth", "v");

        assertThat(DigiCertIssuanceService.DcvToken.parse(token.serialize())).isEqualTo(token);
        assertThat(DigiCertIssuanceService.DcvToken.parse(null)).isNull();
        assertThat(DigiCertIssuanceService.DcvToken.parse("no-separator")).isNull();
    }

    private static String stagedKeyAndCsr() {
        return """
                -----BEGIN PRIVATE KEY MARKER-----
                -----BEGIN PRIVATE KEY-----
                MIIEvg==
                -----END PRIVATE KEY-----
                -----END PRIVATE KEY MARKER-----
                -----BEGIN CERTIFICATE REQUEST-----
                MIICVD==
                -----END CERTIFICATE REQUEST-----""";
    }

    // ── External CSR (Akamai CPS) — issueWithExternalCsr exercises issueCore w/ null privateKey + null kvPath ────

    @Test
    void issueWithExternalCsr_successPath_storesChainOnly() throws Exception {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec-1");
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-ext");

        ObjectNode orderBody = buildOrderResponse(7777, "_digicert-dcv", "dcv-token-ext");
        ObjectNode issuedBody = JsonNodeFactory.instance.objectNode();
        issuedBody.put("status", "issued");
        ObjectNode certRef = JsonNodeFactory.instance.objectNode();
        certRef.put("id", "cert-id-ext");
        issuedBody.set("certificate", certRef);

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(contains("/ssl_dv_sha2"), eq(HttpMethod.POST),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(orderBody));
                    when(mock.exchange(contains("/check-dcv"), eq(HttpMethod.PUT),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(JsonNodeFactory.instance.objectNode()));
                    when(mock.exchange(anyString(), eq(HttpMethod.GET),
                            any(), eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(issuedBody));
                    when(mock.exchange(contains("/download"), eq(HttpMethod.GET),
                            any(), eq(String.class)))
                            .thenReturn(ResponseEntity.ok(SELF_SIGNED_CERT_PEM));
                })) {

            IssuanceResult result = service.issueWithExternalCsr(
                    "xref-ext", "example.com", List.of(), dnsProvider, Map.of(),
                    "https://kv.vault.azure.net/secrets/dc-api-key",
                    "-----BEGIN CERTIFICATE REQUEST-----\nMIICVD==\n-----END CERTIFICATE REQUEST-----",
                    365);

            assertThat(result.orderId()).isEqualTo("7777");
            assertThat(result.certSecretHandle())
                    .isEqualTo("https://kv-agent.vault.azure.net/secrets/cert-xref-ext");
            // External CSR path: no CSR generated, no staging slot used.
            verifyNoInteractions(csrKeyPairService);
        }
    }

    // ── order response missing id ──────────────────────────────────

    @Test
    void issue_orderResponseMissingId_throwsPermanent() {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        givenValidCsr();
        ObjectNode noIdBody = JsonNodeFactory.instance.objectNode();
        ObjectNode dcv = JsonNodeFactory.instance.objectNode();
        dcv.put("name", "_digicert-dcv");
        dcv.put("value", "v");
        noIdBody.set("dcv_token", dcv);

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> when(mock.exchange(anyString(), eq(HttpMethod.POST), any(),
                        eq(tools.jackson.databind.JsonNode.class)))
                        .thenReturn(ResponseEntity.ok(noIdBody)))) {

            assertThatThrownBy(() -> service.issue("xref-1", "example.com", List.of(),
                    dnsProvider, Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DIGICERT_ORDER_INVALID"));
        }
    }

    // ── order cancelled (the second arm of the rejected/cancelled OR) ───

    @Test
    void issue_orderCancelled_throwsPermanent() throws Exception {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec-1");

        ObjectNode orderBody = buildOrderResponse(9100, "_digicert-dcv", "tok");
        ObjectNode cancelledBody = JsonNodeFactory.instance.objectNode();
        cancelledBody.put("status", "cancelled");

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(contains("/ssl_dv_sha2"), eq(HttpMethod.POST), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(orderBody));
                    when(mock.exchange(contains("/check-dcv"), eq(HttpMethod.PUT), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(JsonNodeFactory.instance.objectNode()));
                    when(mock.exchange(anyString(), eq(HttpMethod.GET), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(cancelledBody));
                })) {
            assertThatThrownBy(() -> service.issue("xref-1", "example.com", List.of(),
                    dnsProvider, Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("CA_ORDER_REJECTED"));
        }
    }

    // ── HttpClientErrorException non-401/403/429 → TransientAgentException ──

    @Test
    void issue_order500_throwsTransient_caApiError() {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        givenValidCsr();

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> when(mock.exchange(anyString(), eq(HttpMethod.POST), any(),
                        eq(tools.jackson.databind.JsonNode.class)))
                        .thenThrow(HttpClientErrorException.create(
                                HttpStatus.BAD_REQUEST, "Bad Request", null, null, null)))) {

            assertThatThrownBy(() -> service.issue("xref-1", "example.com", List.of(),
                    dnsProvider, Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", null))
                    .isInstanceOf(com.certping.agent.exception.TransientAgentException.class)
                    .satisfies(e -> assertThat(((com.certping.agent.exception.TransientAgentException) e).getErrorCode())
                            .isEqualTo("CA_API_ERROR"));
        }
    }

    // ── attachCheckpoint Retryable branch — 429 after ORDER_CREATED attaches checkpoint ──

    @Test
    void issue_checkDcv429AfterOrderCreated_attachesCheckpointToRetryable() throws Exception {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        // storeSecret must return non-null so KeyStagingHelper.stage(...) returns a real
        // path — that path is what triggers the non-null state in issueCore (a null
        // privateKeyKvPath disables checkpointing entirely).
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-1");
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec-1");

        ObjectNode orderBody = buildOrderResponse(9200, "_digicert-dcv", "tok");
        org.springframework.http.HttpHeaders rh = new org.springframework.http.HttpHeaders();
        rh.add("Retry-After", "30");

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(contains("/ssl_dv_sha2"), eq(HttpMethod.POST), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(orderBody));
                    when(mock.exchange(contains("/check-dcv"), eq(HttpMethod.PUT), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenThrow(HttpClientErrorException.create(
                                    HttpStatus.TOO_MANY_REQUESTS, "Too Many Requests",
                                    rh, new byte[0], StandardCharsets.UTF_8));
                })) {

            assertThatThrownBy(() -> service.issue("xref-1", "example.com", List.of(),
                    dnsProvider, Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", null))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(e -> {
                        RetryableAgentException re = (RetryableAgentException) e;
                        assertThat(re.getErrorCode()).isEqualTo("CA_PROVIDER_THROTTLED");
                        // checkpoint attached because state reached ORDER_CREATED before the failure
                        assertThat(re.getCheckpoint()).isNotNull();
                        assertThat(re.getCheckpoint().orderRef()).isEqualTo("9200");
                    });
            // TXT cleanup still happens in the finally block before the throw
            verify(dnsProvider).deleteTxtRecord(anyString(), anyString());
        }
    }

    @Test
    void issue_recordsTheOrderDigiCertCreatedOnceItAnswers() throws Exception {
        CheckpointRecorder recorder = mock(CheckpointRecorder.class);
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-1");
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec-1");

        ObjectNode orderBody = buildOrderResponse(9200, "_digicert-dcv", "tok");
        org.springframework.http.HttpHeaders rh = new org.springframework.http.HttpHeaders();
        rh.add("Retry-After", "30");

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(contains("/ssl_dv_sha2"), eq(HttpMethod.POST), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(orderBody));
                    when(mock.exchange(contains("/check-dcv"), eq(HttpMethod.PUT), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenThrow(HttpClientErrorException.create(
                                    HttpStatus.TOO_MANY_REQUESTS, "Too Many Requests",
                                    rh, new byte[0], StandardCharsets.UTF_8));
                })) {

            assertThatThrownBy(() -> service.issue("xref-1", "example.com", List.of(),
                    dnsProvider, Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", null, null, recorder))
                    .isInstanceOf(RetryableAgentException.class);

            verify(recorder).recordAnswered(argThat(created -> created.step()
                    == com.certping.agent.exception.IssuanceCheckpoint.Step.ORDER_CREATED
                    && "9200".equals(created.orderRef())));
        }
    }

    // ── TransientAgentException rethrown through attachCheckpoint non-Retryable branch ──

    @Test
    void issue_pollThrowsTransient_propagatesWithoutCheckpointAttachment() throws Exception {
        // Simulate a transient exception bubbling out of the poll loop while state is at
        // ORDER_CREATED. attachCheckpoint's `instanceof RetryableAgentException` arm is
        // false → returns the exception unchanged (line 324).
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec-1");

        ObjectNode orderBody = buildOrderResponse(9300, "_digicert-dcv", "tok");

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(contains("/ssl_dv_sha2"), eq(HttpMethod.POST), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(orderBody));
                    when(mock.exchange(contains("/check-dcv"), eq(HttpMethod.PUT), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(JsonNodeFactory.instance.objectNode()));
                    // poll: HTTP 500 → wrapped to TransientAgentException
                    when(mock.exchange(anyString(), eq(HttpMethod.GET), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenThrow(HttpClientErrorException.create(
                                    HttpStatus.INTERNAL_SERVER_ERROR, "boom", null, null, null));
                })) {

            assertThatThrownBy(() -> service.issue("xref-1", "example.com", List.of(),
                    dnsProvider, Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", null))
                    .isInstanceOf(com.certping.agent.exception.TransientAgentException.class);
        }
    }

    // ── generic Exception → DIGICERT_ISSUANCE_FAILED + RateLimit branch on generic Exception ──

    @Test
    void issue_genericExceptionInsideTry_wrappedAsPermanent() {
        // Trigger a non-Http RuntimeException from inside the try block (DNS provider) so
        // the catch(Exception) wraps it into DIGICERT_ISSUANCE_FAILED.
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-1");
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString()))
                .thenThrow(new RuntimeException("dns provider down"));

        ObjectNode orderBody = buildOrderResponse(9700, "_digicert-dcv", "tok");
        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> when(mock.exchange(anyString(), eq(HttpMethod.POST), any(),
                        eq(tools.jackson.databind.JsonNode.class)))
                        .thenReturn(ResponseEntity.ok(orderBody)))) {
            assertThatThrownBy(() -> service.issue("xref-1", "example.com", List.of(),
                    dnsProvider, Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DIGICERT_ISSUANCE_FAILED"));
        }
    }

    // ── parseFirstCert failure → CERT_PARSE_FAILED (caught as Exception → DIGICERT_ISSUANCE_FAILED) ──

    @Test
    void issue_downloadReturnsGarbage_failsParseAndThrows() throws Exception {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec-1");
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-bad");

        ObjectNode orderBody = buildOrderResponse(9400, "_digicert-dcv", "tok");
        ObjectNode issuedBody = JsonNodeFactory.instance.objectNode();
        issuedBody.put("status", "issued");
        ObjectNode certRef = JsonNodeFactory.instance.objectNode();
        certRef.put("id", "cert-id-bad");
        issuedBody.set("certificate", certRef);

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(contains("/ssl_dv_sha2"), eq(HttpMethod.POST), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(orderBody));
                    when(mock.exchange(contains("/check-dcv"), eq(HttpMethod.PUT), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(JsonNodeFactory.instance.objectNode()));
                    when(mock.exchange(anyString(), eq(HttpMethod.GET), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(issuedBody));
                    when(mock.exchange(contains("/download"), eq(HttpMethod.GET), any(),
                            eq(String.class)))
                            .thenReturn(ResponseEntity.ok("not-a-pem-anywhere"));
                })) {

            assertThatThrownBy(() -> service.issue("xref-1", "example.com", List.of(),
                    dnsProvider, Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> {
                        // parseFirstCert throws CERT_PARSE_FAILED PermanentAgentException;
                        // the outer catch(PermanentAgentException) rethrows it directly.
                        String code = ((PermanentAgentException) e).getErrorCode();
                        assertThat(code).isIn("CERT_PARSE_FAILED", "DIGICERT_ISSUANCE_FAILED");
                    });
        }
    }

    // ── poll body null → status="unknown" timeout path ─────────

    @Test
    void issue_pollResponseBodyNull_treatedAsUnknown_timeout() throws Exception {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec-1");

        ObjectNode orderBody = buildOrderResponse(9500, "_digicert-dcv", "tok");

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(contains("/ssl_dv_sha2"), eq(HttpMethod.POST), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(orderBody));
                    when(mock.exchange(contains("/check-dcv"), eq(HttpMethod.PUT), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(JsonNodeFactory.instance.objectNode()));
                    // poll returns null body → triggers `order != null ? ... : "unknown"`
                    when(mock.exchange(anyString(), eq(HttpMethod.GET), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(null));
                })) {

            assertThatThrownBy(() -> service.issue("xref-1", "example.com", List.of(),
                    dnsProvider, Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("CA_ORDER_TIMEOUT"));
        }
    }

    // ── buildDcvRecordName — apiRecordName blank/empty falls back to "_digicert." + domain ──

    @Test
    void issue_dcvTokenNameBlank_fallsBackToDigicertDotDomain() throws Exception {
        when(secretStore.read(anyString())).thenReturn("dc-api-key-12345");
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec-1");
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-blank");

        // Build an order response with an empty dcv_token.name to force the fallback in
        // buildDcvRecordName: apiRecordName isBlank → return "_digicert." + domain.
        ObjectNode orderBody = buildOrderResponse(9600, "", "tok-blank");
        ObjectNode issuedBody = JsonNodeFactory.instance.objectNode();
        issuedBody.put("status", "issued");
        ObjectNode certRef = JsonNodeFactory.instance.objectNode();
        certRef.put("id", "cert-id-blank");
        issuedBody.set("certificate", certRef);

        try (MockedConstruction<RestTemplate> ignored = Mockito.mockConstruction(RestTemplate.class,
                (mock, ctx) -> {
                    when(mock.exchange(contains("/ssl_dv_sha2"), eq(HttpMethod.POST), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(orderBody));
                    when(mock.exchange(contains("/check-dcv"), eq(HttpMethod.PUT), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(JsonNodeFactory.instance.objectNode()));
                    when(mock.exchange(anyString(), eq(HttpMethod.GET), any(),
                            eq(tools.jackson.databind.JsonNode.class)))
                            .thenReturn(ResponseEntity.ok(issuedBody));
                    when(mock.exchange(contains("/download"), eq(HttpMethod.GET), any(),
                            eq(String.class)))
                            .thenReturn(ResponseEntity.ok(SELF_SIGNED_CERT_PEM));
                })) {

            service.issue("xref-1", "example.com", List.of(),
                    dnsProvider, Map.of(), "https://kv.vault.azure.net/secrets/dc-api-key", null);

            // fallback path was taken → record name is "_digicert." + domain
            verify(dnsProvider).addTxtRecord(eq("_digicert.example.com"), eq("tok-blank"));
        }
    }
}
