// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.CheckpointRecorder;
import com.certping.agent.exception.IssuanceCheckpoint;
import com.certping.agent.ssl.dns.DnsPropagationVerifier;
import com.certping.agent.ssl.dns.DnsProvider;
import com.certping.agent.ssl.dns.DnsProviderSelector;
import com.certping.agent.ssl.dns.DnsTxtCleanupService;
import com.certping.agent.ssl.dns.DnsTxtWorkflowService;
import com.certping.agent.ssl.dns.DnsValidationDomainService;
import com.certping.agent.ssl.globalsign.GlobalSignAtlasClient;
import com.certping.agent.ssl.globalsign.GlobalSignIssuanceService;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.JsonNode;
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
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.shredzone.acme4j.util.KeyPairUtils;
import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.ObjectMapper;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class GlobalSignIssuanceServiceTest {

    @Mock private CsrKeyPairService csrKeyPairService;
    @Mock private SecretStore secretStore;
    @Mock private GlobalSignAtlasClient atlasClient;
    @Mock private DnsPropagationVerifier dnsPropagationVerifier;
    @Mock private DnsProvider dnsProvider;

    private AgentProperties properties;
    private GlobalSignIssuanceService service;

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
        properties.getGlobalsign().setPollMaxAttempts(1);
        properties.getGlobalsign().setPollIntervalMs(1000);
        service = new GlobalSignIssuanceService(
                csrKeyPairService,
                secretStore,
                properties,
                atlasClient,
                new DnsTxtCleanupService(),
                new DnsValidationDomainService(),
                new DnsTxtWorkflowService(new DnsProviderSelector(), dnsPropagationVerifier,
                        new DnsTxtCleanupService()),
                new KeyStagingHelper(secretStore));
    }

    // ── Resume with checkpoint skips POST /certificates ──────────────────────

    @Test
    void issue_resumeWithCheckpoint_skipsPostCertificates() throws Exception {
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

        // ensureDomainsVerified skips re-claim work when findVerifiedClaimId returns a value.
        when(atlasClient.findVerifiedClaimId(anyString())).thenReturn("claim-already-verified");
        // validationpolicy fetch is best-effort; null is fine for resume.
        when(atlasClient.getValidationPolicy()).thenReturn(null);

        // Poll loop sees the cert already ISSUED — single fetch returns the leaf PEM.
        ObjectNode certNode = JsonNodeFactory.instance.objectNode();
        certNode.put("status", "ISSUED");
        certNode.put("certificate", SELF_SIGNED_CERT_PEM);
        when(atlasClient.getCertificate(eq("SERIAL-RESUME-123"))).thenReturn((JsonNode) certNode);
        when(atlasClient.getTrustChainPem()).thenReturn(SELF_SIGNED_CERT_PEM);

        IssuanceCheckpoint resume = new IssuanceCheckpoint(
                "GLOBALSIGN",
                IssuanceCheckpoint.Step.ORDER_CREATED,
                "SERIAL-RESUME-123",
                null,
                stagingPath);

        IssuanceResult result = service.issue(
                "xref-resume", "example.com", false, List.of(),
                dnsProvider, Map.of(), null, resume, false, CheckpointRecorder.NONE);

        assertThat(result.certSecretHandle())
                .isEqualTo("https://kv-agent.vault.azure.net/secrets/cert-xref-resume");

        // The whole point of resume: POST /certificates was NOT called, key was read
        // from KV (no CSR-gen), staging slot was purged on terminal success.
        verify(atlasClient, never()).issueCertificate(anyString(), any(), anyString(), any());
        verify(atlasClient).getCertificate(eq("SERIAL-RESUME-123"));
        verify(secretStore).read(eq(stagingPath));
        verify(secretStore).delete(eq(stagingPath));
        verifyNoInteractions(csrKeyPairService);
    }

    // ── Private helper coverage via reflection ───────────────────────────────

    private static final ObjectMapper MAPPER = JsonMapper.builderWithJackson2Defaults().build();

    private Object invokePrivate(String methodName, Class<?>[] paramTypes, Object... args) throws Exception {
        Method m = GlobalSignIssuanceService.class.getDeclaredMethod(methodName, paramTypes);
        m.setAccessible(true);
        try {
            return m.invoke(service, args);
        } catch (InvocationTargetException ite) {
            if (ite.getCause() instanceof RuntimeException re) throw re;
            throw ite;
        }
    }

    @Test
    void resolveCsrPolicy_nullPolicy_returnsRsa2048Defaults() throws Exception {
        Object result = invokePrivate("resolveCsrPolicy", new Class<?>[]{JsonNode.class}, new Object[]{null});
        Method keyType = result.getClass().getDeclaredMethod("keyType");
        Method keySize = result.getClass().getDeclaredMethod("keySize");
        keyType.setAccessible(true); keySize.setAccessible(true);
        assertThat(keyType.invoke(result)).isEqualTo("RSA");
        assertThat(keySize.invoke(result)).isEqualTo(2048);
    }

    @Test
    void resolveCsrPolicy_rsa4096_picked() throws Exception {
        JsonNode policy = MAPPER.readTree(
                "{\"public_key\":{\"key_format\":\"PKCS10\",\"key_type\":\"RSA\",\"allowed_lengths\":[4096]}}");
        Object result = invokePrivate("resolveCsrPolicy", new Class<?>[]{JsonNode.class}, policy);
        Method keyType = result.getClass().getDeclaredMethod("keyType");
        Method keySize = result.getClass().getDeclaredMethod("keySize");
        keyType.setAccessible(true); keySize.setAccessible(true);
        assertThat(keyType.invoke(result)).isEqualTo("RSA");
        assertThat(keySize.invoke(result)).isEqualTo(4096);
    }

    @Test
    void resolveCsrPolicy_ecdsa256_picked() throws Exception {
        JsonNode policy = MAPPER.readTree(
                "{\"public_key\":{\"key_format\":\"PKCS10\",\"key_type\":\"ECDSA\",\"allowed_lengths\":[256,384]}}");
        Object result = invokePrivate("resolveCsrPolicy", new Class<?>[]{JsonNode.class}, policy);
        Method keyType = result.getClass().getDeclaredMethod("keyType");
        Method keySize = result.getClass().getDeclaredMethod("keySize");
        keyType.setAccessible(true); keySize.setAccessible(true);
        assertThat(keyType.invoke(result)).isEqualTo("ECDSA");
        assertThat(keySize.invoke(result)).isEqualTo(256);
    }

    @Test
    void resolveCsrPolicy_unsupportedKeyFormat_throwsPermanent() throws Exception {
        JsonNode policy = MAPPER.readTree("{\"public_key\":{\"key_format\":\"CRMF\"}}");
        assertThatThrownBy(() -> invokePrivate("resolveCsrPolicy", new Class<?>[]{JsonNode.class}, policy))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void extractLeafPem_certificateField() throws Exception {
        JsonNode cert = MAPPER.readTree("{\"certificate\":\"PEM-A\"}");
        Object pem = invokePrivate("extractLeafPem", new Class<?>[]{JsonNode.class}, cert);
        assertThat(pem).isEqualTo("PEM-A");
    }

    @Test
    void extractLeafPem_pemField() throws Exception {
        JsonNode cert = MAPPER.readTree("{\"pem\":\"PEM-B\"}");
        Object pem = invokePrivate("extractLeafPem", new Class<?>[]{JsonNode.class}, cert);
        assertThat(pem).isEqualTo("PEM-B");
    }

    @Test
    void extractLeafPem_crtField() throws Exception {
        JsonNode cert = MAPPER.readTree("{\"crt\":\"PEM-C\"}");
        Object pem = invokePrivate("extractLeafPem", new Class<?>[]{JsonNode.class}, cert);
        assertThat(pem).isEqualTo("PEM-C");
    }

    @Test
    void extractLeafPem_dataCertificate() throws Exception {
        JsonNode cert = MAPPER.readTree("{\"data\":{\"certificate\":\"PEM-D\"}}");
        Object pem = invokePrivate("extractLeafPem", new Class<?>[]{JsonNode.class}, cert);
        assertThat(pem).isEqualTo("PEM-D");
    }

    @Test
    void extractLeafPem_missing_throwsPermanent() throws Exception {
        JsonNode cert = MAPPER.readTree("{\"status\":\"ISSUED\"}");
        assertThatThrownBy(() -> invokePrivate("extractLeafPem", new Class<?>[]{JsonNode.class}, cert))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void stripWildcard_withWildcard_strips() throws Exception {
        Object out = invokePrivate("stripWildcard", new Class<?>[]{String.class}, "*.example.com");
        assertThat(out).isEqualTo("example.com");
    }

    @Test
    void stripWildcard_noWildcard_unchanged() throws Exception {
        Object out = invokePrivate("stripWildcard", new Class<?>[]{String.class}, "example.com");
        assertThat(out).isEqualTo("example.com");
    }

    @Test
    void stripWildcard_null_returnsEmpty() throws Exception {
        Object out = invokePrivate("stripWildcard", new Class<?>[]{String.class}, new Object[]{null});
        assertThat(out).isEqualTo("");
    }

    @Test
    void extractRegistrableDomain_subdomain_returnsBase() throws Exception {
        Object out = invokePrivate("extractRegistrableDomain", new Class<?>[]{String.class}, "api.example.com");
        assertThat(out).isEqualTo("example.com");
    }

    @Test
    void extractRegistrableDomain_alreadyRoot_unchanged() throws Exception {
        Object out = invokePrivate("extractRegistrableDomain", new Class<?>[]{String.class}, "example.com");
        assertThat(out).isEqualTo("example.com");
    }

    @Test
    void extractRegistrableDomain_deepSubdomain_returnsLastTwoLabels() throws Exception {
        Object out = invokePrivate("extractRegistrableDomain", new Class<?>[]{String.class}, "a.b.c.example.com");
        assertThat(out).isEqualTo("example.com");
    }

    @Test
    void extractRegistrableDomain_blank_returnsNull() throws Exception {
        Object out = invokePrivate("extractRegistrableDomain", new Class<?>[]{String.class}, "");
        assertThat(out).isNull();
    }

    @Test
    void normalizeClaimTokenForDnsTxt_addsPrefix() throws Exception {
        Object out = invokePrivate("normalizeClaimTokenForDnsTxt", new Class<?>[]{String.class}, "abc123");
        assertThat(out).isEqualTo("globalsign-domain-verification=abc123");
    }

    @Test
    void normalizeClaimTokenForDnsTxt_keepsExistingPrefix() throws Exception {
        Object out = invokePrivate("normalizeClaimTokenForDnsTxt",
                new Class<?>[]{String.class}, "globalsign-domain-verification=xyz");
        assertThat(out).isEqualTo("globalsign-domain-verification=xyz");
    }

    @Test
    void normalizeClaimTokenForDnsTxt_blank_throws() throws Exception {
        assertThatThrownBy(() -> invokePrivate("normalizeClaimTokenForDnsTxt",
                new Class<?>[]{String.class}, ""))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void parseFirstCert_validPem_returnsCert() throws Exception {
        Object cert = invokePrivate("parseFirstCert", new Class<?>[]{String.class}, SELF_SIGNED_CERT_PEM);
        assertThat(cert).isInstanceOf(X509Certificate.class);
    }

    @Test
    void parseFirstCert_malformed_throwsPermanent() throws Exception {
        assertThatThrownBy(() -> invokePrivate("parseFirstCert",
                new Class<?>[]{String.class}, "not a pem"))
                .isInstanceOf(PermanentAgentException.class);
    }

    // ── pollUntilIssued / extractLeafPem extras ──────────────────────────────

    @Test
    void pollUntilIssued_revoked_throwsPermanent() throws Exception {
        ObjectNode cert = JsonNodeFactory.instance.objectNode();
        cert.put("status", "REVOKED");
        when(atlasClient.getCertificate(anyString())).thenReturn((JsonNode) cert);
        assertThatThrownBy(() -> invokePrivate("pollUntilIssued",
                new Class<?>[]{String.class, String.class}, "S1", "example.com"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void pollUntilIssued_rejected_throwsPermanent() throws Exception {
        ObjectNode cert = JsonNodeFactory.instance.objectNode();
        cert.put("status", "REJECTED");
        when(atlasClient.getCertificate(anyString())).thenReturn((JsonNode) cert);
        assertThatThrownBy(() -> invokePrivate("pollUntilIssued",
                new Class<?>[]{String.class, String.class}, "S2", "example.com"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void pollUntilIssued_failed_throwsPermanent() throws Exception {
        ObjectNode cert = JsonNodeFactory.instance.objectNode();
        cert.put("status", "FAILED");
        when(atlasClient.getCertificate(anyString())).thenReturn((JsonNode) cert);
        assertThatThrownBy(() -> invokePrivate("pollUntilIssued",
                new Class<?>[]{String.class, String.class}, "S3", "example.com"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void pollUntilIssued_timesOut_throwsPermanent() throws Exception {
        ObjectNode pending = JsonNodeFactory.instance.objectNode();
        pending.put("status", "PENDING");
        when(atlasClient.getCertificate(anyString())).thenReturn((JsonNode) pending);
        // pollMaxAttempts=1 in setUp → after first attempt, timeout (no sleep called because loop ends).
        assertThatThrownBy(() -> invokePrivate("pollUntilIssued",
                new Class<?>[]{String.class, String.class}, "S4", "example.com"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("GLOBALSIGN_ISSUANCE_TIMEOUT"));
    }

    @Test
    void pollUntilIssued_active_returns() throws Exception {
        ObjectNode cert = JsonNodeFactory.instance.objectNode();
        cert.put("status", "ACTIVE");
        when(atlasClient.getCertificate(anyString())).thenReturn((JsonNode) cert);
        Object out = invokePrivate("pollUntilIssued",
                new Class<?>[]{String.class, String.class}, "S5", "example.com");
        assertThat(out).isNotNull();
    }

    @Test
    void pollUntilIssued_valid_returns() throws Exception {
        ObjectNode cert = JsonNodeFactory.instance.objectNode();
        cert.put("status", "VALID");
        when(atlasClient.getCertificate(anyString())).thenReturn((JsonNode) cert);
        Object out = invokePrivate("pollUntilIssued",
                new Class<?>[]{String.class, String.class}, "S6", "example.com");
        assertThat(out).isNotNull();
    }

    @Test
    void waitUntilClaimVerified_verified_returns() throws Exception {
        ObjectNode claim = JsonNodeFactory.instance.objectNode();
        claim.put("status", "VERIFIED");
        when(atlasClient.getDomainClaim(anyString())).thenReturn((JsonNode) claim);
        invokePrivate("waitUntilClaimVerified",
                new Class<?>[]{String.class, String.class}, "claim-1", "example.com");
    }

    @Test
    void waitUntilClaimVerified_error_throwsPermanent() throws Exception {
        ObjectNode claim = JsonNodeFactory.instance.objectNode();
        claim.put("status", "ERROR");
        when(atlasClient.getDomainClaim(anyString())).thenReturn((JsonNode) claim);
        assertThatThrownBy(() -> invokePrivate("waitUntilClaimVerified",
                new Class<?>[]{String.class, String.class}, "claim-1", "example.com"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void waitUntilClaimVerified_failed_throwsPermanent() throws Exception {
        ObjectNode claim = JsonNodeFactory.instance.objectNode();
        claim.put("status", "FAILED");
        when(atlasClient.getDomainClaim(anyString())).thenReturn((JsonNode) claim);
        assertThatThrownBy(() -> invokePrivate("waitUntilClaimVerified",
                new Class<?>[]{String.class, String.class}, "c", "d"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void waitUntilClaimVerified_rejected_throwsPermanent() throws Exception {
        ObjectNode claim = JsonNodeFactory.instance.objectNode();
        claim.put("status", "REJECTED");
        when(atlasClient.getDomainClaim(anyString())).thenReturn((JsonNode) claim);
        assertThatThrownBy(() -> invokePrivate("waitUntilClaimVerified",
                new Class<?>[]{String.class, String.class}, "c", "d"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void waitUntilClaimVerified_timesOut_throwsPermanent() throws Exception {
        ObjectNode claim = JsonNodeFactory.instance.objectNode();
        claim.put("status", "PENDING");
        when(atlasClient.getDomainClaim(anyString())).thenReturn((JsonNode) claim);
        assertThatThrownBy(() -> invokePrivate("waitUntilClaimVerified",
                new Class<?>[]{String.class, String.class}, "c", "d"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("GLOBALSIGN_DOMAIN_VERIFICATION_TIMEOUT"));
    }

    // ── extractRegistrableDomain edge ────────────────────────────────────────

    @Test
    void extractRegistrableDomain_singleLabel_returnsAsIs() throws Exception {
        Object out = invokePrivate("extractRegistrableDomain", new Class<?>[]{String.class}, "localhost");
        assertThat(out).isEqualTo("localhost");
    }

    @Test
    void extractRegistrableDomain_nullInput_returnsNull() throws Exception {
        Object out = invokePrivate("extractRegistrableDomain", new Class<?>[]{String.class}, new Object[]{null});
        assertThat(out).isNull();
    }

    // ── resolveCsrPolicy extras ──────────────────────────────────────────────

    @Test
    void resolveCsrPolicy_ecdsa384_secondPreference() throws Exception {
        JsonNode policy = MAPPER.readTree(
                "{\"public_key\":{\"key_format\":\"PKCS10\",\"key_type\":\"ECDSA\",\"allowed_lengths\":[384,521]}}");
        Object result = invokePrivate("resolveCsrPolicy", new Class<?>[]{JsonNode.class}, policy);
        Method keySize = result.getClass().getDeclaredMethod("keySize");
        keySize.setAccessible(true);
        assertThat(keySize.invoke(result)).isEqualTo(384);
    }

    @Test
    void resolveCsrPolicy_ecdsa521_thirdPreference() throws Exception {
        JsonNode policy = MAPPER.readTree(
                "{\"public_key\":{\"key_format\":\"PKCS10\",\"key_type\":\"ECDSA\",\"allowed_lengths\":[521]}}");
        Object result = invokePrivate("resolveCsrPolicy", new Class<?>[]{JsonNode.class}, policy);
        Method keySize = result.getClass().getDeclaredMethod("keySize");
        keySize.setAccessible(true);
        assertThat(keySize.invoke(result)).isEqualTo(521);
    }

    @Test
    void resolveCsrPolicy_ecdsaUnknownSize_returnsFirst() throws Exception {
        JsonNode policy = MAPPER.readTree(
                "{\"public_key\":{\"key_format\":\"PKCS10\",\"key_type\":\"ECDSA\",\"allowed_lengths\":[123,456]}}");
        Object result = invokePrivate("resolveCsrPolicy", new Class<?>[]{JsonNode.class}, policy);
        Method keySize = result.getClass().getDeclaredMethod("keySize");
        keySize.setAccessible(true);
        assertThat(keySize.invoke(result)).isEqualTo(123);
    }

    @Test
    void resolveCsrPolicy_rsa3072_secondPreference() throws Exception {
        JsonNode policy = MAPPER.readTree(
                "{\"public_key\":{\"key_format\":\"PKCS10\",\"key_type\":\"RSA\",\"allowed_lengths\":[3072,4096]}}");
        Object result = invokePrivate("resolveCsrPolicy", new Class<?>[]{JsonNode.class}, policy);
        Method keySize = result.getClass().getDeclaredMethod("keySize");
        keySize.setAccessible(true);
        assertThat(keySize.invoke(result)).isEqualTo(3072);
    }

    @Test
    void resolveCsrPolicy_rsaOddSize_returnsFirst() throws Exception {
        JsonNode policy = MAPPER.readTree(
                "{\"public_key\":{\"key_format\":\"PKCS10\",\"key_type\":\"RSA\",\"allowed_lengths\":[1024,5120]}}");
        Object result = invokePrivate("resolveCsrPolicy", new Class<?>[]{JsonNode.class}, policy);
        Method keySize = result.getClass().getDeclaredMethod("keySize");
        keySize.setAccessible(true);
        assertThat(keySize.invoke(result)).isEqualTo(1024);
    }

    @Test
    void resolveCsrPolicy_emptyAllowedLengths_keepsDefault() throws Exception {
        JsonNode policy = MAPPER.readTree(
                "{\"public_key\":{\"key_format\":\"PKCS10\",\"key_type\":\"RSA\",\"allowed_lengths\":[]}}");
        Object result = invokePrivate("resolveCsrPolicy", new Class<?>[]{JsonNode.class}, policy);
        Method keySize = result.getClass().getDeclaredMethod("keySize");
        keySize.setAccessible(true);
        assertThat(keySize.invoke(result)).isEqualTo(2048);
    }

    // ── normalizeClaimTokenForDnsTxt: null arg ───────────────────────────────

    @Test
    void normalizeClaimTokenForDnsTxt_null_throws() throws Exception {
        assertThatThrownBy(() -> invokePrivate("normalizeClaimTokenForDnsTxt",
                new Class<?>[]{String.class}, new Object[]{null}))
                .isInstanceOf(PermanentAgentException.class);
    }

    // ── Full issue() path with all domains already VERIFIED ──────────────────

    @Test
    void issue_newOrder_happyPath_returnsResult() throws Exception {
        when(atlasClient.findVerifiedClaimId(anyString())).thenReturn("verified-existing");
        when(atlasClient.getValidationPolicy()).thenReturn(null);

        when(csrKeyPairService.generateCsrAndKeyPair(anyString(), any(), anyString(), org.mockito.ArgumentMatchers.anyInt()))
                .thenReturn(new CsrKeyPairService.CsrKeyPairResult(null,
                        "-----BEGIN CERTIFICATE REQUEST-----\nMIIC\n-----END CERTIFICATE REQUEST-----",
                        "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"));
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-new-xref");

        when(atlasClient.issueCertificate(anyString(), any(), anyString(), any(), any()))
                .thenReturn(new GlobalSignAtlasClient.IssueResult("NEW-SERIAL"));

        ObjectNode cert = JsonNodeFactory.instance.objectNode();
        cert.put("status", "ISSUED");
        cert.put("certificate", SELF_SIGNED_CERT_PEM);
        when(atlasClient.getCertificate(eq("NEW-SERIAL"))).thenReturn((JsonNode) cert);
        when(atlasClient.getTrustChainPem()).thenReturn(SELF_SIGNED_CERT_PEM);

        IssuanceResult result = service.issue(
                "xref-new", "example.com", false, List.of(),
                dnsProvider, Map.of(), 30, null, false, CheckpointRecorder.NONE);

        assertThat(result.certSecretHandle())
                .isEqualTo("https://kv-agent.vault.azure.net/secrets/cert-new-xref");
        verify(atlasClient).issueCertificate(eq("example.com"), any(), anyString(), any(), eq(30));
    }

    @Test
    void issue_recordsTheOrderGlobalSignCreatedOnceItAnswers() throws Exception {
        when(atlasClient.findVerifiedClaimId(anyString())).thenReturn("verified-existing");
        when(atlasClient.getValidationPolicy()).thenReturn(null);

        when(csrKeyPairService.generateCsrAndKeyPair(anyString(), any(), anyString(), org.mockito.ArgumentMatchers.anyInt()))
                .thenReturn(new CsrKeyPairService.CsrKeyPairResult(null,
                        "-----BEGIN CERTIFICATE REQUEST-----\nMIIC\n-----END CERTIFICATE REQUEST-----",
                        "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"));
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-new-xref");

        when(atlasClient.issueCertificate(anyString(), any(), anyString(), any(), any()))
                .thenReturn(new GlobalSignAtlasClient.IssueResult("NEW-SERIAL"));

        ObjectNode cert = JsonNodeFactory.instance.objectNode();
        cert.put("status", "ISSUED");
        cert.put("certificate", SELF_SIGNED_CERT_PEM);
        when(atlasClient.getCertificate(eq("NEW-SERIAL"))).thenReturn((JsonNode) cert);
        when(atlasClient.getTrustChainPem()).thenReturn(SELF_SIGNED_CERT_PEM);

        CheckpointRecorder recorder = mock(CheckpointRecorder.class);
        IssuanceResult result = service.issue(
                "xref-new", "example.com", false, List.of(),
                dnsProvider, Map.of(), 30, null, false, recorder);

        assertThat(result.certSecretHandle())
                .isEqualTo("https://kv-agent.vault.azure.net/secrets/cert-new-xref");
        verify(recorder).recordAnswered(argThat(created -> created.step() == IssuanceCheckpoint.Step.ORDER_CREATED
                && "NEW-SERIAL".equals(created.orderRef())));
    }

    @Test
    void issueWithExternalCsr_happyPath_returnsResult() throws Exception {
        when(atlasClient.findVerifiedClaimId(anyString())).thenReturn("verified-existing");
        when(atlasClient.getValidationPolicy()).thenReturn(null);
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-ext");

        when(atlasClient.issueCertificate(anyString(), any(), anyString(), any(), any()))
                .thenReturn(new GlobalSignAtlasClient.IssueResult("EXT-SERIAL"));

        ObjectNode cert = JsonNodeFactory.instance.objectNode();
        cert.put("status", "ISSUED");
        cert.put("certificate", SELF_SIGNED_CERT_PEM);
        when(atlasClient.getCertificate(eq("EXT-SERIAL"))).thenReturn((JsonNode) cert);
        when(atlasClient.getTrustChainPem()).thenReturn(SELF_SIGNED_CERT_PEM);

        IssuanceResult result = service.issueWithExternalCsr(
                "xref-ext", "example.com", false, List.of(),
                dnsProvider, Map.of(),
                "-----BEGIN CERTIFICATE REQUEST-----\nXYZ\n-----END CERTIFICATE REQUEST-----",
                null, false);

        assertThat(result.certSecretHandle()).isEqualTo("https://kv-agent.vault.azure.net/secrets/cert-ext");
        assertThat(result.keyCustody()).isEqualTo(com.certping.agent.ssl.KeyCustody.CUSTOMER_HELD);
    }

    @Test
    void issue_emptyDomain_throwsIllegalArg() {
        // DnsValidationDomainService rejects an empty primary domain.
        assertThatThrownBy(() -> service.issue("xref", "", false, List.of(),
                dnsProvider, Map.of(), null, null, false, CheckpointRecorder.NONE))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // ── extractLeafPem additional fields not previously tested ──────────────

    @Test
    void extractLeafPem_certificateNonTextual_falls_through_to_pem() throws Exception {
        // {"certificate":{}} -> certificate.isTextual()==false → fall to next branch.
        JsonNode cert = MAPPER.readTree("{\"certificate\":{},\"pem\":\"PEM-from-fallback\"}");
        Object pem = invokePrivate("extractLeafPem", new Class<?>[]{JsonNode.class}, cert);
        assertThat(pem).isEqualTo("PEM-from-fallback");
    }
}
