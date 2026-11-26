// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.CheckpointRecorder;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.handler.acme.AcmeAccountResult;
import com.certping.agent.handler.acme.AcmeAccountService;
import com.certping.agent.ssl.acme.LetsEncryptAcmeService;
import com.certping.agent.ssl.dns.DnsPropagationVerifier;
import com.certping.agent.ssl.dns.DnsProvider;
import com.certping.agent.ssl.dns.DnsProviderSelector;
import com.certping.agent.ssl.dns.DnsTxtCleanupService;
import com.certping.agent.ssl.dns.DnsTxtWorkflowService;
import com.certping.agent.ssl.dns.DnsValidationDomainService;
import com.certping.agent.secrets.SecretStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.exception.AcmeRateLimitedException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.net.URL;
import java.time.Duration;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class LetsEncryptAcmeServiceTest {

    @Mock private AcmeAccountService acmeAccountService;
    @Mock private CsrKeyPairService csrKeyPairService;
    @Mock private SecretStore secretStore;
        @Mock private DnsPropagationVerifier dnsPropagationVerifier;
    @Mock private DnsProvider dnsProvider;

    private AgentProperties properties;
    private LetsEncryptAcmeService service;

    @BeforeEach
    void setUp() {
        properties = new AgentProperties();
        properties.getAcme().setDirectoryUrl("https://acme-staging-v02.api.letsencrypt.org/directory");
                properties.getKeyvault().setUri("https://kv-agent.vault.azure.net");
        properties.getAcme().getChallenge().setDnsPropagationWaitMs(1);
        properties.getAcme().getChallenge().setMaxAttempts(2);
        properties.getAcme().getChallenge().setPollIntervalMs(1);
        service = new LetsEncryptAcmeService(
                acmeAccountService,
                csrKeyPairService,
                secretStore,
                properties,
                new DnsTxtCleanupService(),
                new DnsValidationDomainService(),
                new DnsTxtWorkflowService(new DnsProviderSelector(), dnsPropagationVerifier,
                        new DnsTxtCleanupService()),
                new com.certping.agent.ssl.KeyStagingHelper(secretStore));
    }

    //  helper: configure mocks for happy path flow 

    private void givenValidAccount() throws Exception {
        KeyPair kp = KeyPairUtils.createKeyPair(2048);
        AcmeAccountResult acmeResult = new AcmeAccountResult(
                kp,
                new URL("https://acme-staging.api.letsencrypt.org/acme/acct/123456"),
                "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1"
        );
        when(acmeAccountService.getOrCreate(anyString(), any())).thenReturn(acmeResult);
    }

    private void givenValidCsr() {
        when(csrKeyPairService.generateCsrAndKeyPair(anyString(), any()))
                .thenReturn(new CsrKeyPairService.CsrKeyPairResult(
                        new byte[]{1, 2, 3},
                        "-----BEGIN CERTIFICATE REQUEST-----\nMIICVD==\n-----END CERTIFICATE REQUEST-----",
                        "-----BEGIN PRIVATE KEY-----\nMIIEvg==\n-----END PRIVATE KEY-----"
                ));
    }

    //  success path via mocked ACME Session 

    @Test
    void issue_success_storesCertAndReturnsResult() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("record-id-1");
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-1");

        // Mock the entire ACME4j stack
        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);

        // Build a self-signed certificate for the result
        KeyPair certKp = KeyPairUtils.createKeyPair(2048);
        org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder builder =
                new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                        new javax.security.auth.x500.X500Principal("CN=example.com"),
                        java.math.BigInteger.valueOf(System.currentTimeMillis()),
                        new java.util.Date(),
                        new java.util.Date(System.currentTimeMillis() + 90L * 24 * 3600 * 1000),
                        new javax.security.auth.x500.X500Principal("CN=example.com"),
                        certKp.getPublic());
        var signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256WithRSA").build(certKp.getPrivate());
        java.security.cert.X509Certificate leafCert =
                new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(builder.build(signer));

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("digest-val");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leafCert));

        // Mock account.newOrder() chain
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> sessionMock = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            IssuanceResult result = service.issue(
                    "organization-1", "xref-1", "example.com",
                    false,
                    List.of(), dnsProvider, Map.of(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1", null);

            assertThat(result.certSecretHandle()).isEqualTo("https://kv-agent.vault.azure.net/secrets/cert-xref-1");
            assertThat(result.acmeAccountHandle()).isEqualTo("https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1");
            assertThat(result.orderId()).isNull();
            verify(dnsProvider).addTxtRecord(anyString(), anyString());
            verify(dnsPropagationVerifier).awaitAll(anyList(), eq(false));
            verify(dnsProvider).deleteTxtRecord(anyString(), anyString());
            verify(secretStore).create(eq("xref-1"), anyString());
        }
    }

    //  order already VALID at entry: skip challenge + finalize

    @Test
    void issue_orderAlreadyValidAtEntry_skipsChallengeAndFinalize() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-resume");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Certificate mockCert = mock(Certificate.class);

        X509Certificate leafCert = buildSelfSignedCert("CN=example.com");

        // Entry probe sees VALID → service skips DNS TXT add, challenge trigger,
        // executeOrderWithRetry, and waitForOrderValid; jumps to getCertificate.
        when(mockOrder.getStatus()).thenReturn(org.shredzone.acme4j.Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leafCert));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            IssuanceResult result = service.issue(
                    "organization-1", "xref-resume", "example.com",
                    false, List.of(), dnsProvider, Map.of(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1",
                    null);

            assertThat(result.certSecretHandle())
                    .isEqualTo("https://kv-agent.vault.azure.net/secrets/cert-xref-resume");

            // The whole point: no DNS work, no finalize call.
            verify(dnsProvider, never()).addTxtRecord(anyString(), anyString());
            verify(dnsPropagationVerifier, never()).awaitAll(anyList(), anyBoolean());
            verify(mockOrder, never()).execute(any(byte[].class));
        }
    }

    //  reused authorizations: READY orders and already VALID authorizations

    /** Wires login, account and newOrder to hand back {@code order}, whose certificate is {@code leaf}. */
    private Login loginReturning(Order order, X509Certificate leaf) throws Exception {
        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Certificate mockCert = mock(Certificate.class);
        when(order.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leaf));
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(order);
        when(mockLogin.getAccount()).thenReturn(mockAccount);
        return mockLogin;
    }

    private Authorization authorization(String domain, Dns01Challenge challenge, Status... statuses) {
        Authorization auth = mock(Authorization.class);
        when(auth.getIdentifier()).thenReturn(Identifier.dns(domain));
        when(auth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(challenge));
        when(auth.getStatus()).thenReturn(statuses[0], java.util.Arrays.copyOfRange(statuses, 1, statuses.length));
        return auth;
    }

    private IssuanceResult issueWith(Login login, List<String> sans) {
        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(login))) {
            return service.issue("organization-1", "xref-reuse", "example.com", false, sans, dnsProvider,
                    Map.of(), "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1", null);
        }
    }

    @Test
    void issue_orderReadyAtEntry_finalizesWithoutChallenges() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(secretStore.create(anyString(), anyString())).thenReturn("https://kv-agent.vault.azure.net/secrets/r");
        Order mockOrder = mock(Order.class);
        Dns01Challenge challenge = mock(Dns01Challenge.class);
        Authorization auth = authorization("example.com", challenge, Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(auth));
        when(mockOrder.getStatus()).thenReturn(Status.READY, Status.VALID);
        Login login = loginReturning(mockOrder, buildSelfSignedCert("CN=example.com"));

        IssuanceResult result = issueWith(login, List.of());

        assertThat(result.certSecretHandle()).isEqualTo("https://kv-agent.vault.azure.net/secrets/r");
        verify(mockOrder).execute(any(byte[].class));
        verify(challenge, never()).trigger();
        verify(dnsProvider, never()).addTxtRecord(anyString(), anyString());
        verify(dnsPropagationVerifier, never()).awaitAll(anyList(), anyBoolean());
    }

    @Test
    void issue_mixedAuthorizations_challengesOnlyThePendingOnes() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec");
        when(secretStore.create(anyString(), anyString())).thenReturn("https://kv-agent.vault.azure.net/secrets/m");
        Order mockOrder = mock(Order.class);
        Dns01Challenge reused = mock(Dns01Challenge.class);
        Dns01Challenge fresh = mock(Dns01Challenge.class);
        when(fresh.getDigest()).thenReturn("fresh-digest");
        when(fresh.getStatus()).thenReturn(Status.VALID);
        Authorization valid = authorization("example.com", reused, Status.VALID);
        Authorization pending = authorization("api.example.com", fresh, Status.PENDING, Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(valid, pending));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        Login login = loginReturning(mockOrder, buildSelfSignedCert("CN=example.com"));

        issueWith(login, List.of("api.example.com"));

        verify(fresh).trigger();
        verify(reused, never()).trigger();
        verify(reused, never()).getDigest();
        verify(dnsProvider).addTxtRecord(eq("_acme-challenge.api.example.com"), eq("fresh-digest"));
        verify(dnsProvider, never()).addTxtRecord(eq("_acme-challenge.example.com"), anyString());
        verify(mockOrder).execute(any(byte[].class));
    }

    @Test
    void issue_allAuthorizationsValid_skipsDnsAndChallengesButFinalizes() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(secretStore.create(anyString(), anyString())).thenReturn("https://kv-agent.vault.azure.net/secrets/a");
        Order mockOrder = mock(Order.class);
        Dns01Challenge c1 = mock(Dns01Challenge.class);
        Dns01Challenge c2 = mock(Dns01Challenge.class);
        List<Authorization> auths = List.of(
                authorization("example.com", c1, Status.VALID),
                authorization("api.example.com", c2, Status.VALID));
        when(mockOrder.getAuthorizations()).thenReturn(auths);
        // The order is still reported PENDING (stale), but every authorization is reused.
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        Login login = loginReturning(mockOrder, buildSelfSignedCert("CN=example.com"));

        IssuanceResult result = issueWith(login, List.of("api.example.com"));

        assertThat(result.certSecretHandle()).isEqualTo("https://kv-agent.vault.azure.net/secrets/a");
        verify(c1, never()).trigger();
        verify(c2, never()).trigger();
        verify(dnsProvider, never()).addTxtRecord(anyString(), anyString());
        verify(dnsPropagationVerifier, never()).awaitAll(anyList(), anyBoolean());
        verify(mockOrder).execute(any(byte[].class));
    }

    @Test
    void issue_deadAuthorization_failsClearlyWithoutChallenging() throws Exception {
        for (Status dead : List.of(Status.INVALID, Status.DEACTIVATED, Status.EXPIRED, Status.REVOKED)) {
            givenValidAccount();
            givenValidCsr();
            Order mockOrder = mock(Order.class);
            Dns01Challenge challenge = mock(Dns01Challenge.class);
            Authorization auth = authorization("example.com", challenge, dead);
            when(mockOrder.getAuthorizations()).thenReturn(List.of(auth));
            when(mockOrder.getStatus()).thenReturn(Status.PENDING);
            Login login = loginReturning(mockOrder, buildSelfSignedCert("CN=example.com"));

            assertThatThrownBy(() -> issueWith(login, List.of()))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasMessageContaining("example.com")
                    .hasMessageContaining(dead.name());
            verify(challenge, never()).trigger();
            verify(mockOrder, never()).execute(any(byte[].class));
        }
        verify(dnsProvider, never()).addTxtRecord(anyString(), anyString());
    }

    //  Resume with checkpoint bypasses newOrder via bindOrder

    @Test
    void issue_resumeWithCheckpoint_callsBindOrderInsteadOfNewOrder() throws Exception {
        givenValidAccount();
        // No CSR-gen stub — the resume path reads from KV, never calls csrKeyPairService.

        String stagingPath = "https://kv-agent.vault.azure.net/secrets/xref-resume-key-staging";
        // Packed format the service uses: MARKER\nkey\nEND_MARKER\ncsr
        String packed = """
                -----BEGIN PRIVATE KEY MARKER-----
                -----BEGIN PRIVATE KEY-----
                MIIE==
                -----END PRIVATE KEY-----
                -----END PRIVATE KEY MARKER-----
                -----BEGIN CERTIFICATE REQUEST-----
                MIICVD==
                -----END CERTIFICATE REQUEST-----""";
        when(secretStore.read(stagingPath)).thenReturn(packed);
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-resume");

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Certificate mockCert = mock(Certificate.class);

        X509Certificate leafCert = buildSelfSignedCert("CN=example.com");

        // Entry-probe path: bound order returns VALID → straight to chain download.
        when(mockOrder.getStatus()).thenReturn(org.shredzone.acme4j.Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leafCert));

        URL orderUrl = new URL("https://acme-staging.api.letsencrypt.org/acme/order/12345");
        when(mockLogin.bindOrder(eq(orderUrl))).thenReturn(mockOrder);
        // Crucially: DO NOT stub mockLogin.getAccount() — newOrder path must not be taken.

        com.certping.agent.exception.IssuanceCheckpoint resume =
                new com.certping.agent.exception.IssuanceCheckpoint(
                        "LETS_ENCRYPT",
                        com.certping.agent.exception.IssuanceCheckpoint.Step.ORDER_CREATED,
                        orderUrl.toString(),
                        "https://acme-staging.api.letsencrypt.org/acme/acct/123456",
                        stagingPath);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            IssuanceResult result = service.issue(
                    "organization-1", "xref-resume", "example.com",
                    false, List.of(), dnsProvider, Map.of(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1",
                    null, resume);

            assertThat(result.certSecretHandle())
                    .isEqualTo("https://kv-agent.vault.azure.net/secrets/cert-xref-resume");

            // The whole point: bindOrder was called, key was read from KV (no CSR-gen),
            // newOrder path never reached, staging slot was purged on success.
            verify(mockLogin).bindOrder(orderUrl);
            verify(secretStore).read(stagingPath);
            verify(secretStore).delete(stagingPath);
            verifyNoInteractions(csrKeyPairService);
        }
    }

    //  domain list construction

    @Test
    void issue_withSanDomains_includesAllInOrder() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("record-id");
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-1");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth1 = mock(Authorization.class);
        Authorization mockAuth2 = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);

        KeyPair certKp = KeyPairUtils.createKeyPair(2048);
        var certBuilder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                new javax.security.auth.x500.X500Principal("CN=example.com"),
                java.math.BigInteger.ONE,
                new java.util.Date(),
                new java.util.Date(System.currentTimeMillis() + 90L * 24 * 3600 * 1000),
                new javax.security.auth.x500.X500Principal("CN=example.com"),
                certKp.getPublic());
        var signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256WithRSA").build(certKp.getPrivate());
        java.security.cert.X509Certificate leafCert =
                new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

        when(mockAuth1.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth1.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth2.getIdentifier()).thenReturn(Identifier.dns("api.example.com"));
        when(mockAuth2.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth1.getStatus()).thenReturn(Status.VALID);
        when(mockAuth2.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("digest");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth1, mockAuth2));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leafCert));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        DnsProvider sanDnsProvider = mock(DnsProvider.class);
        when(sanDnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("san-record");

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            // sanDnsProviders is now keyed by domain pattern (not credential path) so that
            // selectProvider() can match auth domains via exact / wildcard lookup.
            IssuanceResult result = service.issue(
                    "organization-1", "xref-1", "example.com",
                    false,
                    List.of("api.example.com"), dnsProvider,
                    Map.of("api.example.com", sanDnsProvider),
                    null, null);

            assertThat(result).isNotNull();
        }
    }

        @Test
        void issue_replacesDuplicateFallback_createsOrderWithoutReplaces() throws Exception {
                assertReplacesRejectionFallsBack("certificate already has a replacement order");
        }

        @Test
        void issue_replacesUnknownToCa_createsOrderWithoutReplaces() throws Exception {
                // Pebble's answer when it cannot match the ARI certificate id; any CA error on an
                // order that carried the replaces hint must not block the renewal.
                assertReplacesRejectionFallsBack("could not find an order for the given certificate");
        }

        @Test
        void hasNetworkCause_findsTimeoutsAndIoErrorsInTheCauseChain() {
                assertThat(com.certping.agent.ssl.acme.LetsEncryptAcmeService.hasNetworkCause(
                                new RuntimeException("poll failed",
                                                new java.net.http.HttpTimeoutException("request timed out"))))
                                .isTrue();
                assertThat(com.certping.agent.ssl.acme.LetsEncryptAcmeService.hasNetworkCause(
                                new java.io.UncheckedIOException(new java.io.IOException("reset")))).isTrue();
                assertThat(com.certping.agent.ssl.acme.LetsEncryptAcmeService.hasNetworkCause(
                                new IllegalStateException("bad CSR"))).isFalse();
        }

        private void assertReplacesRejectionFallsBack(String caMessage) throws Exception {
                givenValidAccount();
                givenValidCsr();
                when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("record-id");
                when(secretStore.create(anyString(), anyString()))
                                .thenReturn("https://kv-agent.vault.azure.net/secrets/xref-1");

                Login mockLogin = mock(Login.class);
                Account mockAccount = mock(Account.class);
                Order mockOrder = mock(Order.class);
                Authorization mockAuth = mock(Authorization.class);
                Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
                Certificate mockCert = mock(Certificate.class);

                X509Certificate leafCert = buildSelfSignedCert("CN=example.com");
                // inferCurrentCertSecretHandle builds {kvUri}/secrets/{certificateXref} — no "cert-" prefix
                // (the prefix bug was fixed; xref already carries it in production).
                when(secretStore.read("https://kv-agent.vault.azure.net/secrets/xref-1"))
                                .thenReturn(toPem(leafCert));

                when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
                when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
                when(mockAuth.getStatus()).thenReturn(Status.VALID);
                when(mockChallenge.getDigest()).thenReturn("digest");
                when(mockChallenge.getStatus()).thenReturn(Status.VALID);
                when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
                when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
                when(mockOrder.getCertificate()).thenReturn(mockCert);
                when(mockCert.getCertificateChain()).thenReturn(List.of(leafCert));

                OrderBuilder firstBuilder = mock(OrderBuilder.class);
                OrderBuilder fallbackBuilder = mock(OrderBuilder.class);
                when(mockAccount.newOrder()).thenReturn(firstBuilder, fallbackBuilder);
                when(firstBuilder.domains(anyList())).thenReturn(firstBuilder);
                when(fallbackBuilder.domains(anyList())).thenReturn(fallbackBuilder);

                AcmeServerException duplicateReplacement = mock(AcmeServerException.class);
                when(duplicateReplacement.getMessage()).thenReturn(caMessage);
                when(firstBuilder.create()).thenThrow(duplicateReplacement);
                when(fallbackBuilder.create()).thenReturn(mockOrder);
                when(mockLogin.getAccount()).thenReturn(mockAccount);

                try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

                        IssuanceResult result = service.issue(
                                        "organization-1", "xref-1", "example.com", false, List.of(), dnsProvider, Map.of(), null, null);

                        assertThat(result).isNotNull();
                        verify(firstBuilder).replaces(any(X509Certificate.class));
                        verify(fallbackBuilder, never()).replaces(any(X509Certificate.class));
                }
        }

        private X509Certificate buildSelfSignedCert(String dn) throws Exception {
                KeyPair certKp = KeyPairUtils.createKeyPair(2048);
                org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder builder =
                                new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                                                new javax.security.auth.x500.X500Principal(dn),
                                                java.math.BigInteger.valueOf(System.currentTimeMillis()),
                                                new java.util.Date(),
                                                new java.util.Date(System.currentTimeMillis() + 90L * 24 * 3600 * 1000),
                                                new javax.security.auth.x500.X500Principal(dn),
                                                certKp.getPublic());
                var signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256WithRSA").build(certKp.getPrivate());
                return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(builder.build(signer));
        }

        private String toPem(X509Certificate cert) throws Exception {
                return "-----BEGIN CERTIFICATE-----\n"
                                + java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded())
                                + "\n-----END CERTIFICATE-----\n";
        }

    //  exception handling 

    // ── Additional coverage ──────────────────────────────────────────────────

    @Test
    void issue_acmeNonRateLimitServerException_throwsPermanent() throws Exception {
        givenValidAccount();
        givenValidCsr();

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        AcmeServerException serverErr = mock(AcmeServerException.class);
        when(serverErr.getMessage()).thenReturn("internal server error");
        when(mockOrderBuilder.create()).thenThrow(serverErr);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(), dnsProvider, Map.of(), null, null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_ISSUANCE_FAILED"));
        }
    }

    @Test
    void issue_orderInvalidAtEntry_throwsPermanent() throws Exception {
        givenValidAccount();
        givenValidCsr();

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        when(mockOrder.getStatus()).thenReturn(Status.INVALID);

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(), dnsProvider, Map.of(), null, null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_ORDER_INVALID"));
        }
    }

    @Test
    void issue_challengeReturnsInvalid_throwsPermanent() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.INVALID);
        Problem problem = mock(Problem.class);
        when(problem.getType()).thenReturn(java.net.URI.create("urn:ietf:params:acme:error:dns"));
        when(problem.getDetail()).thenReturn(Optional.of("query timed out looking up TXT for _acme-challenge.example.com"));
        when(mockChallenge.getError()).thenReturn(Optional.of(problem));
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING);

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(), dnsProvider, Map.of(), null, null))
                    .isInstanceOf(PermanentAgentException.class)
                    .hasMessageContaining("(urn:ietf:params:acme:error:dns: query timed out looking up TXT"
                            + " for _acme-challenge.example.com)")
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_CHALLENGE_INVALID"));
        }
    }

    @Test
    void issue_authorizationMissingDnsChallenge_throwsPermanent() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.empty());
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING);

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(), dnsProvider, Map.of(), null, null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_NO_DNS_CHALLENGE"));
        }
    }

    @Test
    void issue_validityDaysNot90_logsWarningAndProceeds() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec");
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-1");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);

        X509Certificate leafCert = buildSelfSignedCert("CN=example.com");
        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leafCert));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            // validityDays=30 ≠ 90: triggers the LE-ignores warning branch
            IssuanceResult r = service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(),
                    dnsProvider, Map.of(), null, 30);
            assertThat(r).isNotNull();
        }
    }

    @Test
    void issueWithExternalCsr_skipsKeyStaging_storesChainOnly() throws Exception {
        givenValidAccount();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec");
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-ext");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);

        X509Certificate leafCert = buildSelfSignedCert("CN=example.com");
        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leafCert));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        String externalCsr = "-----BEGIN CERTIFICATE REQUEST-----\nMIICVD==\n-----END CERTIFICATE REQUEST-----";

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            IssuanceResult r = service.issueWithExternalCsr(
                    "organization-1", "xref-ext", "example.com", false, List.of(),
                    dnsProvider, Map.of(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1",
                    externalCsr, true);
            assertThat(r.certSecretHandle()).isEqualTo("https://kv-agent.vault.azure.net/secrets/cert-ext");
            verifyNoInteractions(csrKeyPairService);
            verify(dnsPropagationVerifier).awaitAll(anyList(), eq(true));
        }
    }

    @Test
    void issue_orderFinalizeAlreadyValid_proceedsToChain() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec");
        when(secretStore.create(anyString(), anyString())).thenReturn("kv-path");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);

        X509Certificate leafCert = buildSelfSignedCert("CN=example.com");
        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leafCert));

        // order.execute throws AcmeServerException with status (\"valid\") ... message → fall through
        AcmeServerException alreadyFinalised = mock(AcmeServerException.class);
        when(alreadyFinalised.getMessage()).thenReturn(
                "Order's status (\"valid\") is not acceptable for finalization");
        doThrow(alreadyFinalised).when(mockOrder).execute(any(byte[].class));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            IssuanceResult r = service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(), dnsProvider, Map.of(), null, null);
            assertThat(r).isNotNull();
        }
    }

    @Test
    void issue_orderProcessingAtEntry_waitsForValid() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(secretStore.create(anyString(), anyString())).thenReturn("kv-path");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Certificate mockCert = mock(Certificate.class);
        X509Certificate leafCert = buildSelfSignedCert("CN=example.com");

        when(mockOrder.getStatus()).thenReturn(Status.PROCESSING, Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leafCert));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            IssuanceResult r = service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(), dnsProvider, Map.of(), null, null);
            assertThat(r).isNotNull();
            // No DNS work
            verify(dnsProvider, never()).addTxtRecord(anyString(), anyString());
        }
    }

    @Test
    void issue_orderCreationRateLimited_throwsRetryable() throws Exception {
        givenValidAccount();
        givenValidCsr();

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        AcmeRateLimitedException rl = mock(AcmeRateLimitedException.class);
        when(rl.getMessage()).thenReturn("Too many orders");
        when(rl.getRetryAfter()).thenReturn(java.util.Optional.of(java.time.Instant.now().plusSeconds(60)));
        when(mockOrderBuilder.create()).thenThrow(rl);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(), dnsProvider, Map.of(), null, null))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                            .isEqualTo("ACME_RATE_LIMITED"));
        }
    }

    @Test
    void issue_orderCreatedThenRateLimited_attachesCheckpoint() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockOrder.getLocation()).thenReturn(new URL("https://acme/order/55"));
        // order.execute throws rate limit → bubbles into AcmeRateLimitedException catch
        AcmeRateLimitedException rl = mock(AcmeRateLimitedException.class);
        when(rl.getMessage()).thenReturn("rate limited on execute");
        when(rl.getRetryAfter()).thenReturn(java.util.Optional.empty());
        doThrow(rl).when(mockOrder).execute(any(byte[].class));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(),
                    dnsProvider, Map.of(), null, null))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                            .isEqualTo("ACME_RATE_LIMITED"));
        }
    }

    @Test
    void issue_ariUnsupportedOperationException_continuesWithoutReplaces() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec");
        when(secretStore.create(anyString(), anyString())).thenReturn("kv-path");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);

        X509Certificate leafCert = buildSelfSignedCert("CN=example.com");
        when(secretStore.read("https://kv-agent.vault.azure.net/secrets/xref-1"))
                .thenReturn(toPem(leafCert));

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leafCert));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        doThrow(new UnsupportedOperationException("ARI not supported"))
                .when(mockOrderBuilder).replaces(any(X509Certificate.class));
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            IssuanceResult r = service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(),
                    dnsProvider, Map.of(), null, null);
            assertThat(r).isNotNull();
            verify(mockOrderBuilder).replaces(any(X509Certificate.class));
        }
    }

    @Test
    void issue_previousCertSecretHandle_blankString_skipsAri() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec");
        when(secretStore.create(anyString(), anyString())).thenReturn("kv-path");
        // KV throws "Secret not found" → ARI skipped silently
        when(secretStore.read(anyString()))
                .thenThrow(new RuntimeException("Secret not found"));

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);

        X509Certificate leafCert = buildSelfSignedCert("CN=example.com");

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leafCert));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            // Use the renewal overload with explicit previousCertSecretHandle
            IssuanceResult r = service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(),
                    dnsProvider, Map.of(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1",
                    null, null,
                    "https://kv-agent.vault.azure.net/secrets/prev-xref", false, CheckpointRecorder.NONE);
            assertThat(r).isNotNull();
            verify(mockOrderBuilder, never()).replaces(any(X509Certificate.class));
        }
    }

    @Test
    void issue_recordsTheOrderLetsEncryptCreatedOnceItAnswers() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec");
        when(secretStore.create(anyString(), anyString())).thenReturn("kv-path");
        // KV throws "Secret not found" → ARI skipped silently
        when(secretStore.read(anyString()))
                .thenThrow(new RuntimeException("Secret not found"));

        CheckpointRecorder recorder = mock(CheckpointRecorder.class);
        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);

        X509Certificate leafCert = buildSelfSignedCert("CN=example.com");

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getLocation()).thenReturn(new URL("https://acme.test/order/1"));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leafCert));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            IssuanceResult r = service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(),
                    dnsProvider, Map.of(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1",
                    null, null,
                    "https://kv-agent.vault.azure.net/secrets/prev-xref", false, recorder);
            assertThat(r).isNotNull();
            verify(recorder).recordAnswered(argThat(created ->
                    created.step() == com.certping.agent.exception.IssuanceCheckpoint.Step.ORDER_CREATED
                            && "https://acme.test/order/1".equals(created.orderRef())));
            verify(recorder, never()).recordBeforeSending(any());
        }
    }

    @Test
    void issue_genericRuntimeException_throwsPermanent() throws Exception {
        givenValidAccount();
        givenValidCsr();

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenThrow(new RuntimeException("unexpected"));
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(),
                    dnsProvider, Map.of(), null, null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_ISSUANCE_FAILED"));
        }
    }

    // ── LetsEncryptManualService coverage (shared package; extending this test file) ─

    @Test
    void manual_completeValidation_missingOrderUrl_throwsPermanent() {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        assertThatThrownBy(() -> manual.completeValidation(
                "organization-1", "xref-1", "example.com", false, false, List.of(),
                null, "acct-path", List.of()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("ACME_ORDER_URL_MISSING"));
        assertThatThrownBy(() -> manual.completeValidation(
                "organization-1", "xref-1", "example.com", false, false, List.of(),
                "  ", "acct-path", List.of()))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void manual_completeValidation_missingAccountPath_throwsPermanent() {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        assertThatThrownBy(() -> manual.completeValidation(
                "organization-1", "xref-1", "example.com", false, false, List.of(),
                "https://example.com/order/1", null, List.of()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("ACME_ACCOUNT_PATH_MISSING"));
    }

    @Test
    void manual_requestTxtRecords_accountServiceFails_propagates() {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        when(acmeAccountService.getOrCreate(anyString(), any()))
                .thenThrow(new PermanentAgentException("ACME_ACCOUNT_FAILED", "boom"));

        assertThatThrownBy(() -> manual.requestTxtRecords(
                "organization-1", "xref-1", "example.com", false, false, List.of(), null))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void manual_requestTxtRecords_success_returnsTxtRecords() throws Exception {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getDigest()).thenReturn("digest-x");
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getLocation()).thenReturn(new URL("https://acme/order/9"));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            var result = manual.requestTxtRecords(
                    "organization-1", "xref-1", "example.com", false, false, List.of(), null);
            assertThat(result).isNotNull();
            assertThat(result.txtRecords()).hasSize(1);
            assertThat(result.txtRecords().get(0).getRecordName()).isEqualTo("_acme-challenge.example.com");
        }
    }

    @Test
    void manual_requestTxtRecords_authMissingChallenge_throwsPermanent() throws Exception {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.empty());
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> manual.requestTxtRecords(
                    "organization-1", "xref-1", "example.com", false, false, List.of(), null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_NO_DNS_CHALLENGE"));
        }
    }

    @Test
    void manual_requestTxtRecords_networkError_throwsTransient() throws Exception {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenThrow(new org.shredzone.acme4j.exception.AcmeNetworkException(
                new java.io.IOException("net down")));
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> manual.requestTxtRecords(
                    "organization-1", "xref-1", "example.com", false, false, List.of(), null))
                    .isInstanceOf(TransientAgentException.class)
                    .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                            .isEqualTo("ACME_NETWORK_ERROR"));
        }
    }

    @Test
    void manual_requestTxtRecords_rateLimited_throwsRetryable() throws Exception {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        AcmeRateLimitedException rl = mock(AcmeRateLimitedException.class);
        when(rl.getMessage()).thenReturn("too many");
        when(rl.getRetryAfter()).thenReturn(java.util.Optional.empty());
        when(mockOrderBuilder.create()).thenThrow(rl);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> manual.requestTxtRecords(
                    "organization-1", "xref-1", "example.com", false, false, List.of(), null))
                    .isInstanceOf(RetryableAgentException.class);
        }
    }

    @Test
    void manual_requestTxtRecords_noAuthorizations_throwsPermanent() throws Exception {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);

        when(mockOrder.getAuthorizations()).thenReturn(List.of()); // empty

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> manual.requestTxtRecords(
                    "organization-1", "xref-1", "example.com", false, false, List.of(), null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_NO_AUTHORIZATIONS"));
        }
    }

    @Test
    void manual_completeValidation_happyPath_completesAndStores() throws Exception {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();
        givenValidCsr();
        when(secretStore.create(anyString(), anyString())).thenReturn("kv-cert-path");

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);

        X509Certificate leaf = buildSelfSignedCert("CN=example.com");
        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("digest");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leaf));

        URL orderUrl = new URL("https://acme/order/1");
        when(mockLogin.bindOrder(eq(orderUrl))).thenReturn(mockOrder);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            IssuanceResult r = manual.completeValidation(
                    "organization-1", "xref-1", "example.com", false, false, List.of(),
                    orderUrl.toString(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1",
                    List.of());
            assertThat(r).isNotNull();
            assertThat(r.certSecretHandle()).isEqualTo("kv-cert-path");
        }
    }

    @Test
    void manual_completeValidation_challengeInvalid_throwsPermanent() throws Exception {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.INVALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));

        URL orderUrl = new URL("https://acme/order/2");
        when(mockLogin.bindOrder(eq(orderUrl))).thenReturn(mockOrder);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> manual.completeValidation(
                    "organization-1", "xref-1", "example.com", false, false, List.of(),
                    orderUrl.toString(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1",
                    List.of()))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_CHALLENGE_FAILED"));
        }
    }

    @Test
    void manual_completeValidation_noChallenge_throwsPermanent() throws Exception {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);

        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.empty());
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));

        URL orderUrl = new URL("https://acme/order/3");
        when(mockLogin.bindOrder(eq(orderUrl))).thenReturn(mockOrder);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> manual.completeValidation(
                    "organization-1", "xref-1", "example.com", false, false, List.of(),
                    orderUrl.toString(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1",
                    List.of()))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_NO_DNS_CHALLENGE"));
        }
    }

    @Test
    void manual_completeValidation_withExplicitTxtHints_usesHints() throws Exception {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();
        givenValidCsr();
        when(secretStore.create(anyString(), anyString())).thenReturn("kv-cert-path");

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);

        X509Certificate leaf = buildSelfSignedCert("CN=example.com");
        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("digest");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leaf));

        URL orderUrl = new URL("https://acme/order/4");
        when(mockLogin.bindOrder(eq(orderUrl))).thenReturn(mockOrder);

        var hint = new com.certping.agent.model.message.CertManualValidateMessage.TxtRecordEntry();
        hint.setRecordName("_acme-challenge.example.com");
        hint.setRecordValue("digest");
        var badHint = new com.certping.agent.model.message.CertManualValidateMessage.TxtRecordEntry();
        badHint.setRecordName(null);
        badHint.setRecordValue("x");

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            IssuanceResult r = manual.completeValidation(
                    "organization-1", "xref-1", "example.com", false, false, List.of(),
                    orderUrl.toString(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1",
                    java.util.Arrays.asList(hint, badHint, null));
            assertThat(r).isNotNull();
        }
    }

    @Test
    void manual_completeValidation_orderTimeout_throwsPermanent() throws Exception {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();
        givenValidCsr();

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        X509Certificate leaf = buildSelfSignedCert("CN=example.com");
        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("digest");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        // Order never reaches VALID — finishes as PROCESSING after waitForCompletion
        when(mockOrder.getStatus()).thenReturn(Status.PROCESSING);
        when(mockOrder.waitForCompletion(any(Duration.class))).thenReturn(Status.PROCESSING);

        URL orderUrl = new URL("https://acme/order/timeout");
        when(mockLogin.bindOrder(eq(orderUrl))).thenReturn(mockOrder);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> manual.completeValidation(
                    "organization-1", "xref-1", "example.com", false, false, List.of(),
                    orderUrl.toString(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1",
                    List.of()))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_ORDER_TIMEOUT"));
        }
    }

    @Test
    void manual_completeValidation_genericException_throwsPermanent() throws Exception {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();

        Login mockLogin = mock(Login.class);
        URL orderUrl = new URL("https://acme/order/generic");
        when(mockLogin.bindOrder(eq(orderUrl))).thenThrow(new RuntimeException("boom"));

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> manual.completeValidation(
                    "organization-1", "xref-1", "example.com", false, false, List.of(),
                    orderUrl.toString(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1",
                    List.of()))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_MANUAL_VALIDATE_FAILED"));
        }
    }

    @Test
    void manual_requestTxtRecords_genericException_throwsPermanent() {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        when(acmeAccountService.getOrCreate(anyString(), any()))
                .thenThrow(new RuntimeException("unexpected"));

        assertThatThrownBy(() -> manual.requestTxtRecords(
                "organization-1", "xref-1", "example.com", false, false, List.of(), null))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("ACME_MANUAL_TXT_FAILED"));
    }

    @Test
    void manual_completeValidation_invalidUrl_throwsPermanent() {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        when(acmeAccountService.getOrCreate(anyString(), any())).thenAnswer(inv -> {
            KeyPair kp = org.shredzone.acme4j.util.KeyPairUtils.createKeyPair(2048);
            return new com.certping.agent.handler.acme.AcmeAccountResult(
                    kp, new URL("https://acme/acct/1"), "acct-path");
        });
        // Invalid URL string should throw MalformedURLException → caught → permanent
        assertThatThrownBy(() -> manual.completeValidation(
                "organization-1", "xref-1", "example.com", false, false, List.of(),
                "not-a-url://??", "acct-path", List.of()))
                .isInstanceOf(PermanentAgentException.class);
    }

    // ── LetsEncryptRevocationService coverage ─

    @Test
    void revoke_letsEncrypt_invalidBundle_throwsPermanent() {
        var revSvc = new com.certping.agent.ssl.acme.LetsEncryptRevocationService(properties);
        assertThatThrownBy(() -> revSvc.revoke("not-a-valid-pem-bundle", "KEY_COMPROMISE"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void revoke_letsEncrypt_emptyBundle_throwsPermanent() {
        var revSvc = new com.certping.agent.ssl.acme.LetsEncryptRevocationService(properties);
        assertThatThrownBy(() -> revSvc.revoke("", "KEY_COMPROMISE"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void issue_acmeAccountServiceFails_propagatesException() {
        when(acmeAccountService.getOrCreate(anyString(), any()))
                .thenThrow(new PermanentAgentException("ACME_ACCOUNT_FAILED", "account error"));

        assertThatThrownBy(() -> service.issue(
                "organization-1", "xref-1", "example.com", false, List.of(), dnsProvider, Map.of(), null, null))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("ACME_ACCOUNT_FAILED"));
    }

    @Test
    void issue_csrGenerationFails_propagatesException() throws Exception {
        givenValidAccount();
        when(csrKeyPairService.generateCsrAndKeyPair(anyString(), any()))
                .thenThrow(new PermanentAgentException("CSR_GENERATION_FAILED", "key gen error"));

        assertThatThrownBy(() -> service.issue(
                "organization-1", "xref-1", "example.com", false, List.of(), dnsProvider, Map.of(), null, null))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void issue_acmeNetworkException_throwsTransient() throws Exception {
        givenValidAccount();
        givenValidCsr();

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenThrow(new org.shredzone.acme4j.exception.AcmeNetworkException(
                new java.io.IOException("Network unreachable")));
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(), dnsProvider, Map.of(), null, null))
                    .isInstanceOf(TransientAgentException.class)
                    .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                            .isEqualTo("ACME_NETWORK_ERROR"));
        }
    }

    @Test
    void issue_challengeNeverValid_throwsTransient() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("record-id");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getDigest()).thenReturn("digest");
        // Challenge never becomes VALID
        when(mockChallenge.getStatus()).thenReturn(Status.PROCESSING);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(), dnsProvider, Map.of(), null, null))
                    .isInstanceOf(TransientAgentException.class)
                    .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                            .isEqualTo("ACME_CHALLENGE_FAILED"));
            verify(dnsProvider).deleteTxtRecord(anyString(), anyString());
        }
    }

    @Test
    void issue_orderNeverValid_throwsPermanent() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("record-id");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("digest");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        // Order: entry probe sees PENDING (fresh order); after finalize stays PROCESSING forever
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.PROCESSING);

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(), dnsProvider, Map.of(), null, null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_ORDER_TIMEOUT"));
        }
    }

    @Test
    void issue_orderRetryAfter_thenSucceeds() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("record-id");
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-1");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);

        X509Certificate leafCert = buildSelfSignedCert("CN=example.com");
        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("digest");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        // Entry probe sees PENDING (fresh order); waitForOrderValid sees PROCESSING twice then VALID.
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.PROCESSING, Status.PROCESSING, Status.VALID, Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leafCert));

        when(mockOrder.waitForCompletion(any(Duration.class))).thenReturn(Status.VALID);

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            IssuanceResult result = service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(), dnsProvider, Map.of(), null, null);

            assertThat(result.certSecretHandle()).isEqualTo("https://kv-agent.vault.azure.net/secrets/cert-xref-1");
            verify(mockOrder).waitForCompletion(any(Duration.class));
        }
    }

    @Test
    void issue_wrappedRateLimitDuringCertificateDownload_throwsRetryableRateLimited() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("record-id");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("digest");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);

        AcmeRateLimitedException nestedRateLimit = mock(AcmeRateLimitedException.class);
        when(nestedRateLimit.getMessage()).thenReturn("Service busy; retry later.");
        when(mockCert.getCertificateChain()).thenThrow(new RuntimeException("Certificate lazy-load failed", nestedRateLimit));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(), dnsProvider, Map.of(), null, null))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(e -> {
                        RetryableAgentException ex = (RetryableAgentException) e;
                        assertThat(ex.getErrorCode()).isEqualTo("ACME_RATE_LIMITED");
                        assertThat(ex.getMessage()).contains("certificate chain download");
                    });
        }
    }

    @Test
    void issue_wildcardAndCoveredSan_usesIdenticalIdentifiersForOrderAndCsr() throws Exception {
        givenValidAccount();
        when(csrKeyPairService.generateCsrAndKeyPair(anyString(), any()))
                .thenReturn(new CsrKeyPairService.CsrKeyPairResult(
                        new byte[]{1, 2, 3},
                        "-----BEGIN CERTIFICATE REQUEST-----\nMIICVD==\n-----END CERTIFICATE REQUEST-----",
                        "-----BEGIN PRIVATE KEY-----\nMIIEvg==\n-----END PRIVATE KEY-----"
                ));
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("record-id");
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-1");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);

        X509Certificate leafCert = buildSelfSignedCert("CN=example.com");
        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("*.example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("digest");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leafCert));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            service.issue(
                    "organization-1", "xref-1", "example.com", true,
                    List.of("*.example.com", "api.example.com"), dnsProvider, Map.of(), null, null);
        }

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<String>> orderDomainsCaptor = ArgumentCaptor.forClass(List.class);
        verify(mockOrderBuilder).domains(orderDomainsCaptor.capture());

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<String>> csrSansCaptor = ArgumentCaptor.forClass(List.class);
        verify(csrKeyPairService).generateCsrAndKeyPair(eq("*.example.com"), csrSansCaptor.capture());

        assertThat(orderDomainsCaptor.getValue()).containsExactly("*.example.com", "example.com");
        assertThat(csrSansCaptor.getValue()).containsExactly("example.com");
    }

    @Test
    void issue_nonWildcardPrimaryWithMixedSan_usesExpectedIdentifiersForOrderAndCsr() throws Exception {
        givenValidAccount();
        when(csrKeyPairService.generateCsrAndKeyPair(anyString(), any()))
                .thenReturn(new CsrKeyPairService.CsrKeyPairResult(
                        new byte[]{1, 2, 3},
                        "-----BEGIN CERTIFICATE REQUEST-----\nMIICVD==\n-----END CERTIFICATE REQUEST-----",
                        "-----BEGIN PRIVATE KEY-----\nMIIEvg==\n-----END PRIVATE KEY-----"
                ));
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("record-id");
        when(secretStore.create(anyString(), anyString()))
                .thenReturn("https://kv-agent.vault.azure.net/secrets/cert-xref-1");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);

        X509Certificate leafCert = buildSelfSignedCert("CN=xyz.com");
        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("xyz.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("digest");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leafCert));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            service.issue(
                    "organization-1", "xref-1", "xyz.com", false,
                    List.of("*.xyz.com", "xyz.xom", "api.xyz.com"), dnsProvider, Map.of(), null, null);
        }

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<String>> orderDomainsCaptor = ArgumentCaptor.forClass(List.class);
        verify(mockOrderBuilder).domains(orderDomainsCaptor.capture());

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<String>> csrSansCaptor = ArgumentCaptor.forClass(List.class);
        verify(csrKeyPairService).generateCsrAndKeyPair(eq("xyz.com"), csrSansCaptor.capture());

        assertThat(orderDomainsCaptor.getValue()).containsExactly("xyz.com", "*.xyz.com", "xyz.xom");
        assertThat(csrSansCaptor.getValue()).containsExactly("*.xyz.com", "xyz.xom");
    }

    // ── Additional LetsEncryptManualService coverage ───────────────────────────

    @Test
    void manual_requestTxtRecords_acmeException_throwsPermanent() throws Exception {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        AcmeServerException serverErr = mock(AcmeServerException.class);
        when(serverErr.getMessage()).thenReturn("internal server error");
        when(mockOrderBuilder.create()).thenThrow(serverErr);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> manual.requestTxtRecords(
                    "organization-1", "xref-1", "example.com", false, false, List.of(), null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_MANUAL_TXT_FAILED"));
        }
    }

    @Test
    void manual_requestTxtRecords_withSanEntries_flattensPatterns() throws Exception {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getDigest()).thenReturn("dig");
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getLocation()).thenReturn(new URL("https://acme/order/77"));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        com.certping.agent.model.message.SanDomainEntry entry1 =
                new com.certping.agent.model.message.SanDomainEntry();
        entry1.setPatterns(List.of("api.example.com", "*.api.example.com"));
        com.certping.agent.model.message.SanDomainEntry entry2 =
                new com.certping.agent.model.message.SanDomainEntry();
        entry2.setPatterns(null); // filtered out
        com.certping.agent.model.message.SanDomainEntry entry3 =
                new com.certping.agent.model.message.SanDomainEntry();
        entry3.setPatterns(List.of("api.example.com")); // duplicate → distinct()

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            var result = manual.requestTxtRecords(
                    "organization-1", "xref-1", "example.com", false, true,
                    List.of(entry1, entry2, entry3), null);
            assertThat(result).isNotNull();
        }
    }

    @Test
    void manual_completeValidation_networkError_throwsTransient() throws Exception {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.PENDING);
        // challenge.trigger() throws AcmeNetworkException
        doThrow(new org.shredzone.acme4j.exception.AcmeNetworkException(new java.io.IOException("down")))
                .when(mockChallenge).trigger();
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));

        URL orderUrl = new URL("https://acme/order/net");
        when(mockLogin.bindOrder(eq(orderUrl))).thenReturn(mockOrder);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> manual.completeValidation(
                    "organization-1", "xref-1", "example.com", false, false, List.of(),
                    orderUrl.toString(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1",
                    List.of()))
                    .isInstanceOf(TransientAgentException.class)
                    .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                            .isEqualTo("ACME_NETWORK_ERROR"));
        }
    }

    @Test
    void manual_completeValidation_rateLimitedOnTrigger_throwsRetryable() throws Exception {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.PENDING);
        AcmeRateLimitedException rl = mock(AcmeRateLimitedException.class);
        when(rl.getMessage()).thenReturn("rate limited");
        when(rl.getRetryAfter()).thenReturn(java.util.Optional.empty());
        doThrow(rl).when(mockChallenge).trigger();
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));

        URL orderUrl = new URL("https://acme/order/rl");
        when(mockLogin.bindOrder(eq(orderUrl))).thenReturn(mockOrder);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> manual.completeValidation(
                    "organization-1", "xref-1", "example.com", false, false, List.of(),
                    orderUrl.toString(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1",
                    List.of()))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                            .isEqualTo("ACME_RATE_LIMITED"));
        }
    }

    @Test
    void manual_completeValidation_acmeServerException_throwsPermanent() throws Exception {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.PENDING);
        AcmeServerException serverErr = mock(AcmeServerException.class);
        when(serverErr.getMessage()).thenReturn("server error");
        doThrow(serverErr).when(mockChallenge).trigger();
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));

        URL orderUrl = new URL("https://acme/order/acme");
        when(mockLogin.bindOrder(eq(orderUrl))).thenReturn(mockOrder);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> manual.completeValidation(
                    "organization-1", "xref-1", "example.com", false, false, List.of(),
                    orderUrl.toString(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1",
                    List.of()))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_MANUAL_VALIDATE_FAILED"));
        }
    }

    @Test
    void manual_completeValidation_orderExecuteRateLimited_throwsRetryable() throws Exception {
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();
        givenValidCsr();

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING);

        AcmeRateLimitedException rl = mock(AcmeRateLimitedException.class);
        when(rl.getMessage()).thenReturn("execute rate limited");
        when(rl.getRetryAfter()).thenReturn(java.util.Optional.empty());
        doThrow(rl).when(mockOrder).execute(any(byte[].class));

        URL orderUrl = new URL("https://acme/order/exec-rl");
        when(mockLogin.bindOrder(eq(orderUrl))).thenReturn(mockOrder);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            assertThatThrownBy(() -> manual.completeValidation(
                    "organization-1", "xref-1", "example.com", false, false, List.of(),
                    orderUrl.toString(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1",
                    List.of()))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                            .isEqualTo("ACME_RATE_LIMITED"));
        }
    }

    @Test
    void manual_completeValidation_authPendingAfterChallengeValid_waitsForAuthorization() throws Exception {
        // Drives AcmePollingSupport.waitForAuthorizationCompletion's inner branch (auth not VALID/INVALID).
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();
        givenValidCsr();
        when(secretStore.create(anyString(), anyString())).thenReturn("kv-path");

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);
        X509Certificate leaf = buildSelfSignedCert("CN=example.com");

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        // Auth: PENDING first → triggers waitForCompletion path; then VALID
        when(mockAuth.getStatus()).thenReturn(Status.PENDING);
        when(mockAuth.waitForCompletion(any(Duration.class))).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leaf));

        URL orderUrl = new URL("https://acme/order/auth-wait");
        when(mockLogin.bindOrder(eq(orderUrl))).thenReturn(mockOrder);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            IssuanceResult r = manual.completeValidation(
                    "organization-1", "xref-1", "example.com", false, false, List.of(),
                    orderUrl.toString(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1",
                    List.of());
            assertThat(r).isNotNull();
            verify(mockAuth).waitForCompletion(any(Duration.class));
        }
    }

    @Test
    void manual_completeValidation_withSanCsr_multiDomain() throws Exception {
        // Exercise the SAN branch in CSR build (line 273-274 of LetsEncryptManualService).
        var manual = new com.certping.agent.ssl.acme.LetsEncryptManualService(
                acmeAccountService, csrKeyPairService, secretStore, properties,
                dnsPropagationVerifier, new com.certping.agent.ssl.dns.DnsValidationDomainService());
        givenValidAccount();
        givenValidCsr();
        when(secretStore.create(anyString(), anyString())).thenReturn("kv-path");

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);
        X509Certificate leaf = buildSelfSignedCert("CN=example.com");

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leaf));

        URL orderUrl = new URL("https://acme/order/san");
        when(mockLogin.bindOrder(eq(orderUrl))).thenReturn(mockOrder);

        com.certping.agent.model.message.SanDomainEntry entry =
                new com.certping.agent.model.message.SanDomainEntry();
        entry.setPatterns(List.of("api.example.com"));

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            IssuanceResult r = manual.completeValidation(
                    "organization-1", "xref-1", "example.com", false, true, List.of(entry),
                    orderUrl.toString(),
                    "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1",
                    List.of());
            assertThat(r).isNotNull();
            // CSR built with primary "example.com" and sans ["api.example.com"]
            verify(csrKeyPairService).generateCsrAndKeyPair(eq("example.com"),
                    argThat(sans -> sans != null && sans.size() == 1 && sans.contains("api.example.com")));
        }
    }

    // ── refreshOrderStatus catch path: order.fetch() throws ───────────────────

    @Test
    void issue_refreshOrderStatusFetchThrows_continuesWithCachedStatus() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec");
        when(secretStore.create(anyString(), anyString())).thenReturn("kv-path");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);
        X509Certificate leaf = buildSelfSignedCert("CN=example.com");

        // order.fetch() throws — catch logs and falls back to cached status
        doThrow(new RuntimeException("fetch failed")).when(mockOrder).fetch();
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockOrder.getLocation()).thenReturn(new URL("https://acme/order/refresh"));
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leaf));

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            IssuanceResult r = service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(),
                    dnsProvider, Map.of(), null, null);
            assertThat(r).isNotNull();
            verify(mockOrder).fetch();
        }
    }

    @Test
    void issue_orderLocationNull_skipsStateOrderRefUpdate() throws Exception {
        // Tests the else branch (line 248-250) when order.getLocation() returns null.
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec");
        when(secretStore.create(anyString(), anyString())).thenReturn("kv-path");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);
        X509Certificate leaf = buildSelfSignedCert("CN=example.com");

        // getLocation() returns null → takes the else branch on line 248
        when(mockOrder.getLocation()).thenReturn(null);
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leaf));

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            IssuanceResult r = service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(),
                    dnsProvider, Map.of(), null, null);
            assertThat(r).isNotNull();
        }
    }

    @Test
    void issue_dnsCleanupThrowsRuntime_swallowedAsBestEffort() throws Exception {
        givenValidAccount();
        givenValidCsr();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec");
        // DNS deleteTxtRecord throws RuntimeException → cleanup catch (line 624-625)
        doThrow(new RuntimeException("DNS API error")).when(dnsProvider).deleteTxtRecord(anyString(), anyString());
        when(secretStore.create(anyString(), anyString())).thenReturn("kv-path");

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);
        X509Certificate leaf = buildSelfSignedCert("CN=example.com");

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leaf));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            // Even though DNS cleanup fails, the issuance succeeds (best-effort)
            IssuanceResult r = service.issue(
                    "organization-1", "xref-1", "example.com", false, List.of(),
                    dnsProvider, Map.of(), null, null);
            assertThat(r).isNotNull();
        }
    }

    @Test
    void issue_externalCsr_emptyCertBundleAri_returnsNullSkipsAri() throws Exception {
        // Exercise previousCertSecretHandle path where bundle is blank → returns null early
        givenValidAccount();
        when(dnsProvider.addTxtRecord(anyString(), anyString())).thenReturn("rec");
        when(secretStore.create(anyString(), anyString())).thenReturn("kv-path");
        when(secretStore.read(anyString())).thenReturn("");  // blank → returns null

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);
        X509Certificate leaf = buildSelfSignedCert("CN=example.com");

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.PENDING, Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leaf));

        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        String externalCsr = "-----BEGIN CERTIFICATE REQUEST-----\nMIICVD==\n-----END CERTIFICATE REQUEST-----";

        try (MockedConstruction<Session> ignored = Mockito.mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {
            IssuanceResult r = service.issueWithExternalCsr(
                    "organization-1", "xref-1", "example.com", false, List.of(),
                    dnsProvider, Map.of(), null, externalCsr, false);
            assertThat(r).isNotNull();
            // ARI should be skipped — replaces never called
            verify(mockOrderBuilder, never()).replaces(any(X509Certificate.class));
        }
    }

    // ── LetsEncryptRevocationService: outer generic catch ───────────────────────

    @Test
    void revoke_letsEncrypt_certParseFailure_throwsPermanent() {
        // Bundle parses (has cert+key PEM blocks) but cert body is garbage → CertificateException
        // → falls through to the outer Exception catch (line 74-81) → PermanentAgentException.
        var revSvc = new com.certping.agent.ssl.acme.LetsEncryptRevocationService(properties);
        String bundle = """
                -----BEGIN CERTIFICATE-----
                bm90LWEtcmVhbC1jZXJ0
                -----END CERTIFICATE-----
                -----BEGIN PRIVATE KEY-----
                bm90LWEtcmVhbC1rZXk=
                -----END PRIVATE KEY-----
                """;
        assertThatThrownBy(() -> revSvc.revoke(bundle, "KEY_COMPROMISE"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("REVOCATION_FAILED"));
    }
}
