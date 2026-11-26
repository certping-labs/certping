// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.acme;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.handler.acme.AcmeAccountResult;
import com.certping.agent.handler.acme.AcmeAccountService;
import com.certping.agent.model.message.CertManualValidateMessage;
import com.certping.agent.model.message.SanDomainEntry;
import com.certping.agent.ssl.CsrKeyPairService;
import com.certping.agent.ssl.IssuanceResult;
import com.certping.agent.ssl.dns.DnsPropagationVerifier;
import com.certping.agent.ssl.dns.DnsValidationDomainService;
import com.certping.agent.secrets.SecretStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.OrderBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.exception.AcmeRateLimitedException;
import org.shredzone.acme4j.util.KeyPairUtils;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
class LetsEncryptManualServiceTest {

    private static final String ACCT_URL = "https://acme-staging.example/acme/acct/7";
    private static final String ORDER_URL = "https://acme-staging.example/acme/order/42";
    private static final String DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory";

    @Mock private AcmeAccountService acmeAccountService;
    @Mock private CsrKeyPairService csrKeyPairService;
    @Mock private SecretStore secretStore;
    @Mock private DnsPropagationVerifier dnsPropagationVerifier;

    private AgentProperties properties;
    private LetsEncryptManualService service;

    @BeforeEach
    void setUp() {
        properties = new AgentProperties();
        properties.getAcme().setDirectoryUrl(DIRECTORY);
        properties.getAcme().getChallenge().setDnsPropagationWaitMs(1);
        properties.getAcme().getChallenge().setMaxAttempts(3);
        properties.getAcme().getChallenge().setPollIntervalMs(1);
        properties.getAcme().getDnsVerification().setMaxAttempts(2);
        properties.getAcme().getDnsVerification().setPollIntervalMs(1);
        service = new LetsEncryptManualService(
                acmeAccountService,
                csrKeyPairService,
                secretStore,
                properties,
                dnsPropagationVerifier,
                new DnsValidationDomainService());
    }

    @Test
    void requestTxtRecords_success_returnsManualTxtResult() throws Exception {
        AcmeAccountResult account = accountResult();
        when(acmeAccountService.getOrCreate(eq("organization-1"), eq(null))).thenReturn(account);

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getDigest()).thenReturn("digest-xyz");
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getLocation()).thenReturn(new URL(ORDER_URL));

        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            ManualTxtResult result = service.requestTxtRecords(
                    "organization-1", "xref-1", "example.com", false, false, List.of(), null);

            assertThat(result.txtRecords()).hasSize(1);
            assertThat(result.txtRecords().get(0).getRecordName()).isEqualTo("_acme-challenge.example.com");
            assertThat(result.txtRecords().get(0).getRecordValue()).isEqualTo("digest-xyz");
            assertThat(result.orderUrl().toString()).isEqualTo(ORDER_URL);
            assertThat(result.accountUrl()).isEqualTo(account.accountLocation());
            assertThat(result.acmeAccountHandle()).isEqualTo(account.acmeAccountHandle());
        }
    }

    @Test
    void requestTxtRecords_wildcard_stripsStarInRecordName() throws Exception {
        AcmeAccountResult account = accountResult();
        when(acmeAccountService.getOrCreate(anyString(), any())).thenReturn(account);

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("*.example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getLocation()).thenReturn(new URL(ORDER_URL));

        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            ManualTxtResult result = service.requestTxtRecords(
                    "t", "x", "example.com", true, false, List.of(), null);

            assertThat(result.txtRecords().get(0).getRecordName()).isEqualTo("_acme-challenge.example.com");
        }
    }

    @Test
    void requestTxtRecords_noDns01Challenge_throwsPermanent() throws Exception {
        when(acmeAccountService.getOrCreate(anyString(), any())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.empty());
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));

        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.requestTxtRecords(
                    "t", "x", "example.com", false, false, List.of(), null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_NO_DNS_CHALLENGE"));
        }
    }

    @Test
    void requestTxtRecords_emptyAuthorizations_throwsPermanent() throws Exception {
        when(acmeAccountService.getOrCreate(anyString(), any())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        Order mockOrder = mock(Order.class);
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);

        when(mockOrder.getAuthorizations()).thenReturn(List.of());
        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenReturn(mockOrder);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.requestTxtRecords(
                    "t", "x", "example.com", false, false, List.of(), null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_NO_AUTHORIZATIONS"));
        }
    }

    @Test
    void requestTxtRecords_acmeNetworkException_throwsTransient() throws Exception {
        when(acmeAccountService.getOrCreate(anyString(), any())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);

        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenThrow(new AcmeNetworkException(new IOException("unreachable")));
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.requestTxtRecords(
                    "t", "x", "example.com", false, false, List.of(), null))
                    .isInstanceOf(TransientAgentException.class)
                    .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                            .isEqualTo("ACME_NETWORK_ERROR"));
        }
    }

    @Test
    void requestTxtRecords_rateLimited_throwsRetryable() throws Exception {
        // AcmeRateLimitedException bubbles up from OrderBuilder.create() and the service catch
        // block routes it through toRetryable("manual TXT request", ...) -> ACME_RATE_LIMITED
        // with retryAfter derived from getRetryAfter().
        when(acmeAccountService.getOrCreate(anyString(), any())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);

        Instant retryAt = Instant.now().plusSeconds(120);
        AcmeRateLimitedException rateLimited = mock(AcmeRateLimitedException.class);
        when(rateLimited.getRetryAfter()).thenReturn(Optional.of(retryAt));
        when(rateLimited.getMessage()).thenReturn("Too many new orders for account");

        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenThrow(rateLimited);
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.requestTxtRecords(
                    "t", "x", "example.com", false, false, List.of(), null))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(e -> {
                        RetryableAgentException re = (RetryableAgentException) e;
                        assertThat(re.getErrorCode()).isEqualTo("ACME_RATE_LIMITED");
                        // retryAfter is computed as (retryAt - now); allow slop for clock progression
                        assertThat(re.getRetryAfter())
                                .isBetween(Duration.ofSeconds(115), Duration.ofSeconds(125));
                    });
        }
    }

    @Test
    void completeValidation_missingOrderUrl_throws() {
        assertThatThrownBy(() -> service.completeValidation(
                "t", "x", "example.com", false, false, List.of(),
                " ", "path", List.of()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("ACME_ORDER_URL_MISSING"));
    }

    @Test
    void completeValidation_missingAccountPath_throws() {
        assertThatThrownBy(() -> service.completeValidation(
                "t", "x", "example.com", false, false, List.of(),
                ORDER_URL, "  ", List.of()))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("ACME_ACCOUNT_PATH_MISSING"));
    }

    @Test
    void completeValidation_noTxtRecordsToVerify_throws() throws Exception {
        when(acmeAccountService.getOrCreate(eq("t"), eq("https://kv/secrets/acct")))
                .thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);

        when(mockOrder.getAuthorizations()).thenReturn(List.of());
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.completeValidation(
                    "t", "xref-1", "example.com", false, false, List.of(),
                                        ORDER_URL, "https://kv/secrets/acct",
                    List.of()))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_NO_DNS_CHALLENGE"));
        }
    }

    @Test
    void completeValidation_usesHintsForDnsPropagationWhenPresent() throws Exception {
                when(acmeAccountService.getOrCreate(eq("organization-1"), eq("https://kv.vault.azure.net/secrets/acct")))
                                .thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);
        X509Certificate leaf = selfSignedLeaf();

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leaf));
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        when(csrKeyPairService.generateCsrAndKeyPair(anyString(), any()))
                .thenReturn(new CsrKeyPairService.CsrKeyPairResult(
                        new byte[]{9}, "csr-pem", "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"));
        when(secretStore.create(eq("xref-1"), anyString()))
                .thenReturn("https://kv.vault.azure.net/secrets/cert-xref-1");

        CertManualValidateMessage.TxtRecordEntry hint = new CertManualValidateMessage.TxtRecordEntry();
        hint.setRecordName("_acme-challenge.example.com");
        hint.setRecordValue("expected-digest");

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            IssuanceResult result = service.completeValidation(
                    "organization-1", "xref-1", "example.com", false, false, List.of(),
                    ORDER_URL, "https://kv.vault.azure.net/secrets/acct",
                    List.of(hint));

            assertThat(result.certSecretHandle()).contains("cert-xref-1");
            assertThat(result.orderId()).isNull();

            @SuppressWarnings("unchecked")
            ArgumentCaptor<List<DnsPropagationVerifier.TxtRecord>> captor =
                    ArgumentCaptor.forClass(List.class);
            verify(dnsPropagationVerifier).verifyAll(captor.capture());
            assertThat(captor.getValue()).hasSize(1);
            assertThat(captor.getValue().get(0).recordName()).isEqualTo("_acme-challenge.example.com");
            assertThat(captor.getValue().get(0).expectedValue()).isEqualTo("expected-digest");
        }
    }

    @Test
    void completeValidation_dnsVerifierThrowsPermanent_propagates() throws Exception {
        when(acmeAccountService.getOrCreate(eq("t"), eq("https://kv/secrets/acct")))
                .thenReturn(accountResult());
        Mockito.doThrow(new PermanentAgentException("DNS_PROPAGATION_TIMEOUT", "not visible"))
                .when(dnsPropagationVerifier).verifyAll(anyList());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        CertManualValidateMessage.TxtRecordEntry hint = new CertManualValidateMessage.TxtRecordEntry();
        hint.setRecordName("_acme-challenge.example.com");
        hint.setRecordValue("dig");

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.completeValidation(
                    "t", "x", "example.com", false, false, List.of(),
                                        ORDER_URL, "https://kv/secrets/acct",
                    List.of(hint)))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("DNS_PROPAGATION_TIMEOUT"));
        }
    }

    @Test
    void completeValidation_challengeInvalidAfterTrigger_throws() throws Exception {
                when(acmeAccountService.getOrCreate(eq("t"), eq("https://kv/secrets/acct")))
                                .thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        when(mockChallenge.getStatus()).thenReturn(Status.PENDING);
        when(mockChallenge.waitForCompletion(any(Duration.class))).thenReturn(Status.INVALID);

        CertManualValidateMessage.TxtRecordEntry hint = new CertManualValidateMessage.TxtRecordEntry();
        hint.setRecordName("_acme-challenge.example.com");
        hint.setRecordValue("dig");

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.completeValidation(
                    "t", "x", "example.com", false, false, List.of(),
                    ORDER_URL, "https://kv/secrets/acct",
                    List.of(hint)))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_CHALLENGE_FAILED"));
        }
    }

    @Test
    void completeValidation_orderRetryAfter_thenSucceeds() throws Exception {
        when(acmeAccountService.getOrCreate(eq("organization-1"), eq("https://kv.vault.azure.net/secrets/acct")))
                .thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);
        X509Certificate leaf = selfSignedLeaf();

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.PROCESSING, Status.PROCESSING, Status.VALID, Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leaf));
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        when(mockOrder.waitForCompletion(any(Duration.class))).thenReturn(Status.VALID);

        when(csrKeyPairService.generateCsrAndKeyPair(anyString(), any()))
                .thenReturn(new CsrKeyPairService.CsrKeyPairResult(
                        new byte[]{9}, "csr-pem", "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"));
        when(secretStore.create(eq("xref-1"), anyString()))
                .thenReturn("https://kv.vault.azure.net/secrets/cert-xref-1");

        CertManualValidateMessage.TxtRecordEntry hint = new CertManualValidateMessage.TxtRecordEntry();
        hint.setRecordName("_acme-challenge.example.com");
        hint.setRecordValue("expected-digest");

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            IssuanceResult result = service.completeValidation(
                    "organization-1", "xref-1", "example.com", false, false, List.of(),
                    ORDER_URL, "https://kv.vault.azure.net/secrets/acct",
                    List.of(hint));

            assertThat(result.certSecretHandle()).contains("cert-xref-1");
            verify(mockOrder).waitForCompletion(any(Duration.class));
        }
    }

    @Test
    void completeValidation_usesConfiguredDomainsForCsr_ignoringAcmeOrderIdentifiers() throws Exception {
        // Even when the ACME order contains extra identifiers (one.app.example.com,
        // two.app.example.com), the CSR must be built solely from the configured
        // sanDomainEntries not from whatever the CA happened to return in the order.
        // With empty sanDomainEntries the CSR must contain only the primary wildcard.
        when(acmeAccountService.getOrCreate(eq("organization-1"), eq("https://kv.vault.azure.net/secrets/acct")))
                .thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization authPrimary = mock(Authorization.class);
        Authorization authOne = mock(Authorization.class);
        Authorization authTwo = mock(Authorization.class);
        Dns01Challenge chPrimary = mock(Dns01Challenge.class);
        Dns01Challenge chOne = mock(Dns01Challenge.class);
        Dns01Challenge chTwo = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);
        X509Certificate leaf = selfSignedLeaf();

        when(authPrimary.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(authOne.getIdentifier()).thenReturn(Identifier.dns("one.app.example.com"));
        when(authTwo.getIdentifier()).thenReturn(Identifier.dns("two.app.example.com"));
        when(authPrimary.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(chPrimary));
        when(authOne.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(chOne));
        when(authTwo.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(chTwo));
        when(authPrimary.getStatus()).thenReturn(Status.VALID);
        when(authOne.getStatus()).thenReturn(Status.VALID);
        when(authTwo.getStatus()).thenReturn(Status.VALID);
        when(chPrimary.getStatus()).thenReturn(Status.VALID);
        when(chOne.getStatus()).thenReturn(Status.VALID);
        when(chTwo.getStatus()).thenReturn(Status.VALID);

        when(mockOrder.getAuthorizations()).thenReturn(List.of(authPrimary, authOne, authTwo));
        when(mockOrder.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leaf));
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        when(csrKeyPairService.generateCsrAndKeyPair(anyString(), any()))
                .thenReturn(new CsrKeyPairService.CsrKeyPairResult(
                        new byte[]{9}, "csr-pem", "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"));
        when(secretStore.create(eq("xref-1"), anyString()))
                .thenReturn("https://kv.vault.azure.net/secrets/cert-xref-1");

        CertManualValidateMessage.TxtRecordEntry hint = new CertManualValidateMessage.TxtRecordEntry();
        hint.setRecordName("_acme-challenge.example.com");
        hint.setRecordValue("expected-digest");

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            service.completeValidation(
                    "organization-1", "xref-1", "example.com", true, true, List.of(),
                    ORDER_URL, "https://kv.vault.azure.net/secrets/acct",
                    List.of(hint));

            // sanDomainEntries is empty, buildOrderDomainList produces ["*.example.com", "example.com"].
            // The ACME order's extra identifiers (one.app.*, two.app.*) must NOT appear in the CSR.
            @SuppressWarnings("unchecked")
            ArgumentCaptor<List<String>> sanCaptor = ArgumentCaptor.forClass(List.class);
            verify(csrKeyPairService).generateCsrAndKeyPair(eq("*.example.com"), sanCaptor.capture());
            assertThat(sanCaptor.getValue()).containsExactly("example.com");
        }
    }

    // ── Additional branch coverage ─────────────────────────────────────────────

    @Test
    void requestTxtRecords_acmeExceptionNotRateLimit_throwsPermanent() throws Exception {
        when(acmeAccountService.getOrCreate(anyString(), any())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);

        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenThrow(
                new org.shredzone.acme4j.exception.AcmeException("server error"));
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.requestTxtRecords(
                    "t", "x", "example.com", false, false, List.of(), null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_MANUAL_TXT_FAILED"));
        }
    }

    @Test
    void requestTxtRecords_acmeExceptionRateLimited_throwsRetryable() throws Exception {
        when(acmeAccountService.getOrCreate(anyString(), any())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);

        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        // AcmeException whose message triggers the heuristic rate-limit classifier
        when(mockOrderBuilder.create()).thenThrow(
                new org.shredzone.acme4j.exception.AcmeException("rate limit exceeded, retry after 60"));
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.requestTxtRecords(
                    "t", "x", "example.com", false, false, List.of(), null))
                    .isInstanceOf(RetryableAgentException.class);
        }
    }

    @Test
    void requestTxtRecords_genericExceptionRateLimited_throwsRetryable() throws Exception {
        when(acmeAccountService.getOrCreate(anyString(), any())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);

        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        // Generic RuntimeException with rate-limit-shaped message -> heuristic catches it in
        // the outer Exception catch
        when(mockOrderBuilder.create()).thenThrow(
                new RuntimeException("too many requests, try again later"));
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.requestTxtRecords(
                    "t", "x", "example.com", false, false, List.of(), null))
                    .isInstanceOf(RetryableAgentException.class);
        }
    }

    @Test
    void requestTxtRecords_genericExceptionNoRateLimit_throwsPermanent() throws Exception {
        when(acmeAccountService.getOrCreate(anyString(), any())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Account mockAccount = mock(Account.class);
        OrderBuilder mockOrderBuilder = mock(OrderBuilder.class);

        when(mockAccount.newOrder()).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.domains(anyList())).thenReturn(mockOrderBuilder);
        when(mockOrderBuilder.create()).thenThrow(new RuntimeException("unexpected NPE"));
        when(mockLogin.getAccount()).thenReturn(mockAccount);

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.requestTxtRecords(
                    "t", "x", "example.com", false, false, List.of(), null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_MANUAL_TXT_FAILED"));
        }
    }

    @Test
    void completeValidation_dnsVerifierThrowsRateLimitedRuntime_throwsRetryable() throws Exception {
        // The outer Exception catch in completeValidation should detect a heuristic rate-limit
        // shape from a non-Acme RuntimeException raised by the DNS propagation verifier.
        when(acmeAccountService.getOrCreate(anyString(), anyString())).thenReturn(accountResult());
        Mockito.doThrow(new RuntimeException("rate limit exceeded for DNS"))
                .when(dnsPropagationVerifier).verifyAll(anyList());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.completeValidation(
                    "t", "x", "example.com", false, false, List.of(),
                    ORDER_URL, "https://kv/secrets/acct", List.of()))
                    .isInstanceOf(RetryableAgentException.class);
        }
    }

    @Test
    void completeValidation_genericRuntimeRateLimited_throwsRetryable() throws Exception {
        when(acmeAccountService.getOrCreate(anyString(), anyString())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        when(mockLogin.bindOrder(any(URL.class)))
                .thenThrow(new RuntimeException("too many requests"));

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.completeValidation(
                    "t", "x", "example.com", false, false, List.of(),
                    ORDER_URL, "https://kv/secrets/acct", List.of()))
                    .isInstanceOf(RetryableAgentException.class);
        }
    }

    @Test
    void completeValidation_genericRuntime_throwsPermanent() throws Exception {
        when(acmeAccountService.getOrCreate(anyString(), anyString())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        when(mockLogin.bindOrder(any(URL.class)))
                .thenThrow(new RuntimeException("unexpected"));

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.completeValidation(
                    "t", "x", "example.com", false, false, List.of(),
                    ORDER_URL, "https://kv/secrets/acct", List.of()))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_MANUAL_VALIDATE_FAILED"));
        }
    }

    @Test
    void completeValidation_nullTxtRecordHints_fallsBackToOrderAuths() throws Exception {
        // null hints list → service derives TXT records from order.getAuthorizations().
        when(acmeAccountService.getOrCreate(anyString(), anyString())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);
        X509Certificate leaf = selfSignedLeaf();

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("derived-digest");
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leaf));
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        when(csrKeyPairService.generateCsrAndKeyPair(anyString(), any()))
                .thenReturn(new CsrKeyPairService.CsrKeyPairResult(
                        new byte[]{9}, "csr-pem", "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"));
        when(secretStore.create(anyString(), anyString())).thenReturn("kv-path");

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            IssuanceResult r = service.completeValidation(
                    "t", "x", "example.com", false, false, List.of(),
                    ORDER_URL, "https://kv/secrets/acct", null);
            assertThat(r).isNotNull();
        }
    }

    @Test
    void completeValidation_oneAuthMissingDns01Challenge_skipped() throws Exception {
        // Hint provides TXT, so toVerify is non-empty. After verify, the trigger loop encounters
        // an authorization whose findChallenge returns Optional.empty() → continue (line 223).
        when(acmeAccountService.getOrCreate(anyString(), anyString())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuthWithChallenge = mock(Authorization.class);
        Authorization mockAuthWithout = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);
        X509Certificate leaf = selfSignedLeaf();

        when(mockAuthWithChallenge.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuthWithChallenge.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuthWithChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");

        // Second auth has no DNS-01 challenge → trigger loop skips it (line 222-223)
        when(mockAuthWithout.getIdentifier()).thenReturn(Identifier.dns("other.example.com"));
        when(mockAuthWithout.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.empty());

        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuthWithChallenge, mockAuthWithout));
        when(mockOrder.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leaf));
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        when(csrKeyPairService.generateCsrAndKeyPair(anyString(), any()))
                .thenReturn(new CsrKeyPairService.CsrKeyPairResult(
                        new byte[]{9}, "csr-pem", "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"));
        when(secretStore.create(anyString(), anyString())).thenReturn("kv-path");

        CertManualValidateMessage.TxtRecordEntry hint = new CertManualValidateMessage.TxtRecordEntry();
        hint.setRecordName("_acme-challenge.example.com");
        hint.setRecordValue("d");

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            IssuanceResult r = service.completeValidation(
                    "t", "x", "example.com", false, false, List.of(),
                    ORDER_URL, "https://kv/secrets/acct", List.of(hint));
            assertThat(r).isNotNull();
        }
    }

    @Test
    void completeValidation_challengeAlreadyValid_skipsTrigger() throws Exception {
        // challenge.getStatus() == VALID → trigger block (line 212-216) is skipped
        when(acmeAccountService.getOrCreate(anyString(), anyString())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);
        X509Certificate leaf = selfSignedLeaf();

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);  // Already VALID, no trigger
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leaf));
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        when(csrKeyPairService.generateCsrAndKeyPair(anyString(), any()))
                .thenReturn(new CsrKeyPairService.CsrKeyPairResult(
                        new byte[]{9}, "csr-pem", "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"));
        when(secretStore.create(anyString(), anyString())).thenReturn("kv-path");

        CertManualValidateMessage.TxtRecordEntry hint = new CertManualValidateMessage.TxtRecordEntry();
        hint.setRecordName("_acme-challenge.example.com");
        hint.setRecordValue("d");

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            IssuanceResult r = service.completeValidation(
                    "t", "x", "example.com", false, false, List.of(),
                    ORDER_URL, "https://kv/secrets/acct", List.of(hint));
            assertThat(r).isNotNull();
            // trigger should NOT have been called (challenge was already VALID)
            verify(mockChallenge, never()).trigger();
        }
    }

    @Test
    void completeValidation_blankTxtRecordHints_filtered_falsBackToOrderAuths() throws Exception {
        // Hints with blank recordName/recordValue are skipped (lines 179-183) and the service
        // falls back to deriving from order.getAuthorizations()'s DNS-01 challenge digest.
        when(acmeAccountService.getOrCreate(anyString(), anyString())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);
        Certificate mockCert = mock(Certificate.class);
        X509Certificate leaf = selfSignedLeaf();

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("derived-digest");
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.VALID);
        when(mockOrder.getCertificate()).thenReturn(mockCert);
        when(mockCert.getCertificateChain()).thenReturn(List.of(leaf));
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        when(csrKeyPairService.generateCsrAndKeyPair(anyString(), any()))
                .thenReturn(new CsrKeyPairService.CsrKeyPairResult(
                        new byte[]{9}, "csr-pem", "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"));
        when(secretStore.create(anyString(), anyString())).thenReturn("kv-path");

        CertManualValidateMessage.TxtRecordEntry blankHint = new CertManualValidateMessage.TxtRecordEntry();
        blankHint.setRecordName("  ");
        blankHint.setRecordValue("  ");

        CertManualValidateMessage.TxtRecordEntry nullHint = new CertManualValidateMessage.TxtRecordEntry();
        // nulls

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            IssuanceResult r = service.completeValidation(
                    "t", "x", "example.com", false, false, List.of(),
                    ORDER_URL, "https://kv/secrets/acct",
                    java.util.Arrays.asList(blankHint, nullHint, null));

            assertThat(r).isNotNull();
        }
    }

    @Test
    void completeValidation_challengeWaitThrowsAcmeException_throwsPermanent() throws Exception {
        when(acmeAccountService.getOrCreate(anyString(), anyString())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getStatus()).thenReturn(Status.PENDING);
        when(mockChallenge.getDigest()).thenReturn("d");
        // waitForCompletion throws AcmeException
        when(mockChallenge.waitForCompletion(any(Duration.class)))
                .thenThrow(new org.shredzone.acme4j.exception.AcmeException("polling failed"));
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        CertManualValidateMessage.TxtRecordEntry hint = new CertManualValidateMessage.TxtRecordEntry();
        hint.setRecordName("_acme-challenge.example.com");
        hint.setRecordValue("d");

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.completeValidation(
                    "t", "x", "example.com", false, false, List.of(),
                    ORDER_URL, "https://kv/secrets/acct", List.of(hint)))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_CHALLENGE_TIMEOUT"));
        }
    }

    @Test
    void completeValidation_challengeNeitherValidNorInvalid_throwsTimeoutPermanent() throws Exception {
        // Challenge waitForCompletion returns PENDING (not VALID/INVALID) → final timeout branch
        when(acmeAccountService.getOrCreate(anyString(), anyString())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockChallenge.getStatus()).thenReturn(Status.PENDING);
        when(mockChallenge.waitForCompletion(any(Duration.class))).thenReturn(Status.PENDING);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        CertManualValidateMessage.TxtRecordEntry hint = new CertManualValidateMessage.TxtRecordEntry();
        hint.setRecordName("_acme-challenge.example.com");
        hint.setRecordValue("d");

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.completeValidation(
                    "t", "x", "example.com", false, false, List.of(),
                    ORDER_URL, "https://kv/secrets/acct", List.of(hint)))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_CHALLENGE_TIMEOUT"));
        }
    }

    @Test
    void completeValidation_authorizationWaitThrowsAcmeException_throwsPermanentChallengeTimeout() throws Exception {
        when(acmeAccountService.getOrCreate(anyString(), anyString())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        // Authorization pending then throws on waitForCompletion
        when(mockAuth.getStatus()).thenReturn(Status.PENDING);
        when(mockAuth.waitForCompletion(any(Duration.class)))
                .thenThrow(new org.shredzone.acme4j.exception.AcmeException("auth poll failed"));
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        CertManualValidateMessage.TxtRecordEntry hint = new CertManualValidateMessage.TxtRecordEntry();
        hint.setRecordName("_acme-challenge.example.com");
        hint.setRecordValue("d");

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.completeValidation(
                    "t", "x", "example.com", false, false, List.of(),
                    ORDER_URL, "https://kv/secrets/acct", List.of(hint)))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_CHALLENGE_TIMEOUT"));
        }
    }

    @Test
    void completeValidation_authorizationInvalidAfterWait_throwsChallengeFailed() throws Exception {
        when(acmeAccountService.getOrCreate(anyString(), anyString())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockAuth.getStatus()).thenReturn(Status.PENDING);
        when(mockAuth.waitForCompletion(any(Duration.class))).thenReturn(Status.INVALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        CertManualValidateMessage.TxtRecordEntry hint = new CertManualValidateMessage.TxtRecordEntry();
        hint.setRecordName("_acme-challenge.example.com");
        hint.setRecordValue("d");

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.completeValidation(
                    "t", "x", "example.com", false, false, List.of(),
                    ORDER_URL, "https://kv/secrets/acct", List.of(hint)))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_CHALLENGE_FAILED"));
        }
    }

    @Test
    void completeValidation_authorizationStuckPending_throwsChallengeTimeout() throws Exception {
        when(acmeAccountService.getOrCreate(anyString(), anyString())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockAuth.getStatus()).thenReturn(Status.PENDING);
        when(mockAuth.waitForCompletion(any(Duration.class))).thenReturn(Status.PENDING);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        CertManualValidateMessage.TxtRecordEntry hint = new CertManualValidateMessage.TxtRecordEntry();
        hint.setRecordName("_acme-challenge.example.com");
        hint.setRecordValue("d");

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.completeValidation(
                    "t", "x", "example.com", false, false, List.of(),
                    ORDER_URL, "https://kv/secrets/acct", List.of(hint)))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_CHALLENGE_TIMEOUT"));
        }
    }

    @Test
    void completeValidation_orderWaitThrowsAcmeException_throwsPermanentOrderTimeout() throws Exception {
        when(acmeAccountService.getOrCreate(anyString(), anyString())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockAuth.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockOrder.getStatus()).thenReturn(Status.PROCESSING);
        when(mockOrder.waitForCompletion(any(Duration.class)))
                .thenThrow(new org.shredzone.acme4j.exception.AcmeException("order poll failed"));
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        when(csrKeyPairService.generateCsrAndKeyPair(anyString(), any()))
                .thenReturn(new CsrKeyPairService.CsrKeyPairResult(
                        new byte[]{9}, "csr-pem", "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"));

        CertManualValidateMessage.TxtRecordEntry hint = new CertManualValidateMessage.TxtRecordEntry();
        hint.setRecordName("_acme-challenge.example.com");
        hint.setRecordValue("d");

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.completeValidation(
                    "t", "x", "example.com", false, false, List.of(),
                    ORDER_URL, "https://kv/secrets/acct", List.of(hint)))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_ORDER_TIMEOUT"));
        }
    }

    @Test
    void completeValidation_authorizationInvalid_throwsPermanent() throws Exception {
        when(acmeAccountService.getOrCreate(anyString(), anyString())).thenReturn(accountResult());

        Login mockLogin = mock(Login.class);
        Order mockOrder = mock(Order.class);
        Authorization mockAuth = mock(Authorization.class);
        Dns01Challenge mockChallenge = mock(Dns01Challenge.class);

        when(mockAuth.getIdentifier()).thenReturn(Identifier.dns("example.com"));
        when(mockAuth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(mockChallenge));
        when(mockChallenge.getStatus()).thenReturn(Status.VALID);
        when(mockChallenge.getDigest()).thenReturn("d");
        // Auth becomes INVALID after waitForCompletion
        when(mockAuth.getStatus()).thenReturn(Status.PENDING);
        when(mockAuth.waitForCompletion(any(Duration.class))).thenReturn(Status.INVALID);
        when(mockOrder.getAuthorizations()).thenReturn(List.of(mockAuth));
        when(mockLogin.bindOrder(any(URL.class))).thenReturn(mockOrder);

        CertManualValidateMessage.TxtRecordEntry hint = new CertManualValidateMessage.TxtRecordEntry();
        hint.setRecordName("_acme-challenge.example.com");
        hint.setRecordValue("d");

        try (MockedConstruction<Session> ignored = mockConstruction(Session.class,
                (mock, ctx) -> when(mock.login(any(URL.class), any(KeyPair.class))).thenReturn(mockLogin))) {

            assertThatThrownBy(() -> service.completeValidation(
                    "t", "x", "example.com", false, false, List.of(),
                    ORDER_URL, "https://kv/secrets/acct", List.of(hint)))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_CHALLENGE_FAILED"));
        }
    }

    private static AcmeAccountResult accountResult() throws Exception {
        KeyPair kp = KeyPairUtils.createKeyPair(2048);
        return new AcmeAccountResult(
                kp,
                new URL(ACCT_URL),
                "https://kv-agent.vault.azure.net/secrets/acme-acct-organization-1");
    }

    private static X509Certificate selfSignedLeaf() throws Exception {
        KeyPair certKp = KeyPairUtils.createKeyPair(2048);
        var builder = new JcaX509v3CertificateBuilder(
                new X500Principal("CN=example.com"),
                BigInteger.ONE,
                new Date(),
                new Date(System.currentTimeMillis() + 90L * 24 * 3600 * 1000),
                new X500Principal("CN=example.com"),
                certKp.getPublic());
        var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(certKp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

        private Authorization mockAuthorization(String domain, String digest) {
                Authorization auth = mock(Authorization.class);
                Dns01Challenge challenge = mock(Dns01Challenge.class);
                when(auth.getIdentifier()).thenReturn(Identifier.dns(domain));
                when(auth.findChallenge(Dns01Challenge.TYPE)).thenReturn(Optional.of(challenge));
                when(auth.getStatus()).thenReturn(Status.VALID);
                when(challenge.getDigest()).thenReturn(digest);
                return auth;
        }
}
