// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.smallstep;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.secrets.SecretStoreProvider;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SmallstepClientRevocationTest {
    private static final Instant NOW = Instant.parse("2026-09-01T00:00:00Z");

    /**
     * Certificate validity has to satisfy two clocks. The client's own CRL checks run on the pinned
     * {@link #NOW}, but the TLS handshake is validated by the JSSE against the real system clock,
     * which no test can pin. A window anchored only on NOW expires on a wall-clock date and the
     * suite then fails every day after it, on a change nobody made.
     */
    private static final Instant REAL_NOW = Instant.now();
    private static final Instant VALID_FROM =
            (NOW.isBefore(REAL_NOW) ? NOW : REAL_NOW).minus(Duration.ofDays(1));
    private static final Instant VALID_TO =
            (NOW.isAfter(REAL_NOW) ? NOW : REAL_NOW).plus(Duration.ofDays(1));
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final ObjectMapper MAPPER = JsonMapper.builderWithJackson2Defaults().build();

    private Authority authority;
    private HttpsServer server;
    private SmallstepClient client;
    private AgentProperties properties;
    private byte[] crl;
    private int revokeStatus;
    private int crlStatus;
    private String revokeErrorMessage;
    private JsonNode revokeRequest;
    private boolean updateCrlOnSuccessfulRevoke;
    private boolean blockCrl;
    private CountDownLatch crlEntered;
    private CountDownLatch crlRelease;
    private final AtomicInteger intermediateRequests = new AtomicInteger();

    @BeforeAll
    static void addProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    void setUp() throws Exception {
        authority = authority();
        crl = crl(authority, NOW.minusSeconds(30), NOW.plusSeconds(3600),
                BigInteger.valueOf(0xdef)).getEncoded();
        revokeStatus = 200;
        crlStatus = 200;
        revokeErrorMessage = "already revoked";
        updateCrlOnSuccessfulRevoke = true;
        crlEntered = new CountDownLatch(1);
        crlRelease = new CountDownLatch(1);
        server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverContext(authority)));
        server.createContext("/1.0/revoke", this::revoke);
        server.createContext("/1.0/crl", this::crl);
        server.createContext("/1.0/intermediates", this::intermediates);
        server.start();

        String credential = credentialJson(authority,
                "https://localhost:" + server.getAddress().getPort());
        properties = new AgentProperties();
        properties.getSmallstep().setEnabled(true);
        properties.getSmallstep().setCredentialsJson(credential);
        properties.getSmallstep().setRequestTimeoutSeconds(5);
        client = new SmallstepClient(properties, new UnusedSecretStore(), MAPPER, CLOCK);
    }

    @AfterEach
    void stopServer() {
        crlRelease.countDown();
        server.stop(0);
    }

    @Test
    void revokeSendsTheStepCaContractAndConfirmsFromTheSignedCrl() {
        SmallstepRevocationService.Result result = client.revoke(
                authority.intermediate().getSubjectX500Principal().getName(),
                "abc", "KEY_COMPROMISE");

        assertThat(result.alreadyRevoked()).isFalse();
        assertThat(result.reason()).isEqualTo("KEY_COMPROMISE");
        assertThat(revokeRequest.path("serial").asString()).isEqualTo("2748");
        assertThat(revokeRequest.path("reasonCode").asInt()).isEqualTo(1);
        assertThat(revokeRequest.path("passive").asBoolean()).isTrue();
        assertThat(revokeRequest.path("ott").asString()).isNotBlank();
        assertThat(intermediateRequests).hasValue(1);
    }

    @Test
    void repeatRevokeIsSuccessfulOnlyWhenTheCrlAlreadyContainsTheSerial() {
        revokeStatus = 403;
        crl = encodedCrl(BigInteger.valueOf(0xabc));

        SmallstepRevocationService.Result result = client.revoke(
                authority.intermediate().getSubjectX500Principal().getName(),
                "abc", "KEY_COMPROMISE");

        assertThat(result.alreadyRevoked()).isTrue();
        assertThat(revokeRequest).isNull();
    }

    @Test
    void duplicateRevokeWithoutCrlEvidenceRemainsRetryable() throws Exception {
        revokeStatus = 403;
        crl = crl(authority, NOW.minusSeconds(30), NOW.plusSeconds(3600),
                BigInteger.valueOf(0xdef)).getEncoded();

        assertThatThrownBy(() -> client.revoke(
                authority.intermediate().getSubjectX500Principal().getName(),
                "abc", "KEY_COMPROMISE"))
                .isInstanceOfSatisfying(TransientAgentException.class, exception ->
                        assertThat(exception.getErrorCode())
                                .isEqualTo("SMALLSTEP_REVOCATION_NOT_CONFIRMED"));
    }

    @Test
    void genuineAuthorizationFailureRemainsPermanent() throws Exception {
        revokeStatus = 403;
        revokeErrorMessage = "invalid provisioner token";
        crl = crl(authority, NOW.minusSeconds(30), NOW.plusSeconds(3600),
                BigInteger.valueOf(0xdef)).getEncoded();

        assertThatThrownBy(() -> client.revoke(
                authority.intermediate().getSubjectX500Principal().getName(),
                "abc", "KEY_COMPROMISE"))
                .isInstanceOfSatisfying(PermanentAgentException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo("SMALLSTEP_AUTH_FAILED"));
    }

    @Test
    void acceptedWriteWithoutCrlEvidenceRemainsRetryable() throws Exception {
        updateCrlOnSuccessfulRevoke = false;

        assertThatThrownBy(() -> client.revoke(
                authority.intermediate().getSubjectX500Principal().getName(),
                "abc", "KEY_COMPROMISE"))
                .isInstanceOfSatisfying(TransientAgentException.class, exception ->
                        assertThat(exception.getErrorCode())
                                .isEqualTo("SMALLSTEP_REVOCATION_NOT_CONFIRMED"));
    }

    @Test
    void renewalLookupUsesTheSameVerifiedCrlAndCachesTheTrustedIntermediate() {
        crl = encodedCrl(BigInteger.valueOf(0xabc));
        String issuer = authority.intermediate().getSubjectX500Principal().getName();

        assertThat(client.isRevoked(issuer, "abc")).isTrue();
        assertThat(client.isRevoked(issuer, "def")).isFalse();
        assertThat(intermediateRequests).hasValue(1);
    }

    @Test
    void stalledCrlBodyIsBoundedByTheConfiguredRequestTimeout() {
        properties.getSmallstep().setRequestTimeoutSeconds(1);
        InputStream stalled = new InputStream() {
            private final CountDownLatch neverReleased = new CountDownLatch(1);

            @Override
            public int read() throws IOException {
                try {
                    neverReleased.await();
                    return -1;
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    throw new InterruptedIOException("test read interrupted");
                }
            }
        };

        assertThatThrownBy(() -> client.readCrlBody(stalled, 1024))
                .isInstanceOfSatisfying(TransientAgentException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo("SMALLSTEP_CRL_TIMEOUT"));
    }

    @Test
    void missingCrlFailsBeforeSubmittingRevocation() {
        crlStatus = 404;

        assertThatThrownBy(() -> client.revoke(
                authority.intermediate().getSubjectX500Principal().getName(),
                "abc", "KEY_COMPROMISE"))
                .isInstanceOfSatisfying(PermanentAgentException.class, exception ->
                        assertThat(exception.getErrorCode())
                                .isEqualTo("SMALLSTEP_CRL_NOT_CONFIGURED"));
        assertThat(revokeRequest).isNull();
    }

    @Test
    void concurrentCrlDownloadsAreBoundedPerPod() throws Exception {
        properties.getSmallstep().setMaxConcurrentCrlFetches(1);
        client = new SmallstepClient(properties, new UnusedSecretStore(), MAPPER, CLOCK);
        blockCrl = true;
        AtomicReference<Throwable> firstFailure = new AtomicReference<>();
        String issuer = authority.intermediate().getSubjectX500Principal().getName();
        Thread first = Thread.ofVirtual().start(() -> {
            try {
                client.isRevoked(issuer, "abc");
            } catch (Throwable failure) {
                firstFailure.set(failure);
            }
        });
        assertThat(crlEntered.await(5, TimeUnit.SECONDS)).isTrue();

        assertThatThrownBy(() -> client.isRevoked(issuer, "def"))
                .isInstanceOfSatisfying(TransientAgentException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo("SMALLSTEP_CRL_BUSY"));

        crlRelease.countDown();
        first.join(5_000);
        assertThat(first.isAlive()).isFalse();
        assertThat(firstFailure.get()).isNull();
    }

    private void revoke(HttpExchange exchange) throws java.io.IOException {
        revokeRequest = MAPPER.readTree(exchange.getRequestBody());
        if (revokeStatus == 200 && updateCrlOnSuccessfulRevoke) {
            crl = encodedCrl(BigInteger.valueOf(0xabc));
        }
        byte[] response = (revokeStatus == 200 ? "{\"status\":\"ok\"}"
                : "{\"message\":\"" + revokeErrorMessage + "\"}")
                .getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(revokeStatus, response.length);
        exchange.getResponseBody().write(response);
        exchange.close();
    }

    private void crl(HttpExchange exchange) throws java.io.IOException {
        exchange.getResponseHeaders().add("Content-Type", "application/pkix-crl");
        if (crlStatus != 200) {
            exchange.sendResponseHeaders(crlStatus, -1);
            exchange.close();
            return;
        }
        exchange.sendResponseHeaders(200, crl.length);
        if (blockCrl) {
            crlEntered.countDown();
            try {
                crlRelease.await();
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new InterruptedIOException("test CRL response interrupted");
            }
        }
        exchange.getResponseBody().write(crl);
        exchange.close();
    }

    private byte[] encodedCrl(BigInteger serial) {
        try {
            return crl(authority, NOW.minusSeconds(30), NOW.plusSeconds(3600), serial)
                    .getEncoded();
        } catch (Exception exception) {
            throw new IllegalStateException("Could not create test CRL", exception);
        }
    }

    private void intermediates(HttpExchange exchange) throws java.io.IOException {
        intermediateRequests.incrementAndGet();
        byte[] response;
        try {
            response = MAPPER.writeValueAsBytes(
                    java.util.Map.of("crts", java.util.List.of(pem(authority.intermediate()))));
        } catch (Exception exception) {
            throw new java.io.IOException("Failed to encode test intermediate", exception);
        }
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(201, response.length);
        exchange.getResponseBody().write(response);
        exchange.close();
    }

    private static String credentialJson(Authority authority, String baseUrl) throws Exception {
        String jwk = new ECKeyGenerator(Curve.P_256).keyID("test-provisioner").generate()
                .toJSONString();
        return MAPPER.writeValueAsString(java.util.Map.of(
                "baseUrl", baseUrl,
                "authorityName", "Test Smallstep CA",
                "provisionerName", "certping-test",
                "provisionerPrivateJwk", MAPPER.readTree(jwk),
                "rootCaPem", pem(authority.root())));
    }

    private static SSLContext serverContext(Authority authority) throws Exception {
        char[] password = "test-password".toCharArray();
        KeyStore keys = KeyStore.getInstance("PKCS12");
        keys.load(null, password);
        keys.setKeyEntry("server", authority.serverKey().getPrivate(), password,
                new java.security.cert.Certificate[]{authority.server(), authority.root()});
        KeyManagerFactory managers = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        managers.init(keys, password);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(managers.getKeyManagers(), null, null);
        return context;
    }

    private static Authority authority() throws Exception {
        KeyPair rootKey = keyPair();
        X509Certificate root = caCertificate(
                "CN=Test Root", "CN=Test Root", rootKey, rootKey, BigInteger.ONE);
        KeyPair intermediateKey = keyPair();
        X509Certificate intermediate = caCertificate(
                "CN=Test Root", "CN=Test Intermediate", rootKey,
                intermediateKey, BigInteger.TWO);
        KeyPair serverKey = keyPair();
        X509Certificate server = serverCertificate(rootKey, serverKey);
        return new Authority(root, intermediate, intermediateKey, server, serverKey);
    }

    private static X509Certificate caCertificate(
            String issuer, String subject, KeyPair issuerKey, KeyPair subjectKey,
            BigInteger serial) throws Exception {
        JcaX509v3CertificateBuilder builder = certificateBuilder(
                issuer, subject, subjectKey, serial);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return certificate(builder, issuerKey);
    }

    private static X509Certificate serverCertificate(
            KeyPair rootKey, KeyPair serverKey) throws Exception {
        JcaX509v3CertificateBuilder builder = certificateBuilder(
                "CN=Test Root", "CN=localhost", serverKey, BigInteger.valueOf(3));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")));
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        return certificate(builder, rootKey);
    }

    private static JcaX509v3CertificateBuilder certificateBuilder(
            String issuer, String subject, KeyPair subjectKey, BigInteger serial) {
        return new JcaX509v3CertificateBuilder(new X500Name(issuer), serial,
                Date.from(VALID_FROM), Date.from(VALID_TO),
                new X500Name(subject), subjectKey.getPublic());
    }

    private static X509Certificate certificate(
            JcaX509v3CertificateBuilder builder, KeyPair issuerKey) throws Exception {
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
                        .build(issuerKey.getPrivate())));
    }

    private static X509CRL crl(Authority authority, Instant thisUpdate,
                               Instant nextUpdate, BigInteger serial) throws Exception {
        JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(
                authority.intermediate().getSubjectX500Principal(), Date.from(thisUpdate));
        builder.setNextUpdate(Date.from(nextUpdate));
        builder.addCRLEntry(serial, Date.from(thisUpdate), CRLReason.keyCompromise);
        return new JcaX509CRLConverter().setProvider("BC").getCRL(builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
                        .build(authority.intermediateKey().getPrivate())));
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String pem(X509Certificate certificate) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                        .encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    private record Authority(X509Certificate root, X509Certificate intermediate,
                             KeyPair intermediateKey, X509Certificate server,
                             KeyPair serverKey) {}

    private static final class UnusedSecretStore implements SecretStore {
        @Override public String read(String handle) { throw new UnsupportedOperationException(); }
        @Override public String create(String name, String value) { throw new UnsupportedOperationException(); }
        @Override public String update(String handle, String value) { throw new UnsupportedOperationException(); }
        @Override public void delete(String handle) { throw new UnsupportedOperationException(); }
        @Override public boolean isOwnedByThisAgent(String handle) { return false; }
        @Override public String handleFor(String name) { return name; }
        @Override public SecretStoreProvider provider() { return SecretStoreProvider.AZURE_KV; }
    }
}
