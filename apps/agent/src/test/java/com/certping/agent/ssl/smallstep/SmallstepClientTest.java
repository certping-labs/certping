// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.smallstep;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.secrets.SecretStoreProvider;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Covers credential resolution only — {@link #connectedEndpoint()} parses the credential and
 * builds the TLS trust store without a network call, which is enough to exercise which source
 * (secret store vs literal credentials-json) fed the session.
 */
@DisplayName("SmallstepClient")
class SmallstepClientTest {

    private AgentProperties properties;
    private CountingSecretStore secretStore;
    private SmallstepClient client;
    private String rootCaPem;

    @BeforeEach
    void setUp() throws Exception {
        rootCaPem = selfSignedPem();
        properties = new AgentProperties();
        AgentProperties.SmallstepProperties config = properties.getSmallstep();
        config.setEnabled(true);
        config.setCredentialPath("kv://smallstep");

        secretStore = new CountingSecretStore(credentialJson());
        client = new SmallstepClient(properties, secretStore, JsonMapper.builderWithJackson2Defaults().build(), Clock.systemUTC());
    }

    @Test
    @DisplayName("asks step-ca for the profile validity only when one is known")
    void signBodyCarriesRelativeNotAfterOnlyWithAValidity() {
        assertThat(SmallstepClient.signBody("csr", "ott", java.time.Duration.ofDays(365)))
                .containsEntry("csr", "csr")
                .containsEntry("ott", "ott")
                .containsEntry("notAfter", "8760h");
        assertThat(SmallstepClient.signBody("csr", "ott", null)).doesNotContainKey("notAfter");
    }

    @Test
    @DisplayName("reads the credential from the secret store when only credential-path is set")
    void resolvesViaSecretStoreByDefault() {
        assertThat(client.connectedEndpoint()).isEqualTo("https://step.internal");
        assertThat(secretStore.reads()).isEqualTo(1);
    }

    @Test
    @DisplayName("uses credentials-json directly without touching the secret store when set")
    void usesCredentialsJsonWithoutSecretStore() {
        properties.getSmallstep().setCredentialPath(null);
        properties.getSmallstep().setCredentialsJson(credentialJson());

        assertThat(client.connectedEndpoint()).isEqualTo("https://step.internal");
        assertThat(secretStore.reads()).isEqualTo(0);
    }

    @Test
    @DisplayName("prefers credentials-json over credential-path when both are set")
    void credentialsJsonTakesPrecedenceOverCredentialPath() {
        properties.getSmallstep().setCredentialsJson(credentialJson());

        assertThat(client.connectedEndpoint()).isEqualTo("https://step.internal");
        assertThat(secretStore.reads()).isEqualTo(0);
    }

    @Test
    @DisplayName("fails clearly when neither credential path nor credentials-json is configured")
    void missingCredentialSourceIsRejected() {
        properties.getSmallstep().setCredentialPath("  ");

        assertThatThrownBy(() -> client.connectedEndpoint())
                .isInstanceOfSatisfying(PermanentAgentException.class, e ->
                        assertThat(e.getErrorCode()).isEqualTo("SMALLSTEP_CONFIG_MISSING"));
    }

    private String credentialJson() {
        return """
                {"baseUrl":"https://step.internal","authorityName":"Device CA",
                 "provisionerName":"certping-agent",
                 "provisionerPrivateJwk":{"kty":"EC","crv":"P-256","d":"secret"},
                 "rootCaPem":"%s"}"""
                .formatted(rootCaPem.replace("\n", "\\n"));
    }

    private static String selfSignedPem() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        var subject = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, "Smallstep Test Root").build();
        var holder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.ONE,
                new Date(System.currentTimeMillis() - 3_600_000),
                new Date(System.currentTimeMillis() + 3_600_000),
                subject, keyPair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
                        .build(keyPair.getPrivate()));
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider("BC").getCertificate(holder);
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    private static final class CountingSecretStore implements SecretStore {
        private final AtomicInteger reads = new AtomicInteger();
        private final String value;

        CountingSecretStore(String value) {
            this.value = value;
        }

        int reads() {
            return reads.get();
        }

        @Override public String read(String handle) { reads.incrementAndGet(); return value; }
        @Override public String create(String name, String v) { throw new UnsupportedOperationException(); }
        @Override public String update(String handle, String v) { throw new UnsupportedOperationException(); }
        @Override public void delete(String handle) { throw new UnsupportedOperationException(); }
        @Override public boolean isOwnedByThisAgent(String handle) { return false; }
        @Override public String handleFor(String name) { return name; }
        @Override public SecretStoreProvider provider() { return null; }
    }
}
