// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("EjbcaTlsContextFactory")
class EjbcaTlsContextFactoryTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    @Test
    @DisplayName("the IdP client is separate from the EJBCA client")
    void idpClientIsSeparateFromEjbcaClient() {
        // Regression guard. Reusing the EJBCA client for the token endpoint pins its truststore to
        // the customer's private ManagementCA, which cannot validate a public IdP — so OAuth would
        // fail on every request in the most common production shape (private EJBCA, public Entra).
        HttpClient idpClient = EjbcaTlsContextFactory.createIdpHttpClient(TIMEOUT);

        assertThat(idpClient).isNotNull();
        assertThat(idpClient.sslContext())
                .as("IdP client must keep the JDK default trust material")
                .isSameAs(defaultSslContext());
    }

    @Test
    @DisplayName("the EJBCA client does not use default trust material when a CA chain is pinned")
    void ejbcaClientPinsSuppliedChain() {
        EjbcaCredentials credentials = oauthCredentialsWithPinnedChain();

        HttpClient ejbcaClient = EjbcaTlsContextFactory.createHttpClient(credentials, TIMEOUT);

        assertThat(ejbcaClient.sslContext())
                .as("a pinned serverCaChainPem must replace the default trust material")
                .isNotSameAs(defaultSslContext());
    }

    @Test
    @DisplayName("never follows redirects, because a redirected POST loses its body")
    void neverFollowsRedirects() {
        assertThat(EjbcaTlsContextFactory.createIdpHttpClient(TIMEOUT).followRedirects())
                .isEqualTo(HttpClient.Redirect.NEVER);
        assertThat(EjbcaTlsContextFactory
                .createHttpClient(oauthCredentialsWithPinnedChain(), TIMEOUT).followRedirects())
                .isEqualTo(HttpClient.Redirect.NEVER);
    }

    private static javax.net.ssl.SSLContext defaultSslContext() {
        try {
            return javax.net.ssl.SSLContext.getDefault();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** OAuth so no P12 is needed, but with a pinned chain — the combination that used to break. */
    private static EjbcaCredentials oauthCredentialsWithPinnedChain() {
        return new EjbcaCredentials(
                EjbcaCredentials.AuthMethod.OAUTH_CLIENT_CREDENTIALS,
                "https://ejbca.internal.example.com:8443",
                null, null,
                "https://login.microsoftonline.com/tid/oauth2/v2.0/token",
                "client-id", "client-secret", "api://ejbca/.default", null,
                selfSignedCaPem());
    }

    /** A real X.509 — the factory parses it, so a placeholder string will not do. */
    private static String selfSignedCaPem() {
        try {
            java.security.Security.addProvider(
                    new org.bouncycastle.jce.provider.BouncyCastleProvider());
            var generator = java.security.KeyPairGenerator.getInstance("RSA", "BC");
            generator.initialize(2048);
            var keyPair = generator.generateKeyPair();
            var name = new org.bouncycastle.asn1.x500.X500NameBuilder(
                    org.bouncycastle.asn1.x500.style.BCStyle.INSTANCE)
                    .addRDN(org.bouncycastle.asn1.x500.style.BCStyle.CN, "test-ca").build();
            var holder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                    name, java.math.BigInteger.ONE,
                    new java.util.Date(System.currentTimeMillis() - 3600_000),
                    new java.util.Date(System.currentTimeMillis() + 3600_000),
                    name, keyPair.getPublic())
                    .build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                            "SHA256withRSA").setProvider("BC").build(keyPair.getPrivate()));
            return "-----BEGIN CERTIFICATE-----\n"
                    + java.util.Base64.getMimeEncoder(64, "\n".getBytes())
                            .encodeToString(holder.getEncoded())
                    + "\n-----END CERTIFICATE-----\n";
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
