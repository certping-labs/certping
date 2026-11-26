// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The RA identity must publish the <em>CA</em> as the issuer in GetCACert, not the RA leaf. A PKCS#12
 * stores its chain leaf-first, so {@link RaIdentity#caChain()} must drop the leaf.
 */
class RaIdentityTest {

    @BeforeAll
    static void provider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void caChainStripsTheRaLeafWhenChainIsLeafFirst() throws Exception {
        X509Certificate ra = selfSigned("CN=ra");
        X509Certificate ca = selfSigned("CN=ManagementCA");
        RaIdentity id = new RaIdentity(null, ra, List.of(ra, ca));   // PKCS#12 shape: [RA, CA]

        assertThat(id.cert()).isEqualTo(ra);
        assertThat(id.caChain()).containsExactly(ca);
    }

    @Test
    void caChainIsEmptyWhenOnlyTheRaCertIsPresent() throws Exception {
        X509Certificate ra = selfSigned("CN=ra");
        assertThat(new RaIdentity(null, ra, List.of(ra)).caChain()).isEmpty();
    }

    @Test
    void caChainIsUnchangedWhenChainDoesNotLeadWithTheRaLeaf() throws Exception {
        X509Certificate ra = selfSigned("CN=ra");
        X509Certificate ca = selfSigned("CN=ManagementCA");
        assertThat(new RaIdentity(null, ra, List.of(ca)).caChain()).containsExactly(ca);
    }

    @Test
    void rejectsEcRaIdentityBecauseScepEnvelopeRequiresRsaKeyTransport() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair keys = generator.generateKeyPair();
        X509Certificate certificate = selfSigned(keys, "CN=ec-ra", "SHA256withECDSA");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("ra", keys.getPrivate(), "pw".toCharArray(),
                new Certificate[]{certificate});
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        keyStore.store(output, "pw".toCharArray());

        assertThatThrownBy(() -> RaIdentity.fromPkcs12(output.toByteArray(), "pw".toCharArray()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("must use RSA")
                .hasMessageContaining("--kty RSA --size 2048");
    }

    @Test
    void rejectsAChainThatStopsBeforeTheRoot() throws Exception {
        KeyPair caKeys = rsa();
        KeyPair raKeys = rsa();
        X509Certificate ra = signed(raKeys, "CN=ra", caKeys, "CN=Intermediate");

        assertThatThrownBy(() -> RaIdentity.fromPkcs12(p12(raKeys, ra), "pw".toCharArray()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("up to and including the root");
    }

    @Test
    void acceptsAChainThatEndsAtTheRoot() throws Exception {
        KeyPair rootKeys = rsa();
        KeyPair raKeys = rsa();
        X509Certificate root = selfSigned(rootKeys, "CN=Root", "SHA256withRSA");
        X509Certificate ra = signed(raKeys, "CN=ra", rootKeys, "CN=Root");

        RaIdentity id = RaIdentity.fromPkcs12(p12(raKeys, ra, root), "pw".toCharArray());
        assertThat(id.caChain()).containsExactly(root);
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    private static X509Certificate signed(KeyPair subject, String dn, KeyPair issuer, String issuerDn)
            throws Exception {
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name(issuerDn), BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minus(Duration.ofMinutes(5))), Date.from(now.plus(Duration.ofDays(1))),
                new X500Name(dn), subject.getPublic());
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
                .build(issuer.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(cs));
    }

    private static byte[] p12(KeyPair keys, X509Certificate... chain) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("ra", keys.getPrivate(), "pw".toCharArray(), chain);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        keyStore.store(output, "pw".toCharArray());
        return output.toByteArray();
    }

    private static X509Certificate selfSigned(String dn) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair keys = g.generateKeyPair();
        return selfSigned(keys, dn, "SHA256withRSA");
    }

    private static X509Certificate selfSigned(KeyPair keys, String dn, String signatureAlgorithm)
            throws Exception {
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name(dn), BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minus(Duration.ofMinutes(5))), Date.from(now.plus(Duration.ofDays(1))),
                new X500Name(dn), keys.getPublic());
        ContentSigner cs = new JcaContentSignerBuilder(signatureAlgorithm).setProvider("BC")
                .build(keys.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(cs));
    }
}
