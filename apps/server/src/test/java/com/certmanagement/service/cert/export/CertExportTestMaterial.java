// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HexFormat;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Real key pairs and a root → intermediate → leaf chain, generated locally, plus the agent's bundle
 * layout: chain PEM, then the key in the traditional OpenSSL form acme4j writes.
 *
 * <p>Keys and certificates always come from the JDK's providers, built with BouncyCastle unregistered:
 * the expected material must not depend on whether an earlier application boot left BouncyCastle
 * first, which also breaks the JDK's own EC key generator (it resolves its curve parameters by
 * provider order).
 */
final class CertExportTestMaterial {

    /** prime256v1 OID as OpenSSL writes it in an {@code EC PARAMETERS} block ahead of the key. */
    static final String EC_PARAMETERS_BLOCK =
            "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n";

    /** The JDK provider that implements {@code CertificateFactory("X.509")}. */
    private static final String SUN_PROVIDER = "SUN";
    private static final AtomicLong SERIALS = new AtomicLong(1000);
    private static final KeyPair ROOT_KEYS = rsaKeyPair();
    private static final KeyPair INTERMEDIATE_KEYS = rsaKeyPair();
    static final KeyPair RSA_LEAF_KEYS = rsaKeyPair();
    static final KeyPair EC_LEAF_KEYS = ecKeyPair();

    private CertExportTestMaterial() {
    }

    record Chain(X509Certificate leaf, X509Certificate intermediate, KeyPair leafKeys) {
    }

    static Chain chainFor(String commonName, KeyPair leafKeys) {
        return withJdkProvidersOnly(() -> {
            X500Name root = new X500Name("CN=Test Root");
            X500Name intermediateName = new X500Name("CN=Test Intermediate");
            X509Certificate intermediate = sign(root, ROOT_KEYS.getPrivate(), intermediateName,
                    INTERMEDIATE_KEYS, true);
            X509Certificate leaf = sign(intermediateName, INTERMEDIATE_KEYS.getPrivate(),
                    new X500Name("CN=" + commonName), leafKeys, false);
            return new Chain(leaf, intermediate, leafKeys);
        });
    }

    /** Exactly what LetsEncryptAcmeService stores: chainPem + "\n" + privateKeyPem. */
    static String agentBundle(Chain chain, boolean includeKey) {
        String chainPem = pem(chain.leaf()) + pem(chain.intermediate());
        return includeKey ? chainPem + "\n" + pem(chain.leafKeys()) : chainPem;
    }

    static String pem(Object object) {
        StringWriter out = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            writer.writeObject(object);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return out.toString();
    }

    static String fingerprint(X509Certificate certificate) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
            return HexFormat.of().withUpperCase().withDelimiter(":").formatHex(digest);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static KeyPair rsaKeyPair() {
        return withJdkProvidersOnly(() -> {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
            generator.initialize(2048);
            return generator.generateKeyPair();
        });
    }

    static KeyPair ecKeyPair() {
        return withJdkProvidersOnly(() -> {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "SunEC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        });
    }

    private static <T> T withJdkProvidersOnly(Callable<T> action) {
        try {
            return SecurityProviderModeExtension.callIn(SecurityProviderMode.NO_BOUNCY_CASTLE, action);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static X509Certificate sign(X500Name issuer, PrivateKey issuerKey, X500Name subject, KeyPair subjectKeys,
                                        boolean isCa) throws Exception {
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer,
                BigInteger.valueOf(SERIALS.incrementAndGet()), Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(90, ChronoUnit.DAYS)), subject, subjectKeys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        return new JcaX509CertificateConverter().setProvider(SUN_PROVIDER).getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey)));
    }
}
