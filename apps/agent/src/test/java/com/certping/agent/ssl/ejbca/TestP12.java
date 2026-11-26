// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

/** A real client PKCS#12, generated once — the driver actually loads it, so a stub will not do. */
final class TestP12 {

    static final String PASSWORD = "p12-password";
    private static volatile String cached;

    private TestP12() {
    }

    static synchronized String base64() {
        if (cached != null) {
            return cached;
        }
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();

            var subject = new X500NameBuilder(BCStyle.INSTANCE)
                    .addRDN(BCStyle.CN, "certping-test-client").build();
            X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC")
                    .getCertificate(new JcaX509v3CertificateBuilder(
                            subject, BigInteger.ONE,
                            new Date(System.currentTimeMillis() - 3_600_000),
                            new Date(System.currentTimeMillis() + 3_600_000),
                            subject, keyPair.getPublic())
                            .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
                                    .build(keyPair.getPrivate())));

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry("client", keyPair.getPrivate(), PASSWORD.toCharArray(),
                    new Certificate[]{certificate});

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            keyStore.store(out, PASSWORD.toCharArray());
            cached = Base64.getEncoder().encodeToString(out.toByteArray());
            return cached;
        } catch (Exception e) {
            throw new IllegalStateException("could not build a test P12", e);
        }
    }
}
