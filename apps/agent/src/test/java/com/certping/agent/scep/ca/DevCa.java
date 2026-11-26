// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep.ca;

import com.certping.agent.scep.RaIdentity;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/** In-memory CA fixture. It is test-scoped and cannot be packaged in the runtime application. */
final class DevCa {
    private DevCa() {}

    static KeyPair rootKeyPair() {
        return rsa();
    }

    static X509Certificate root(KeyPair ca, String dn) {
        return build(dn, ca.getPublic(), dn, ca.getPrivate(), true, 3650);
    }

    static RaIdentity issueRa(X509Certificate caCert, KeyPair caKeys, String dn) {
        KeyPair ra = rsa();
        X509Certificate raCert = build(dn, ra.getPublic(),
                caCert.getSubjectX500Principal().getName(), caKeys.getPrivate(), false, 1825);
        return new RaIdentity(ra.getPrivate(), raCert, List.of(caCert));
    }

    static X509Certificate sign(
            PKCS10CertificationRequest csr, X509Certificate caCert, PrivateKey caKey) {
        try {
            PublicKey publicKey = new JcaPKCS10CertificationRequest(csr)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).getPublicKey();
            return build(csr.getSubject().toString(), publicKey,
                    caCert.getSubjectX500Principal().getName(), caKey, false, 825);
        } catch (Exception exception) {
            throw new IllegalStateException("test certificate signing failed", exception);
        }
    }

    private static X509Certificate build(String subjectDn, PublicKey subjectKey,
                                         String issuerDn, PrivateKey issuerKey,
                                         boolean ca, int days) {
        try {
            Instant now = Instant.now();
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    new X500Name(issuerDn), BigInteger.valueOf(now.toEpochMilli()),
                    Date.from(now.minus(Duration.ofMinutes(5))),
                    Date.from(now.plus(Duration.ofDays(days))),
                    new X500Name(subjectDn), subjectKey);
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(issuerKey);
            return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(builder.build(signer));
        } catch (Exception exception) {
            throw new IllegalStateException("test CA build failed", exception);
        }
    }

    private static KeyPair rsa() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception exception) {
            throw new IllegalStateException("test key generation failed", exception);
        }
    }
}
