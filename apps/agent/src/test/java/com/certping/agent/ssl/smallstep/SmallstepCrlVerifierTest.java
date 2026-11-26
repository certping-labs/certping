// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.smallstep;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SmallstepCrlVerifierTest {
    private static final Instant NOW = Instant.parse("2026-09-01T00:00:00Z");

    @BeforeAll
    static void addProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void validSignedCrlConfirmsTheExactSerial() throws Exception {
        Authority authority = authority();
        X509CRL crl = crl(authority, NOW.minusSeconds(30), NOW.plusSeconds(3600),
                BigInteger.valueOf(0xabc));

        SmallstepCrlVerifier.Status status = SmallstepCrlVerifier.status(
                SmallstepCrlVerifier.parse(crl.getEncoded()),
                authority.intermediate().getSubjectX500Principal().getName(),
                BigInteger.valueOf(0xabc), authority.intermediate(), NOW);

        assertThat(status.revoked()).isTrue();
        assertThat(status.reason()).isEqualTo("KEY_COMPROMISE");
    }

    @Test
    void validSignedCrlAllowsASerialThatIsNotListed() throws Exception {
        Authority authority = authority();
        X509CRL crl = crl(authority, NOW.minusSeconds(30), NOW.plusSeconds(3600),
                BigInteger.valueOf(0xabc));

        SmallstepCrlVerifier.Status status = SmallstepCrlVerifier.status(crl,
                authority.intermediate().getSubjectX500Principal().getName(),
                BigInteger.valueOf(0xdef), authority.intermediate(), NOW);

        assertThat(status.revoked()).isFalse();
    }

    @Test
    void expiredCrlFailsClosed() throws Exception {
        Authority authority = authority();
        X509CRL crl = crl(authority, NOW.minusSeconds(3600), NOW, BigInteger.ONE);

        assertThatThrownBy(() -> SmallstepCrlVerifier.status(crl,
                authority.intermediate().getSubjectX500Principal().getName(),
                BigInteger.ONE, authority.intermediate(), NOW))
                .isInstanceOfSatisfying(TransientAgentException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo("SMALLSTEP_CRL_STALE"));
    }

    @Test
    void crlSignedByAnotherKeyIsRejected() throws Exception {
        Authority expected = authority();
        Authority attacker = authority();
        X509CRL crl = crl(attacker, NOW.minusSeconds(30), NOW.plusSeconds(3600), BigInteger.ONE);

        assertThatThrownBy(() -> SmallstepCrlVerifier.status(crl,
                crl.getIssuerX500Principal().getName(), BigInteger.ONE,
                expected.intermediate(), NOW))
                .isInstanceOfSatisfying(PermanentAgentException.class, exception ->
                        assertThat(exception.getErrorCode())
                                .isEqualTo("SMALLSTEP_CRL_SIGNATURE_INVALID"));
    }

    @Test
    void invalidRotatedIntermediateDoesNotHideALaterTrustedIntermediate() throws Exception {
        Authority trusted = authority();
        Authority untrusted = authority();
        ObjectMapper mapper = JsonMapper.builderWithJackson2Defaults().build();

        List<X509Certificate> intermediates = SmallstepCrlVerifier.trustedIntermediates(
                pem(trusted.root()), mapper.valueToTree(List.of(
                        pem(untrusted.intermediate()), pem(trusted.intermediate()))));

        assertThat(intermediates).containsExactly(trusted.intermediate());
    }

    private static Authority authority() throws Exception {
        KeyPair rootKey = keyPair();
        X509Certificate root = certificate(
                "CN=Smallstep Root", "CN=Smallstep Root", rootKey, rootKey, BigInteger.ONE);
        KeyPair intermediateKey = keyPair();
        X509Certificate intermediate = certificate(
                "CN=Smallstep Root", "CN=Smallstep Intermediate", rootKey,
                intermediateKey, BigInteger.TWO);
        return new Authority(root, rootKey, intermediate, intermediateKey);
    }

    private static X509Certificate certificate(
            String issuer, String subject, KeyPair issuerKey, KeyPair subjectKey,
            BigInteger serial) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(issuer), serial, Date.from(NOW.minusSeconds(86400)),
                Date.from(NOW.plusSeconds(86400)), new X500Name(subject),
                subjectKey.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
                        .build(issuerKey.getPrivate())));
    }

    private static X509CRL crl(
            Authority authority, Instant thisUpdate, Instant nextUpdate,
            BigInteger revokedSerial) throws Exception {
        JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(
                authority.intermediate().getSubjectX500Principal(), Date.from(thisUpdate));
        builder.setNextUpdate(Date.from(nextUpdate));
        builder.addCRLEntry(revokedSerial, Date.from(thisUpdate), CRLReason.keyCompromise);
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

    private record Authority(X509Certificate root, KeyPair rootKey,
                             X509Certificate intermediate, KeyPair intermediateKey) {}
}
