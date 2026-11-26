// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/** Covers the SAN extraction/formatting used to populate the SCEP_CERT_ISSUED message. */
class ScepSanFormattingTest {

    @BeforeAll
    static void provider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void mapsEverySanTagToItsName() {
        assertThat(CertificateSubjectAlternativeNameExtractor.typeName(0)).isEqualTo("otherName");
        assertThat(CertificateSubjectAlternativeNameExtractor.typeName(1)).isEqualTo("rfc822Name");
        assertThat(CertificateSubjectAlternativeNameExtractor.typeName(2)).isEqualTo("dNSName");
        assertThat(CertificateSubjectAlternativeNameExtractor.typeName(3)).isEqualTo("x400Address");
        assertThat(CertificateSubjectAlternativeNameExtractor.typeName(4)).isEqualTo("directoryName");
        assertThat(CertificateSubjectAlternativeNameExtractor.typeName(5)).isEqualTo("ediPartyName");
        assertThat(CertificateSubjectAlternativeNameExtractor.typeName(6))
                .isEqualTo("uniformResourceIdentifier");
        assertThat(CertificateSubjectAlternativeNameExtractor.typeName(7)).isEqualTo("iPAddress");
        assertThat(CertificateSubjectAlternativeNameExtractor.typeName(8)).isEqualTo("registeredID");
        assertThat(CertificateSubjectAlternativeNameExtractor.typeName(99)).isEqualTo("type99");
    }

    @Test
    void extractsMultipleSanTypesFromLeaf() throws Exception {
        GeneralNames sans = new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "device.corp.example"),
                new GeneralName(GeneralName.rfc822Name, "device@corp.example"),
                new GeneralName(GeneralName.uniformResourceIdentifier,
                        "tag:microsoft.com,2022-09-14:sid:S-1-5-21-1"),
                new GeneralName(GeneralName.iPAddress, "10.0.0.7")
        });

        var names = CertificateSubjectAlternativeNameExtractor.extract(certWithSan(sans));

        assertThat(names).anySatisfy(s -> {
            assertThat(s.type()).isEqualTo("dNSName");
            assertThat(s.value()).isEqualTo("device.corp.example");
        });
        assertThat(names).anySatisfy(s -> {
            assertThat(s.type()).isEqualTo("rfc822Name");
            assertThat(s.value()).isEqualTo("device@corp.example");
        });
        assertThat(names).anySatisfy(s -> {
            assertThat(s.type()).isEqualTo("uniformResourceIdentifier");
            assertThat(s.value()).isEqualTo("tag:microsoft.com,2022-09-14:sid:S-1-5-21-1");
        });
        assertThat(names).anySatisfy(s -> assertThat(s.type()).isEqualTo("iPAddress"));
    }

    @Test
    void decodesMicrosoftUpnOtherNameToStableOidAndText() throws Exception {
        GeneralNames sans = new GeneralNames(new GeneralName(GeneralName.otherName,
                new OtherName(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                        new DERUTF8String("user@corp.example"))));

        var names = CertificateSubjectAlternativeNameExtractor.extract(certWithSan(sans));

        assertThat(names).singleElement().satisfies(name -> {
            assertThat(name.type()).isEqualTo("otherName");
            assertThat(name.oid()).isEqualTo("1.3.6.1.4.1.311.20.2.3");
            assertThat(name.value()).isEqualTo("user@corp.example");
            assertThat(name.value()).doesNotStartWith("[B@");
        });
        assertThat(CertificateSubjectAlternativeNameExtractor.extract(certWithSan(sans)))
                .isEqualTo(names);
    }

    @Test
    void returnsEmptyWhenNoSanExtension() throws Exception {
        assertThat(CertificateSubjectAlternativeNameExtractor.extract(certWithSan(null))).isEmpty();
    }

    private static X509Certificate certWithSan(GeneralNames sans) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair keys = g.generateKeyPair();
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name("CN=device"), BigInteger.ONE,
                Date.from(now.minus(Duration.ofMinutes(5))), Date.from(now.plus(Duration.ofDays(1))),
                new X500Name("CN=device"), keys.getPublic());
        if (sans != null) {
            b.addExtension(Extension.subjectAlternativeName, false, sans);
        }
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keys.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(cs));
    }
}
