// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.util;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.exception.PermanentAgentException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.util.KeyPairUtils;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PemPfxUtilsTest {

    private static String CERT_PEM;
    private static String PRIVATE_KEY_PEM;

    @BeforeAll
    static void setUpFixtures() throws Exception {
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048);

        X500Principal subject = new X500Principal("CN=pfx-test.example.com");
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);
        var certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.currentTimeMillis()),
                notBefore,
                notAfter,
                subject,
                keyPair.getPublic());
        var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

        String certB64 = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(cert.getEncoded());
        CERT_PEM = "-----BEGIN CERTIFICATE-----\n" + certB64 + "\n-----END CERTIFICATE-----\n";

        StringWriter keyWriter = new StringWriter();
        KeyPairUtils.writeKeyPair(keyPair, keyWriter);
        PRIVATE_KEY_PEM = keyWriter.toString();
    }

    @Test
    void toPkcs12Bytes_validBundle_createsLoadablePkcs12() throws Exception {
        CertificateBundle bundle = new CertificateBundle(PRIVATE_KEY_PEM, CERT_PEM, "", CERT_PEM);

        byte[] pfx = PemPfxUtils.toPkcs12Bytes(bundle, "changeit");

        assertThat(pfx).isNotEmpty();

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new ByteArrayInputStream(pfx), "changeit".toCharArray());

        assertThat(keyStore.containsAlias("certping")).isTrue();
    }

    @Test
    void toPkcs12Bytes_blankPrivateKey_throwsPermanentException() {
        CertificateBundle bundle = new CertificateBundle("   ", CERT_PEM, "", CERT_PEM);

        assertThatThrownBy(() -> PemPfxUtils.toPkcs12Bytes(bundle, "changeit"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("CERT_FORMAT_INVALID"));
    }

    @Test
    void toPkcs12Bytes_blankCertificateChain_throwsPermanentException() {
        CertificateBundle bundle = new CertificateBundle(PRIVATE_KEY_PEM, CERT_PEM, "", "   ");

        assertThatThrownBy(() -> PemPfxUtils.toPkcs12Bytes(bundle, "changeit"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("CERT_FORMAT_INVALID"));
    }

    @Test
    void toPkcs12Bytes_malformedCertificateChain_wrapsFailure() {
        CertificateBundle bundle = new CertificateBundle(PRIVATE_KEY_PEM, CERT_PEM, "", "not-a-certificate");

        assertThatThrownBy(() -> PemPfxUtils.toPkcs12Bytes(bundle, "changeit"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("CERT_PFX_BUILD_FAILED"));
    }
}