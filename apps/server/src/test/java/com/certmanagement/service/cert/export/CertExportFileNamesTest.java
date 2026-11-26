// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;

import static com.certmanagement.service.cert.export.CertExportTestMaterial.EC_LEAF_KEYS;

import static org.assertj.core.api.Assertions.assertThat;

class CertExportFileNamesTest {

    @Test
    void wildcardBecomesUnderscoreWildcard() {
        assertThat(CertExportFileNames.fileName("*.example.com", CertExportFormat.PKCS12))
                .isEqualTo("_wildcard.example.com.pfx");
        assertThat(CertExportFileNames.fileName("*.example.com", CertExportFormat.FULLCHAIN_PEM))
                .isEqualTo("_wildcard.example.com-fullchain.pem");
    }

    @Test
    void eachFormatHasItsContractSuffix() {
        assertThat(CertExportFileNames.fileName("example.com", CertExportFormat.CERTIFICATE_PEM))
                .isEqualTo("example.com-cert.pem");
        assertThat(CertExportFileNames.fileName("example.com", CertExportFormat.PRIVATE_KEY_PEM))
                .isEqualTo("example.com-privkey.pem");
        assertThat(CertExportFileNames.fileName("example.com", CertExportFormat.CERTIFICATE_DER))
                .isEqualTo("example.com-cert.der");
        assertThat(CertExportFileNames.fileName("example.com", CertExportFormat.PKCS7))
                .isEqualTo("example.com-chain.p7b");
    }

    @Test
    void onlySafeCharactersSurvive() {
        assertThat(CertExportFileNames.safeCommonName("Ex\"ample;\r\nX-Bad: 1/../é.COM"))
                .matches("[a-z0-9._-]+")
                .startsWith("ex-ample")
                .endsWith(".com")
                .doesNotContain("..");
        assertThat(CertExportFileNames.safeCommonName("../../etc/passwd")).doesNotContain("..").doesNotStartWith(".");
    }

    @Test
    void blankOrUnusableNamesFallBack() {
        assertThat(CertExportFileNames.safeCommonName(null)).isEqualTo("certificate");
        assertThat(CertExportFileNames.safeCommonName("  ")).isEqualTo("certificate");
        assertThat(CertExportFileNames.safeCommonName("...")).isEqualTo("certificate");
    }

    @Test
    void stemComesFromTheLeafCommonName_elseTheWildcardAwareDomain() throws Exception {
        X509Certificate wildcardLeaf = CertExportTestMaterial.chainFor("*.Example.com", EC_LEAF_KEYS).leaf();
        assertThat(CertExportFileNames.stemFor(wildcardLeaf, "ignored.com", false)).isEqualTo("_wildcard.example.com");

        X500Name noCnName = new X500Name("O=No CN");
        X509Certificate noCn = new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(
                noCnName, BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + 86_400_000L), noCnName,
                EC_LEAF_KEYS.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(EC_LEAF_KEYS.getPrivate())));
        assertThat(CertExportFileNames.stemFor(noCn, "example.com", true)).isEqualTo("_wildcard.example.com");
        assertThat(CertExportFileNames.stemFor(noCn, "example.com", false)).isEqualTo("example.com");
    }

    @Test
    void longNamesAreBounded() {
        assertThat(CertExportFileNames.safeCommonName("a".repeat(300) + ".com"))
                .hasSizeLessThanOrEqualTo(CertExportFileNames.MAX_STEM_LENGTH);
    }
}
