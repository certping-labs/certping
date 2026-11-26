// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.util;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.util.KeyPairUtils;

import javax.security.auth.x500.X500Principal;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateIdentityUtilsTest {

    @Test
    void normaliseDomain_lowercasesAndStripsTrailingDot() {
        assertThat(CertificateIdentityUtils.normaliseDomain("Example.COM."))
                .isEqualTo("example.com");
    }

    @Test
    void toAzureKvCertificateName_handlesWildcard() {
        assertThat(CertificateIdentityUtils.toAzureKvCertificateName("*.Example.Com"))
                .isEqualTo("wildcard-example-com");
    }

    @Test
    void extractPrimaryDomainFromPem_prefersSan() throws Exception {
        String pem = buildPem("CN=cert.example.com", "api.example.com");
        Optional<String> domain = CertificateIdentityUtils.extractPrimaryDomainFromPem(pem);
        assertThat(domain).contains("api.example.com");
    }

    @Test
    void extractPrimaryDomainFromPem_fallsBackToCn() throws Exception {
        String pem = buildPem("CN=www.example.com", null);
        Optional<String> domain = CertificateIdentityUtils.extractPrimaryDomainFromPem(pem);
        assertThat(domain).contains("www.example.com");
    }

    @Test
    void extractPrimaryDomainFromPem_invalidPem_returnsEmpty() {
        Optional<String> domain = CertificateIdentityUtils.extractPrimaryDomainFromPem("not-a-pem");
        assertThat(domain).isEmpty();
    }

    @Test
    void hostnameMatches_exactMatch() {
        assertThat(CertificateIdentityUtils.hostnameMatches("api.example.com", "api.example.com")).isTrue();
        assertThat(CertificateIdentityUtils.hostnameMatches("API.Example.com.", "api.example.com")).isTrue();
    }

    @Test
    void hostnameMatches_wildcardCoversLiteral() {
        assertThat(CertificateIdentityUtils.hostnameMatches("*.example.com", "api.example.com")).isTrue();
        assertThat(CertificateIdentityUtils.hostnameMatches("api.example.com", "*.example.com")).isTrue();
    }

    @Test
    void hostnameMatches_wildcardOnlyOneLabel() {
        assertThat(CertificateIdentityUtils.hostnameMatches("*.example.com", "shop.api.example.com")).isFalse();
        assertThat(CertificateIdentityUtils.hostnameMatches("*.example.com", "example.com")).isFalse();
    }

    @Test
    void hostnameMatches_unrelated() {
        assertThat(CertificateIdentityUtils.hostnameMatches("api.example.com", "api.other.com")).isFalse();
        assertThat(CertificateIdentityUtils.hostnameMatches("*.example.com", "*.other.com")).isFalse();
    }

    @Test
    void hostnameMatches_blanksReturnFalse() {
        assertThat(CertificateIdentityUtils.hostnameMatches(null, "api.example.com")).isFalse();
        assertThat(CertificateIdentityUtils.hostnameMatches("api.example.com", "")).isFalse();
    }

    // ── normaliseDomain: additional edge branches ─────────────────────────

    @Test
    void normaliseDomain_null_returnsEmpty() {
        assertThat(CertificateIdentityUtils.normaliseDomain(null)).isEmpty();
    }

    @Test
    void normaliseDomain_multipleTrailingDots_stripsAll() {
        assertThat(CertificateIdentityUtils.normaliseDomain("api.example.com...")).isEqualTo("api.example.com");
    }

    @Test
    void normaliseDomain_whitespaceOnly_returnsEmpty() {
        assertThat(CertificateIdentityUtils.normaliseDomain("   ")).isEqualTo("");
    }

    // ── toAzureKvCertificateName: cover every replacement branch ─────────

    @Test
    void toAzureKvCertificateName_bareWildcardWithoutDot_stillWildcardPrefixed() {
        // "*api" (no dot) → wildcard-api
        assertThat(CertificateIdentityUtils.toAzureKvCertificateName("*api"))
                .isEqualTo("wildcard-api");
    }

    @Test
    void toAzureKvCertificateName_blank_returnsEmpty() {
        assertThat(CertificateIdentityUtils.toAzureKvCertificateName("")).isEmpty();
        assertThat(CertificateIdentityUtils.toAzureKvCertificateName(null)).isEmpty();
    }

    @Test
    void toAzureKvCertificateName_underscoresAndSpaces_replacedWithHyphen() {
        assertThat(CertificateIdentityUtils.toAzureKvCertificateName("my_domain com"))
                .isEqualTo("my-domain-com");
    }

    @Test
    void toAzureKvCertificateName_specialCharsDropped() {
        assertThat(CertificateIdentityUtils.toAzureKvCertificateName("api!.example@com"))
                .isEqualTo("api-example-com");
    }

    @Test
    void toAzureKvCertificateName_multipleHyphens_collapsedToOne() {
        assertThat(CertificateIdentityUtils.toAzureKvCertificateName("a..b..c"))
                .isEqualTo("a-b-c");
    }

    @Test
    void toAzureKvCertificateName_leadingTrailingHyphens_stripped() {
        assertThat(CertificateIdentityUtils.toAzureKvCertificateName("...api.example.com..."))
                .isEqualTo("api-example-com");
    }

    @Test
    void toAzureKvCertificateName_over127Chars_truncated() {
        String longName = "a".repeat(200) + ".example.com";
        String result = CertificateIdentityUtils.toAzureKvCertificateName(longName);
        assertThat(result).hasSize(127);
    }

    @Test
    void toAzureKvCertificateName_allSpecialChars_returnsEmpty() {
        // "!!" → "-" after replaceAll — after strip lead/trail → empty
        assertThat(CertificateIdentityUtils.toAzureKvCertificateName("!!!"))
                .isEmpty();
    }

    // ── hostnameMatches: additional wildcard edge branches ────────────────

    @Test
    void hostnameMatches_bothWildcardsExactMatch_returnsTrue() {
        assertThat(CertificateIdentityUtils.hostnameMatches("*.example.com", "*.example.com")).isTrue();
    }

    @Test
    void hostnameMatches_wildcardDoesNotMatchBareDomain() {
        // "*.example.com" does NOT cover "example.com" (no label substituted).
        assertThat(CertificateIdentityUtils.hostnameMatches("*.example.com", "example.com")).isFalse();
    }

    @Test
    void hostnameMatches_bothBlank_returnsFalse() {
        assertThat(CertificateIdentityUtils.hostnameMatches("", "")).isFalse();
        assertThat(CertificateIdentityUtils.hostnameMatches(null, null)).isFalse();
    }

    @Test
    void hostnameMatches_notMatchingSuffix_returnsFalse() {
        assertThat(CertificateIdentityUtils.hostnameMatches("*.example.com", "api.different.com")).isFalse();
    }

    // ── extractAllHostnames ───────────────────────────────────────────────

    @Test
    void extractAllHostnames_withCnAndSans_returnsAllDeduplicated() throws Exception {
        String pem = buildPem("CN=api.example.com", "api.example.com");
        java.util.List<String> hostnames = CertificateIdentityUtils.extractAllHostnames(pem);
        // CN duplicates first SAN — result should be one entry.
        assertThat(hostnames).hasSize(1).containsExactly("api.example.com");
    }

    @Test
    void extractAllHostnames_cnOnlyNoSan_returnsSingle() throws Exception {
        String pem = buildPem("CN=www.example.com", null);
        java.util.List<String> hostnames = CertificateIdentityUtils.extractAllHostnames(pem);
        assertThat(hostnames).containsExactly("www.example.com");
    }

    @Test
    void extractAllHostnames_invalidPem_returnsEmpty() {
        assertThat(CertificateIdentityUtils.extractAllHostnames("bad")).isEmpty();
    }

    @Test
    void extractPrimaryDomainFromPem_emptyPem_returnsEmpty() {
        assertThat(CertificateIdentityUtils.extractPrimaryDomainFromPem("")).isEmpty();
        assertThat(CertificateIdentityUtils.extractPrimaryDomainFromPem(null)).isEmpty();
    }

    private String buildPem(String subjectDn, String dnsSan) throws Exception {
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
        X500Principal subject = new X500Principal(subjectDn);
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);

        var builder = new JcaX509v3CertificateBuilder(
                subject,
                java.math.BigInteger.valueOf(System.currentTimeMillis()),
                notBefore,
                notAfter,
                subject,
                keyPair.getPublic());

        if (dnsSan != null) {
            GeneralNames sans = new GeneralNames(new GeneralName(GeneralName.dNSName, dnsSan));
            builder.addExtension(Extension.subjectAlternativeName, false, sans);
        }

        var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));

        String certB64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + certB64 + "\n-----END CERTIFICATE-----";
    }
}
