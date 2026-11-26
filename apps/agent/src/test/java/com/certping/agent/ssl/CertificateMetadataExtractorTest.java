// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.util.KeyPairUtils;

import javax.security.auth.x500.X500Principal;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateMetadataExtractorTest {

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void fromLeaf_nullLeaf_returnsNullFields() {
        CertificateMetadata meta = CertificateMetadataExtractor.fromLeaf(null);
        assertThat(meta.signatureAlgorithm()).isNull();
        assertThat(meta.publicKeyAlgorithm()).isNull();
        assertThat(meta.keySize()).isNull();
    }

    @Test
    void fromLeaf_rsaLeaf_extractsMetadata() throws Exception {
        X509Certificate cert = buildSelfSignedRsa();

        CertificateMetadata meta = CertificateMetadataExtractor.fromLeaf(cert);

        assertThat(meta.signatureAlgorithm()).isNotBlank();
        assertThat(meta.publicKeyAlgorithm()).isEqualTo("RSA");
        assertThat(meta.keySize()).isNotNull();
        assertThat(meta.keySize()).isGreaterThanOrEqualTo(2048);
    }

    // ── null-guarded getters ──────────────────────────────────────────────

    @Test
    void getSignatureAlgorithmOid_nullCert_returnsNull() {
        assertThat(CertificateMetadataExtractor.getSignatureAlgorithmOid(null)).isNull();
    }

    @Test
    void getSubjectDn_nullCert_returnsNull() {
        assertThat(CertificateMetadataExtractor.getSubjectDn(null)).isNull();
    }

    @Test
    void getCommonName_nullCert_returnsNull() {
        assertThat(CertificateMetadataExtractor.getCommonName(null)).isNull();
    }

    @Test
    void getKeyUsage_nullCert_returnsNull() {
        assertThat(CertificateMetadataExtractor.getKeyUsage(null)).isNull();
    }

    @Test
    void getPublicKeyCurve_nullCert_returnsNull() {
        assertThat(CertificateMetadataExtractor.getPublicKeyCurve(null)).isNull();
    }

    @Test
    void getExtendedKeyUsage_nullCert_returnsNull() {
        assertThat(CertificateMetadataExtractor.getExtendedKeyUsage(null)).isNull();
    }

    @Test
    void getSubjectKeyIdentifier_nullCert_returnsNull() {
        assertThat(CertificateMetadataExtractor.getSubjectKeyIdentifier(null)).isNull();
    }

    @Test
    void getAuthorityKeyIdentifier_nullCert_returnsNull() {
        assertThat(CertificateMetadataExtractor.getAuthorityKeyIdentifier(null)).isNull();
    }

    // ── common name extraction from DN ────────────────────────────────────

    @Test
    void getCommonName_multiComponentDn_extractsCn() throws Exception {
        X509Certificate cert = buildRsa("CN=cn.example.com,O=Acme,C=US");
        assertThat(CertificateMetadataExtractor.getCommonName(cert)).isEqualTo("cn.example.com");
    }

    @Test
    void getCommonName_noCnInDn_returnsNull() throws Exception {
        X509Certificate cert = buildRsa("O=Acme,C=US");
        assertThat(CertificateMetadataExtractor.getCommonName(cert)).isNull();
    }

    // ── ECC key handling: curve + key size ────────────────────────────────

    @Test
    void fromLeaf_eccLeaf_curveAndKeySizePopulated() throws Exception {
        X509Certificate cert = buildEc();
        CertificateMetadata meta = CertificateMetadataExtractor.fromLeaf(cert);
        assertThat(meta.publicKeyAlgorithm()).isEqualTo("EC");
        assertThat(meta.publicKeyCurve()).isEqualTo("1.2.840.10045.3.1.7");
        assertThat(meta.keySize()).isNotNull();
    }

    @Test
    void getPublicKeyCurve_isStableAcrossJcaProviders() throws Exception {
        X509Certificate original = buildEc();
        byte[] encoded = original.getEncoded();
        X509Certificate defaultParsed = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(encoded));
        X509Certificate bcParsed = (X509Certificate) CertificateFactory.getInstance("X.509", "BC")
                .generateCertificate(new ByteArrayInputStream(encoded));

        assertThat(CertificateMetadataExtractor.getPublicKeyCurve(defaultParsed))
                .isEqualTo("1.2.840.10045.3.1.7")
                .isEqualTo(CertificateMetadataExtractor.getPublicKeyCurve(bcParsed));
        assertThat(CertificateMetadataExtractor.getPublicKeyCurve(defaultParsed)).doesNotContain("@");
    }

    @Test
    void getPublicKeyCurve_rsaCert_returnsNull() throws Exception {
        X509Certificate cert = buildSelfSignedRsa();
        assertThat(CertificateMetadataExtractor.getPublicKeyCurve(cert)).isNull();
    }

    // ── key usage formatting ──────────────────────────────────────────────

    @Test
    void getKeyUsage_certWithDigitalSignatureAndKeyEncipherment_returnsCommaSeparated() throws Exception {
        X509Certificate cert = buildRsaWithKeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
        String kuText = CertificateMetadataExtractor.getKeyUsage(cert);
        assertThat(kuText).contains("digitalSignature").contains("keyEncipherment");
    }

    @Test
    void getKeyUsage_certWithoutKeyUsageExtension_returnsNull() throws Exception {
        X509Certificate cert = buildSelfSignedRsa();  // no KU extension
        assertThat(CertificateMetadataExtractor.getKeyUsage(cert)).isNull();
    }

    @Test
    void getKeyUsage_certWithAllBits_returnsAllNames() throws Exception {
        // Exercises every branch of formatKeyUsage
        int allBits = KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment
                | KeyUsage.dataEncipherment | KeyUsage.keyAgreement | KeyUsage.keyCertSign
                | KeyUsage.cRLSign | KeyUsage.encipherOnly | KeyUsage.decipherOnly;
        X509Certificate cert = buildRsaWithKeyUsage(allBits);
        String kuText = CertificateMetadataExtractor.getKeyUsage(cert);
        assertThat(kuText)
                .contains("digitalSignature")
                .contains("nonRepudiation")
                .contains("keyEncipherment")
                .contains("dataEncipherment")
                .contains("keyAgreement")
                .contains("keyCertSign")
                .contains("cRLSign")
                .contains("encipherOnly")
                .contains("decipherOnly");
    }

    // ── extended key usage ───────────────────────────────────────────────

    @Test
    void getExtendedKeyUsage_certWithServerAndClientAuth_returnsCommaSeparated() throws Exception {
        X509Certificate cert = buildRsaWithExtendedKeyUsage();
        String eku = CertificateMetadataExtractor.getExtendedKeyUsage(cert);
        assertThat(eku).isNotBlank();
    }

    @Test
    void getExtendedKeyUsage_certWithoutEkuExtension_returnsNull() throws Exception {
        X509Certificate cert = buildSelfSignedRsa();
        assertThat(CertificateMetadataExtractor.getExtendedKeyUsage(cert)).isNull();
    }

    // ── subject / authority key identifier ───────────────────────────────

    @Test
    void getSubjectKeyIdentifier_certWithSkiExtension_returnsHex() throws Exception {
        X509Certificate cert = buildRsaWithSki();
        String ski = CertificateMetadataExtractor.getSubjectKeyIdentifier(cert);
        assertThat(ski).isNotBlank().contains(":");
    }

    @Test
    void getSubjectKeyIdentifier_certWithoutSki_returnsNull() throws Exception {
        X509Certificate cert = buildSelfSignedRsa();
        assertThat(CertificateMetadataExtractor.getSubjectKeyIdentifier(cert)).isNull();
    }

    @Test
    void getAuthorityKeyIdentifier_certWithoutAki_returnsNull() throws Exception {
        X509Certificate cert = buildSelfSignedRsa();
        assertThat(CertificateMetadataExtractor.getAuthorityKeyIdentifier(cert)).isNull();
    }

    @Test
    void firstCertificate_readsTheLeafOfABundleWithItsKey() throws Exception {
        X509Certificate leaf = buildSelfSignedRsa();
        String bundle = pem(leaf) + pem(buildEc()) + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";

        assertThat(CertificateMetadataExtractor.firstCertificate(bundle)).isEqualTo(leaf);
    }

    @Test
    void firstCertificate_aBundleWithoutACertificateIsRefused() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> CertificateMetadataExtractor.firstCertificate(
                        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))
                .isInstanceOf(java.security.cert.CertificateException.class);
    }

    @Test
    void sha256Fingerprint_isColonSeparatedUpperCaseHexOfTheDerEncoding() throws Exception {
        X509Certificate cert = buildSelfSignedRsa();
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());

        assertThat(CertificateMetadataExtractor.sha256Fingerprint(cert))
                .isEqualTo(java.util.HexFormat.of().withUpperCase().withDelimiter(":").formatHex(digest))
                .matches("([0-9A-F]{2}:){31}[0-9A-F]{2}");
    }

    private static String pem(X509Certificate cert) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    // ── helpers ────────────────────────────────────────────────────────────

    private X509Certificate buildRsa(String dn) throws Exception {
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
        X500Principal subject = new X500Principal(dn);
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);
        var builder = new JcaX509v3CertificateBuilder(subject,
                java.math.BigInteger.valueOf(System.currentTimeMillis()),
                notBefore, notAfter, subject, keyPair.getPublic());
        var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private X509Certificate buildEc() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = kpg.generateKeyPair();
        X500Principal subject = new X500Principal("CN=ec.example.com");
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);
        var builder = new JcaX509v3CertificateBuilder(subject,
                java.math.BigInteger.valueOf(System.currentTimeMillis()),
                notBefore, notAfter, subject, keyPair.getPublic());
        var signer = new JcaContentSignerBuilder("SHA256WithECDSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private X509Certificate buildRsaWithKeyUsage(int keyUsageBits) throws Exception {
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
        X500Principal subject = new X500Principal("CN=ku.example.com");
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);
        var builder = new JcaX509v3CertificateBuilder(subject,
                java.math.BigInteger.valueOf(System.currentTimeMillis()),
                notBefore, notAfter, subject, keyPair.getPublic());
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageBits));
        var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private X509Certificate buildRsaWithExtendedKeyUsage() throws Exception {
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
        X500Principal subject = new X500Principal("CN=eku.example.com");
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);
        var builder = new JcaX509v3CertificateBuilder(subject,
                java.math.BigInteger.valueOf(System.currentTimeMillis()),
                notBefore, notAfter, subject, keyPair.getPublic());
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(new KeyPurposeId[]{
                        KeyPurposeId.id_kp_serverAuth,
                        KeyPurposeId.id_kp_clientAuth}));
        var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private X509Certificate buildRsaWithSki() throws Exception {
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
        X500Principal subject = new X500Principal("CN=ski.example.com");
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);
        var builder = new JcaX509v3CertificateBuilder(subject,
                java.math.BigInteger.valueOf(System.currentTimeMillis()),
                notBefore, notAfter, subject, keyPair.getPublic());
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        SubjectKeyIdentifier ski = extUtils.createSubjectKeyIdentifier(keyPair.getPublic());
        builder.addExtension(Extension.subjectKeyIdentifier, false, ski);
        var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private X509Certificate buildSelfSignedRsa() throws Exception {
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
        X500Principal subject = new X500Principal("CN=meta.example.com");
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);

        var builder = new JcaX509v3CertificateBuilder(
                subject,
                java.math.BigInteger.valueOf(System.currentTimeMillis()),
                notBefore,
                notAfter,
                subject,
                keyPair.getPublic());

        var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    @Test
    void fromLeaf_readsTheAuthorityKeyIdentifierPoliciesAndCaFlag() throws Exception {
        KeyPair issuerKeys = KeyPairUtils.createKeyPair(2048);
        KeyPair subjectKeys = KeyPairUtils.createKeyPair(2048);
        var builder = new JcaX509v3CertificateBuilder(new X500Principal("CN=issuer.example.com"),
                java.math.BigInteger.TEN, new Date(), new Date(System.currentTimeMillis() + 86_400_000L),
                new X500Principal("CN=ca.example.com"), subjectKeys.getPublic());
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(issuerKeys.getPublic()));
        builder.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(
                new PolicyInformation(new ASN1ObjectIdentifier("2.23.140.1.2.1"))));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256WithRSA").build(issuerKeys.getPrivate())));

        CertificateMetadata meta = CertificateMetadataExtractor.fromLeaf(cert);

        assertThat(meta.authorityKeyIdentifier()).matches("([0-9a-f]{2}:)+[0-9a-f]{2}");
        assertThat(meta.certificatePolicyOids()).containsExactly("2.23.140.1.2.1");
        assertThat(meta.certificateAuthority()).isTrue();
    }

    @Test
    void fromLeaf_dsaLeaf_reportsTheKeySize() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        X500Principal subject = new X500Principal("CN=dsa.example.com");
        var builder = new JcaX509v3CertificateBuilder(subject, java.math.BigInteger.ONE, new Date(),
                new Date(System.currentTimeMillis() + 86_400_000L), subject, keyPair.getPublic());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withDSA").build(keyPair.getPrivate())));

        CertificateMetadata meta = CertificateMetadataExtractor.fromLeaf(cert);

        assertThat(meta.publicKeyAlgorithm()).isEqualTo("DSA");
        assertThat(meta.keySize()).isEqualTo(2048);
        assertThat(meta.certificatePolicyOids()).isEmpty();
        assertThat(meta.certificateAuthority()).isFalse();
    }

}
