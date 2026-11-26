// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1Secret;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KubernetesCertificateParserTest {

    private static X509Certificate issuerCertificate;
    private static X509Certificate leafCertificate;

    private final KubernetesCertificateParser parser = new KubernetesCertificateParser();

    @BeforeAll
    static void buildCertificateChain() throws Exception {
        KeyPair issuerKeyPair = keyPair();
        X500Name issuerName = new X500Name("CN=Test Intermediate CA");
        issuerCertificate = certificate(
                issuerName,
                issuerName,
                issuerKeyPair,
                issuerKeyPair,
                BigInteger.ONE,
                true,
                null);

        KeyPair leafKeyPair = keyPair();
        leafCertificate = certificate(
                issuerName,
                new X500Name("CN=api.example.test"),
                leafKeyPair,
                issuerKeyPair,
                BigInteger.TWO,
                false,
                "api.example.test");
    }

    @Test
    void parseTlsSecrets_chainPresentedIssuerFirst_selectsLeafCertificate() throws Exception {
        String issuerFirstBundle = pem(issuerCertificate) + pem(leafCertificate);
        V1Secret secret = tlsSecret(issuerFirstBundle.getBytes(StandardCharsets.US_ASCII));

        List<KubernetesParsedCertificate> parsed = parser.parseTlsSecrets("prod", List.of(secret));

        assertThat(parsed).singleElement().satisfies(certificate -> {
            assertThat(certificate.certificate().getSerialNumber()).isEqualTo(BigInteger.TWO);
            KubernetesCertificateMetadata metadata = parser.metadataFor(certificate.certificate());
            assertThat(metadata.domain()).isEqualTo("api.example.test");
            assertThat(metadata.sanDomains()).containsExactly("api.example.test");
            assertThat(metadata.certStatus()).isEqualTo("ISSUED");
        });
    }

    @Test
    void parseTlsSecrets_derEncodedCertificate_parsesDecodedSecretBytesDirectly() throws Exception {
        V1Secret secret = tlsSecret(leafCertificate.getEncoded());

        List<KubernetesParsedCertificate> parsed = parser.parseTlsSecrets("prod", List.of(secret));

        assertThat(parsed).singleElement().satisfies(certificate ->
                assertThat(certificate.certificate().getSerialNumber()).isEqualTo(BigInteger.TWO));
    }

    @Test
    void parseTlsSecrets_oversizedCertificateInput_isSkippedSafely() {
        V1Secret secret = tlsSecret(new byte[(1024 * 1024) + 1]);

        List<KubernetesParsedCertificate> parsed = parser.parseTlsSecrets("prod", List.of(secret));

        assertThat(parsed).isEmpty();
    }

    @Test
    void parseTlsSecrets_missingTlsCrt_isSkippedWithWarning() {
        V1Secret secret = new V1Secret()
                .metadata(new V1ObjectMeta().namespace("ns").name("missing-crt"))
                .type("kubernetes.io/tls")
                .data(Map.of("other.key", new byte[] {1, 2, 3}));

        List<KubernetesParsedCertificate> parsed = parser.parseTlsSecrets("prod", List.of(secret));

        assertThat(parsed).isEmpty();
    }

    @Test
    void parseTlsSecrets_emptyTlsCrt_isSkipped() {
        V1Secret secret = new V1Secret()
                .metadata(new V1ObjectMeta().namespace("ns").name("empty-crt"))
                .type("kubernetes.io/tls")
                .data(Map.of("tls.crt", new byte[0]));

        List<KubernetesParsedCertificate> parsed = parser.parseTlsSecrets("prod", List.of(secret));

        assertThat(parsed).isEmpty();
    }

    @Test
    void parseTlsSecrets_nullDataField_isSkipped() {
        V1Secret secret = new V1Secret()
                .metadata(new V1ObjectMeta().namespace("ns").name("null-data"))
                .type("kubernetes.io/tls");
        // .data() left null

        List<KubernetesParsedCertificate> parsed = parser.parseTlsSecrets("prod", List.of(secret));

        assertThat(parsed).isEmpty();
    }

    @Test
    void parseTlsSecrets_unparsableBytes_isSkipped() {
        V1Secret secret = tlsSecret("this is definitely not a certificate".getBytes(StandardCharsets.US_ASCII));

        List<KubernetesParsedCertificate> parsed = parser.parseTlsSecrets("prod", List.of(secret));

        assertThat(parsed).isEmpty();
    }

    @Test
    void parseTlsSecrets_secretMetadataMissing_stillHandled() throws Exception {
        // metadata is null on the secret — parser must not NPE on namespace/name lookup.
        V1Secret secret = new V1Secret()
                .type("kubernetes.io/tls")
                .data(Map.of("tls.crt", "garbage".getBytes(StandardCharsets.US_ASCII)));

        List<KubernetesParsedCertificate> parsed = parser.parseTlsSecrets("prod", List.of(secret));

        assertThat(parsed).isEmpty();
    }

    @Test
    void parseTlsSecrets_multipleSecretsSorted_byNamespaceThenName() throws Exception {
        String bundle = pem(leafCertificate);
        V1Secret secretB = new V1Secret()
                .metadata(new V1ObjectMeta().namespace("z-ns").name("a"))
                .type("kubernetes.io/tls")
                .data(Map.of("tls.crt", bundle.getBytes(StandardCharsets.US_ASCII)));
        V1Secret secretA = new V1Secret()
                .metadata(new V1ObjectMeta().namespace("a-ns").name("z"))
                .type("kubernetes.io/tls")
                .data(Map.of("tls.crt", bundle.getBytes(StandardCharsets.US_ASCII)));

        List<KubernetesParsedCertificate> parsed = parser.parseTlsSecrets("prod", List.of(secretB, secretA));

        assertThat(parsed).hasSize(2);
        // Sorted by namespace then name — a-ns first.
        assertThat(parsed.get(0).namespace()).isEqualTo("a-ns");
        assertThat(parsed.get(1).namespace()).isEqualTo("z-ns");
    }

    @Test
    void parseInlineCustomResourceCertificate_null_returnsNull() {
        assertThat(parser.parseInlineCustomResourceCertificate(
                "prod", "v1", "Kind", "ns", "n", "u", "rv", "spec.tls.certificate", null)).isNull();
    }

    @Test
    void parseInlineCustomResourceCertificate_blank_returnsNull() {
        assertThat(parser.parseInlineCustomResourceCertificate(
                "prod", "v1", "Kind", "ns", "n", "u", "rv", "spec.tls.certificate", "  ")).isNull();
    }

    @Test
    void parseInlineCustomResourceCertificate_validPem_returnsCert() throws Exception {
        String pemString = pem(leafCertificate);
        KubernetesParsedCertificate parsed = parser.parseInlineCustomResourceCertificate(
                "prod", "gateway.networking.k8s.io/v1", "HTTPRoute", "ns", "route1",
                "uid-1", "rv-99", "spec.tls.certificate", pemString);

        assertThat(parsed).isNotNull();
        assertThat(parsed.certificate().getSerialNumber()).isEqualTo(BigInteger.TWO);
    }

    @Test
    void parseInlineCustomResourceCertificate_unparsable_returnsNull() {
        KubernetesParsedCertificate parsed = parser.parseInlineCustomResourceCertificate(
                "prod", "v1", "Kind", "ns", "n", "u", "rv", "spec.tls.certificate",
                "not-a-certificate");
        assertThat(parsed).isNull();
    }

    @Test
    void metadataFor_certificateWithSans_domainIsFirstSan() {
        KubernetesCertificateMetadata metadata = parser.metadataFor(leafCertificate);
        assertThat(metadata.domain()).isEqualTo("api.example.test");
        assertThat(metadata.sanDomains()).contains("api.example.test");
        assertThat(metadata.issuer()).contains("Test Intermediate CA");
        assertThat(metadata.serialNumber()).isNotBlank();
        assertThat(metadata.notBefore()).isNotBlank();
        assertThat(metadata.notAfter()).isNotBlank();
    }

    @Test
    void parseTlsSecrets_nonTlsSecret_isIgnored() {
        V1Secret secret = new V1Secret()
                .metadata(new V1ObjectMeta().namespace("frontend").name("opaque"))
                .type("Opaque")
                .data(Map.of("tls.crt", new byte[] {1, 2, 3}));

        assertThat(parser.parseTlsSecrets("prod", List.of(secret))).isEmpty();
    }

    private static V1Secret tlsSecret(byte[] certificateBytes) {
        return new V1Secret()
                .metadata(new V1ObjectMeta()
                        .namespace("frontend")
                        .name("api-tls")
                        .uid("secret-uid")
                        .resourceVersion("42"))
                .type("kubernetes.io/tls")
                .data(Map.of("tls.crt", certificateBytes));
    }

    private static KeyPair keyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509Certificate certificate(
            X500Name issuer,
            X500Name subject,
            KeyPair subjectKeyPair,
            KeyPair signingKeyPair,
            BigInteger serial,
            boolean certificateAuthority,
            String dnsName) throws Exception {
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(30, ChronoUnit.DAYS)),
                subject,
                subjectKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(certificateAuthority));
        if (dnsName != null) {
            builder.addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, dnsName)));
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(signingKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static String pem(X509Certificate certificate) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }
}
