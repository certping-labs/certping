// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import com.certmanagement.dto.cert.CertExportRequest;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagFactory;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import static com.certmanagement.service.cert.export.CertExportTestMaterial.EC_LEAF_KEYS;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.RSA_LEAF_KEYS;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.agentBundle;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.chainFor;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.pem;
import static com.certmanagement.service.cert.export.KeyMaterialAssertions.assertNamedCurvePkcs8;
import static com.certmanagement.service.cert.export.KeyMaterialAssertions.assertSameKeyMaterial;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertExportFileRendererTest {

    private static final String PASSWORD = "correct horse 9";
    private static final String ALIAS = "_wildcard.example.com";
    private static final CertExportTestMaterial.Chain RSA_CHAIN = chainFor("*.example.com", RSA_LEAF_KEYS);
    private static final CertExportTestMaterial.Chain EC_CHAIN = chainFor("ec.example.com", EC_LEAF_KEYS);

    @AcrossSecurityProviderModes
    void fullChainPem_isLeafThenIntermediate() throws Exception {
        String out = render(RSA_CHAIN, "FULLCHAIN_PEM", false);

        assertThat(out).isEqualTo(pem(RSA_CHAIN.leaf()) + pem(RSA_CHAIN.intermediate()));
        assertThat(out).doesNotContain("PRIVATE KEY");
    }

    @AcrossSecurityProviderModes
    void certificatePem_isLeafOnly() throws Exception {
        assertThat(render(RSA_CHAIN, "CERTIFICATE_PEM", false)).isEqualTo(pem(RSA_CHAIN.leaf()));
    }

    @AcrossSecurityProviderModes
    void certificateDer_isTheLeafEncoding() throws Exception {
        byte[] der = renderBytes(RSA_CHAIN, "CERTIFICATE_DER", false);

        assertThat(der).isEqualTo(RSA_CHAIN.leaf().getEncoded());
        assertThat(java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(der))).isEqualTo(RSA_CHAIN.leaf());
    }

    @AcrossSecurityProviderModes
    void pkcs7_holdsTheWholeChainAndNoKey() throws Exception {
        byte[] p7b = renderBytes(RSA_CHAIN, "PKCS7", false);

        java.util.List<java.security.cert.Certificate> certificates = new java.util.ArrayList<>(
                java.security.cert.CertificateFactory.getInstance("X.509")
                        .generateCertificates(new java.io.ByteArrayInputStream(p7b)));
        assertThat(certificates).containsExactlyInAnyOrder(RSA_CHAIN.leaf(), RSA_CHAIN.intermediate());
        assertThat(new String(p7b, StandardCharsets.ISO_8859_1)).doesNotContain("PRIVATE KEY");
    }

    @AcrossSecurityProviderModes
    void privateKeyPem_convertsTraditionalRsaKeyToPkcs8() throws Exception {
        String out = render(RSA_CHAIN, "PRIVATE_KEY_PEM", false);

        assertThat(out).startsWith("-----BEGIN PRIVATE KEY-----\n").endsWith("-----END PRIVATE KEY-----\n")
                .doesNotContain("RSA PRIVATE KEY");
        assertSameKeyMaterial(readWithJdk(out, "RSA"), RSA_LEAF_KEYS.getPrivate());
    }

    @AcrossSecurityProviderModes
    void privateKeyPem_convertsTraditionalEcKeyToPkcs8() throws Exception {
        String out = render(EC_CHAIN, "PRIVATE_KEY_PEM", false);

        assertThat(out).startsWith("-----BEGIN PRIVATE KEY-----\n").doesNotContain("EC PRIVATE KEY");
        assertNamedCurvePkcs8(readPkcs8(out), SECObjectIdentifiers.secp256r1);
        assertSameKeyMaterial(readWithJdk(out, "EC"), EC_LEAF_KEYS.getPrivate());
    }

    @AcrossSecurityProviderModes
    void pkcs12_defaultUsesAes256Pbes2WithHmacSha256_andLoadsBackInTheJdk() throws Exception {
        byte[] pfx = renderBytes(RSA_CHAIN, "PKCS12", false);

        assertLoadsWithKeyAndFullChain(pfx, RSA_CHAIN);
        PKCS12PfxPdu pdu = new PKCS12PfxPdu(pfx);
        assertThat(pdu.getMacAlgorithmID().getAlgorithm()).isEqualTo(NISTObjectIdentifiers.id_sha256);
        assertThat(pdu.toASN1Structure().getMacData().getIterationCount().intValue())
                .isEqualTo(Pkcs12FileBuilder.ITERATIONS);
        for (AlgorithmIdentifier algorithm : protectionAlgorithms(pdu)) {
            assertThat(algorithm.getAlgorithm()).isEqualTo(PKCSObjectIdentifiers.id_PBES2);
            PBES2Parameters pbes2 = PBES2Parameters.getInstance(algorithm.getParameters());
            assertThat(pbes2.getEncryptionScheme().getAlgorithm()).isEqualTo(NISTObjectIdentifiers.id_aes256_CBC);
            PBKDF2Params kdf = PBKDF2Params.getInstance(pbes2.getKeyDerivationFunc().getParameters());
            assertThat(kdf.getPrf().getAlgorithm()).isEqualTo(PKCSObjectIdentifiers.id_hmacWithSHA256);
            assertThat(kdf.getIterationCount().intValue()).isEqualTo(Pkcs12FileBuilder.ITERATIONS);
        }
    }

    @AcrossSecurityProviderModes
    void pkcs12_legacyUses3desAndSha1Mac_andLoadsBackInTheJdk() throws Exception {
        byte[] pfx = renderBytes(RSA_CHAIN, "PKCS12", true);

        assertLoadsWithKeyAndFullChain(pfx, RSA_CHAIN);
        PKCS12PfxPdu pdu = new PKCS12PfxPdu(pfx);
        assertThat(pdu.getMacAlgorithmID().getAlgorithm()).isEqualTo(OIWObjectIdentifiers.idSHA1);
        assertThat(protectionAlgorithms(pdu)).extracting(AlgorithmIdentifier::getAlgorithm)
                .containsOnly(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC);
    }

    @AcrossSecurityProviderModes
    void pkcs12_withEcKey_loadsBackInTheJdk_defaultAndLegacy() throws Exception {
        assertLoadsWithKeyAndFullChain(renderBytes(EC_CHAIN, "PKCS12", false), EC_CHAIN);
        assertLoadsWithKeyAndFullChain(renderBytes(EC_CHAIN, "PKCS12", true), EC_CHAIN);
    }

    @AcrossSecurityProviderModes
    void pkcs12_rejectsWrongPassword() throws Exception {
        byte[] pfx = renderBytes(RSA_CHAIN, "PKCS12", false);

        assertThatThrownBy(() -> JdkPkcs12Reader.read(pfx, "wrong password".toCharArray(), ALIAS))
                .isInstanceOf(IOException.class);
    }

    private static void assertLoadsWithKeyAndFullChain(byte[] pfx, CertExportTestMaterial.Chain chain)
            throws Exception {
        JdkPkcs12Reader.Contents loaded = JdkPkcs12Reader.read(pfx, PASSWORD.toCharArray(), ALIAS);

        assertThat(loaded.aliases()).containsExactly(ALIAS);
        assertThat(loaded.isKeyEntry()).isTrue();
        assertSameKeyMaterial(loaded.key(), chain.leafKeys().getPrivate());
        assertThat(loaded.chain()).containsExactly(chain.leaf(), chain.intermediate());
    }

    /** The certificate EncryptedData's algorithm and every shrouded key bag's algorithm. */
    private static List<AlgorithmIdentifier> protectionAlgorithms(PKCS12PfxPdu pdu) throws Exception {
        List<AlgorithmIdentifier> algorithms = new ArrayList<>();
        for (ContentInfo info : pdu.getContentInfos()) {
            ASN1ObjectIdentifier type = info.getContentType();
            if (type.equals(PKCSObjectIdentifiers.encryptedData)) {
                algorithms.add(EncryptedData.getInstance(info.getContent()).getEncryptionAlgorithm());
                continue;
            }
            for (PKCS12SafeBag bag : new PKCS12SafeBagFactory(info).getSafeBags()) {
                if (bag.getBagValue() instanceof PKCS8EncryptedPrivateKeyInfo key) {
                    algorithms.add(key.getEncryptionAlgorithm());
                }
            }
        }
        assertThat(algorithms).hasSize(2);
        return algorithms;
    }

    /** Through the JDK's own key factory, proving the JDK reads the exported key. */
    private static PrivateKey readWithJdk(String pem, String algorithm) throws Exception {
        String jdkProvider = algorithm.equals("EC") ? "SunEC" : "SunRsaSign";
        return KeyFactory.getInstance(algorithm, jdkProvider).generatePrivate(new PKCS8EncodedKeySpec(readPkcs8(pem)));
    }

    private static byte[] readPkcs8(String pem) throws IOException {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            return ((PrivateKeyInfo) parser.readObject()).getEncoded();
        }
    }

    private static String render(CertExportTestMaterial.Chain chain, String format, boolean legacy) throws Exception {
        return new String(renderBytes(chain, format, legacy), StandardCharsets.US_ASCII);
    }

    private static byte[] renderBytes(CertExportTestMaterial.Chain chain, String format, boolean legacy)
            throws Exception {
        AgentCertificateBundle bundle = AgentCertificateBundleParser.parse(agentBundle(chain, true));
        try (CertExportOptions options = CertExportOptions.from(new CertExportRequest(format, PASSWORD, legacy))) {
            return CertExportFileRenderer.render(bundle, options, ALIAS);
        }
    }
}
