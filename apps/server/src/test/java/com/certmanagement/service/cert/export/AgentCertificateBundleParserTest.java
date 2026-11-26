// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import com.certmanagement.exception.CertExportException;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

import static com.certmanagement.service.cert.export.CertExportTestMaterial.EC_LEAF_KEYS;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.EC_PARAMETERS_BLOCK;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.RSA_LEAF_KEYS;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.agentBundle;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.chainFor;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.pem;
import static com.certmanagement.service.cert.export.KeyMaterialAssertions.assertSameKeyMaterial;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AgentCertificateBundleParserTest {

    private static final CertExportTestMaterial.Chain RSA_CHAIN = chainFor("example.com", RSA_LEAF_KEYS);
    private static final CertExportTestMaterial.Chain EC_CHAIN = chainFor("ec.example.com", EC_LEAF_KEYS);

    @AcrossSecurityProviderModes
    void parsesAgentRsaBundle_withTraditionalPkcs1Key() {
        String bundle = agentBundle(RSA_CHAIN, true);
        assertThat(bundle).contains("BEGIN RSA PRIVATE KEY");

        AgentCertificateBundle parsed = AgentCertificateBundleParser.parse(bundle);

        assertThat(parsed.chain()).containsExactly(RSA_CHAIN.leaf(), RSA_CHAIN.intermediate());
        assertSameKeyMaterial(parsed.privateKey(), RSA_LEAF_KEYS.getPrivate());
    }

    @AcrossSecurityProviderModes
    void parsesAgentEcBundle_skippingEcParametersAndPublicKeyBlocks() {
        String bundle = agentBundle(EC_CHAIN, false) + "\n" + EC_PARAMETERS_BLOCK + pem(EC_LEAF_KEYS)
                + pem(EC_LEAF_KEYS.getPublic());
        assertThat(bundle).contains("BEGIN EC PRIVATE KEY");

        AgentCertificateBundle parsed = AgentCertificateBundleParser.parse(bundle);

        assertThat(parsed.chain()).hasSize(2);
        assertSameKeyMaterial(parsed.privateKey(), EC_LEAF_KEYS.getPrivate());
        CertificateMaterialVerifier.verify(parsed, CertExportTestMaterial.fingerprint(EC_CHAIN.leaf()));
    }

    /** acme4j generates EC keys with BouncyCastle, whose traditional encoding names the curve inline. */
    @AcrossSecurityProviderModes
    void parsesEcKeyThatCarriesItsCurve() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair bcKeys = generator.generateKeyPair();
        CertExportTestMaterial.Chain chain = chainFor("bc.example.com", bcKeys);

        AgentCertificateBundle parsed = AgentCertificateBundleParser.parse(agentBundle(chain, true));

        assertSameKeyMaterial(parsed.privateKey(), bcKeys.getPrivate());
        CertificateMaterialVerifier.verify(parsed, CertExportTestMaterial.fingerprint(chain.leaf()));
    }

    @AcrossSecurityProviderModes
    void parsesPkcs8Key() throws Exception {
        String pkcs8 = pem(new JcaPKCS8Generator(RSA_LEAF_KEYS.getPrivate(), null));
        assertThat(pkcs8).contains("BEGIN PRIVATE KEY");

        AgentCertificateBundle parsed = AgentCertificateBundleParser.parse(agentBundle(RSA_CHAIN, false) + pkcs8);

        assertSameKeyMaterial(parsed.privateKey(), RSA_LEAF_KEYS.getPrivate());
    }

    @AcrossSecurityProviderModes
    void bundleWithoutKey_hasNoPrivateKey() {
        AgentCertificateBundle parsed = AgentCertificateBundleParser.parse(agentBundle(RSA_CHAIN, false));

        assertThat(parsed.hasPrivateKey()).isFalse();
        assertThat(parsed.leaf()).isEqualTo(RSA_CHAIN.leaf());
    }

    @AcrossSecurityProviderModes
    void rejectsTwoKeys() {
        assertUnreadable(agentBundle(RSA_CHAIN, true) + pem(EC_LEAF_KEYS));
    }

    @AcrossSecurityProviderModes
    void rejectsKeyWithoutCertificate() {
        assertUnreadable(pem(RSA_LEAF_KEYS));
    }

    @AcrossSecurityProviderModes
    void rejectsEncryptedKey() throws Exception {
        String encrypted = pem(new JcaPKCS8Generator(RSA_LEAF_KEYS.getPrivate(),
                new JceOpenSSLPKCS8EncryptorBuilder(JcaPKCS8Generator.AES_256_CBC)
                        .setProvider(new BouncyCastleProvider())
                        .setPassword("password1".toCharArray()).build()));

        assertUnreadable(agentBundle(RSA_CHAIN, false) + encrypted);
    }

    @AcrossSecurityProviderModes
    void rejectsGarbageEmptyAndOversizedSecrets() {
        assertUnreadable("-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n");
        assertUnreadable("");
        assertUnreadable(null);
        assertUnreadable(agentBundle(RSA_CHAIN, true)
                + "x".repeat(AgentCertificateBundleParser.MAX_BUNDLE_CHARS));
    }

    @AcrossSecurityProviderModes
    void rejectsChainLongerThanTheCap() {
        String leafPem = pem(RSA_CHAIN.leaf());
        assertUnreadable(leafPem.repeat(AgentCertificateBundleParser.MAX_CHAIN_LENGTH + 1));
    }

    private static void assertUnreadable(String bundle) {
        assertThatThrownBy(() -> AgentCertificateBundleParser.parse(bundle))
                .isInstanceOfSatisfying(CertExportException.class, e ->
                        assertThat(e.getCode()).isEqualTo(CertExportException.CERT_MATERIAL_MISMATCH));
    }
}
