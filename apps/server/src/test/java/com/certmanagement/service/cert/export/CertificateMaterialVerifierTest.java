// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import com.certmanagement.exception.CertExportException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;
import java.util.Locale;

import static com.certmanagement.service.cert.export.CertExportTestMaterial.EC_LEAF_KEYS;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.RSA_LEAF_KEYS;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.chainFor;
import static com.certmanagement.service.cert.export.CertExportTestMaterial.fingerprint;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateMaterialVerifierTest {

    private static final CertExportTestMaterial.Chain RSA_CHAIN = chainFor("example.com", RSA_LEAF_KEYS);
    private static final CertExportTestMaterial.Chain EC_CHAIN = chainFor("ec.example.com", EC_LEAF_KEYS);

    @AcrossSecurityProviderModes
    void acceptsMatchingRsaAndEcMaterial_inAnyFingerprintNotation() {
        AgentCertificateBundle rsa = bundle(RSA_CHAIN, RSA_CHAIN.leafKeys().getPrivate());
        AgentCertificateBundle ec = bundle(EC_CHAIN, EC_CHAIN.leafKeys().getPrivate());
        String agentNotation = fingerprint(RSA_CHAIN.leaf());

        assertThatCode(() -> CertificateMaterialVerifier.verify(rsa, agentNotation)).doesNotThrowAnyException();
        assertThatCode(() -> CertificateMaterialVerifier.verify(rsa,
                agentNotation.replace(":", "").toLowerCase(Locale.ROOT))).doesNotThrowAnyException();
        assertThatCode(() -> CertificateMaterialVerifier.verify(ec, fingerprint(EC_CHAIN.leaf())))
                .doesNotThrowAnyException();
    }

    @AcrossSecurityProviderModes
    void acceptsBundleWithoutKey_onFingerprintAlone() {
        assertThatCode(() -> CertificateMaterialVerifier.verify(bundle(RSA_CHAIN, null), fingerprint(RSA_CHAIN.leaf())))
                .doesNotThrowAnyException();
    }

    @AcrossSecurityProviderModes
    void rejectsFingerprintOfAnotherCertificate() {
        assertMismatch(bundle(RSA_CHAIN, RSA_CHAIN.leafKeys().getPrivate()), fingerprint(EC_CHAIN.leaf()));
        assertMismatch(bundle(RSA_CHAIN, RSA_CHAIN.leafKeys().getPrivate()), "not-hex");
    }

    @AcrossSecurityProviderModes
    void rejectsKeyThatDoesNotBelongToTheLeaf() {
        assertMismatch(bundle(RSA_CHAIN, CertExportTestMaterial.rsaKeyPair().getPrivate()),
                fingerprint(RSA_CHAIN.leaf()));
        assertMismatch(bundle(RSA_CHAIN, EC_LEAF_KEYS.getPrivate()), fingerprint(RSA_CHAIN.leaf()));
    }

    @AcrossSecurityProviderModes
    void rejectsRsaKeyOnEcCertificate_andEcKeyOnAnotherCurve() throws Exception {
        assertMismatch(bundle(EC_CHAIN, RSA_LEAF_KEYS.getPrivate()), fingerprint(EC_CHAIN.leaf()));
        KeyPairGenerator p384 = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        p384.initialize(new ECGenParameterSpec("secp384r1"));
        assertMismatch(bundle(EC_CHAIN, p384.generateKeyPair().getPrivate()), fingerprint(EC_CHAIN.leaf()));
    }

    /**
     * The production failure: BouncyCastle names its EC key "ECDSA" while the JDK certificate's key
     * says "EC". The pair still matches, so it must pass.
     */
    @AcrossSecurityProviderModes
    void acceptsBouncyCastleEcKeyForJdkCertificate() throws Exception {
        PrivateKey bouncyCastleKey = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider())
                .generatePrivate(new PKCS8EncodedKeySpec(EC_LEAF_KEYS.getPrivate().getEncoded()));
        assertThat(bouncyCastleKey.getAlgorithm()).isNotEqualTo(EC_CHAIN.leaf().getPublicKey().getAlgorithm());

        assertThatCode(() -> CertificateMaterialVerifier.verify(bundle(EC_CHAIN, bouncyCastleKey),
                fingerprint(EC_CHAIN.leaf()))).doesNotThrowAnyException();
    }

    private static AgentCertificateBundle bundle(CertExportTestMaterial.Chain chain, PrivateKey key) {
        return new AgentCertificateBundle(List.of(chain.leaf(), chain.intermediate()), key);
    }

    private static void assertMismatch(AgentCertificateBundle bundle, String fingerprint) {
        assertThatThrownBy(() -> CertificateMaterialVerifier.verify(bundle, fingerprint))
                .isInstanceOfSatisfying(CertExportException.class, e -> {
                    assertThat(e.getCode())
                            .isEqualTo(CertExportException.CERT_MATERIAL_MISMATCH);
                    assertThat(e.getStatus().value()).isEqualTo(502);
                });
    }
}
