// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECParameterSpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Compares keys by their mathematical content, never by encoded bytes: BouncyCastle and the JDK
 * encode the same P-256 key differently (BouncyCastle repeats the curve and the public point inside
 * the PKCS#8 body), and which one built a key depends on the JVM's provider order.
 */
final class KeyMaterialAssertions {

    private KeyMaterialAssertions() {
    }

    /** EC: same private scalar on the same curve. RSA: same modulus and private exponent. */
    static void assertSameKeyMaterial(Key actual, PrivateKey expected) {
        if (expected instanceof ECPrivateKey expectedEc) {
            assertThat(actual).isInstanceOf(ECPrivateKey.class);
            ECPrivateKey actualEc = (ECPrivateKey) actual;
            assertThat(actualEc.getS()).isEqualTo(expectedEc.getS());
            assertSameCurve(actualEc.getParams(), expectedEc.getParams());
        } else if (expected instanceof RSAPrivateKey expectedRsa) {
            assertThat(actual).isInstanceOf(RSAPrivateKey.class);
            RSAPrivateKey actualRsa = (RSAPrivateKey) actual;
            assertThat(actualRsa.getModulus()).isEqualTo(expectedRsa.getModulus());
            assertThat(actualRsa.getPrivateExponent()).isEqualTo(expectedRsa.getPrivateExponent());
        } else {
            fail("Unsupported test key type: " + expected.getClass());
        }
    }

    /**
     * The PKCS#8 body names its curve by OID, in the algorithm identifier and (when repeated) inside
     * the SEC 1 key, and never spells the curve out as explicit parameters, which many TLS stacks reject.
     */
    static void assertNamedCurvePkcs8(byte[] pkcs8, ASN1ObjectIdentifier expectedCurve) throws IOException {
        PrivateKeyInfo info = PrivateKeyInfo.getInstance(pkcs8);
        assertThat(info.getPrivateKeyAlgorithm().getAlgorithm()).isEqualTo(X9ObjectIdentifiers.id_ecPublicKey);
        X962Parameters algorithmParameters = X962Parameters.getInstance(info.getPrivateKeyAlgorithm().getParameters());
        assertThat(algorithmParameters.isNamedCurve()).isTrue();
        assertThat(algorithmParameters.getParameters()).isEqualTo(expectedCurve);

        org.bouncycastle.asn1.sec.ECPrivateKey sec1Key =
                org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(info.parsePrivateKey());
        if (sec1Key.getParametersObject() != null) {
            assertThat(sec1Key.getParametersObject()).isEqualTo(expectedCurve);
        }
    }

    private static void assertSameCurve(ECParameterSpec actual, ECParameterSpec expected) {
        assertThat(actual.getCurve()).isEqualTo(expected.getCurve());
        assertThat(actual.getGenerator()).isEqualTo(expected.getGenerator());
        assertThat(actual.getOrder()).isEqualTo(expected.getOrder());
        assertThat(actual.getCofactor()).isEqualTo(expected.getCofactor());
    }
}
