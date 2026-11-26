// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.util;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.exception.PermanentAgentException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateBundleUtilsTest {

    // ── Fixtures ──────────────────────────────────────────────────────────────

    private static final String LEAF_CERT =
            "-----BEGIN CERTIFICATE-----\nMIILeafCert==\n-----END CERTIFICATE-----";
    private static final String INTERMEDIATE_CERT =
            "-----BEGIN CERTIFICATE-----\nMIIIntermediateCert==\n-----END CERTIFICATE-----";
    private static final String ROOT_CERT =
            "-----BEGIN CERTIFICATE-----\nMIIRootCert==\n-----END CERTIFICATE-----";
    private static final String PRIVATE_KEY_PKCS8 =
            "-----BEGIN PRIVATE KEY-----\nMIIPrivateKey==\n-----END PRIVATE KEY-----";
    private static final String PRIVATE_KEY_PKCS1 =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIRsaKey==\n-----END RSA PRIVATE KEY-----";

    /** Bundle with full chain (leaf + intermediate + root) + PKCS#8 private key — LE output format */
    private static final String FULL_BUNDLE =
            LEAF_CERT + "\n" + INTERMEDIATE_CERT + "\n" + ROOT_CERT + "\n" + PRIVATE_KEY_PKCS8;

    /** Bundle with only leaf cert + PKCS#8 key — DigiCert single-cert response */
    private static final String LEAF_ONLY_BUNDLE =
            LEAF_CERT + "\n" + PRIVATE_KEY_PKCS8;

    /** Bundle with PKCS#1 key */
    private static final String PKCS1_BUNDLE =
            LEAF_CERT + "\n" + INTERMEDIATE_CERT + "\n" + PRIVATE_KEY_PKCS1;

    // ── Happy path ────────────────────────────────────────────────────────────

    @Test
    void parse_fullBundle_extractsLeafCorrectly() {
        CertificateBundle bundle = CertificateBundleUtils.parse(FULL_BUNDLE);
        assertThat(bundle.leafCertificate()).contains("MIILeafCert==");
        assertThat(bundle.leafCertificate()).doesNotContain("MIIIntermediateCert==");
    }

    @Test
    void parse_fullBundle_certChainExcludesLeaf() {
        CertificateBundle bundle = CertificateBundleUtils.parse(FULL_BUNDLE);
        assertThat(bundle.certChain()).contains("MIIIntermediateCert==");
        assertThat(bundle.certChain()).contains("MIIRootCert==");
        assertThat(bundle.certChain()).doesNotContain("MIILeafCert==");
    }

    @Test
    void parse_fullBundle_fullChainIncludesLeaf() {
        CertificateBundle bundle = CertificateBundleUtils.parse(FULL_BUNDLE);
        assertThat(bundle.fullChain()).contains("MIILeafCert==");
        assertThat(bundle.fullChain()).contains("MIIIntermediateCert==");
        assertThat(bundle.fullChain()).contains("MIIRootCert==");
    }

    @Test
    void parse_fullBundle_extractsPrivateKeyPkcs8() {
        CertificateBundle bundle = CertificateBundleUtils.parse(FULL_BUNDLE);
        assertThat(bundle.privateKey()).contains("BEGIN PRIVATE KEY");
        assertThat(bundle.privateKey()).contains("MIIPrivateKey==");
    }

    @Test
    void parse_leafOnlyBundle_certChainIsEmpty() {
        CertificateBundle bundle = CertificateBundleUtils.parse(LEAF_ONLY_BUNDLE);
        assertThat(bundle.leafCertificate()).contains("MIILeafCert==");
        assertThat(bundle.certChain()).isBlank(); // no intermediates
        assertThat(bundle.fullChain()).contains("MIILeafCert==");
    }

    @Test
    void parse_pkcs1Key_detected() {
        CertificateBundle bundle = CertificateBundleUtils.parse(PKCS1_BUNDLE);
        assertThat(bundle.privateKey()).contains("BEGIN RSA PRIVATE KEY");
    }

    // ── Error cases ───────────────────────────────────────────────────────────

    @Test
    void parse_nullBundle_throwsPermanentException() {
        assertThatThrownBy(() -> CertificateBundleUtils.parse(null))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("CERT_FORMAT_INVALID"));
    }

    @Test
    void parse_blankBundle_throwsPermanentException() {
        assertThatThrownBy(() -> CertificateBundleUtils.parse("   "))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("CERT_FORMAT_INVALID"));
    }

    @Test
    void parse_noCertBlock_throwsPermanentException() {
        assertThatThrownBy(() -> CertificateBundleUtils.parse(PRIVATE_KEY_PKCS8))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("CERT_FORMAT_INVALID"));
    }

    @Test
    void parse_noPrivateKey_throwsPermanentException() {
        assertThatThrownBy(() -> CertificateBundleUtils.parse(LEAF_CERT + "\n" + INTERMEDIATE_CERT))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("CERT_FORMAT_INVALID"));
    }
}
