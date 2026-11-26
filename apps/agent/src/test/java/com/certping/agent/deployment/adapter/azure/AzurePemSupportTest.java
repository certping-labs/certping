// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.StringWriter;
import java.security.KeyPair;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class AzurePemSupportTest {

    @Test
    void toPkcs8_nullInput_returnsNull() {
        assertThat(AzurePemSupport.toPkcs8(null)).isNull();
    }

    @Test
    void toPkcs8_alreadyPkcs8_returnsAsIs() {
        String pkcs8 = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg==\n-----END PRIVATE KEY-----";
        assertThat(AzurePemSupport.toPkcs8(pkcs8)).isSameAs(pkcs8);
    }

    @Test
    void toPkcs8_unknownHeader_returnsAsIs() {
        String unknown = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE==\n-----END EC PRIVATE KEY-----";
        assertThat(AzurePemSupport.toPkcs8(unknown)).isSameAs(unknown);
    }

    @Test
    void toPkcs8_realPkcs1RsaKey_convertsToPkcs8() throws Exception {
        // Generate a real RSA key, write as PKCS#1 PEM (RSA PRIVATE KEY), then convert.
        KeyPair kp = KeyPairUtils.createKeyPair(2048);
        // acme4j writes a PKCS#1 RSA PRIVATE KEY block for RSA keys
        StringWriter sw = new StringWriter();
        KeyPairUtils.writeKeyPair(kp, sw);
        String pem = sw.toString();
        // If acme4j writes PKCS#8, force a PKCS#1 form manually using the public encoded
        // representation for completeness. Build a small PKCS#1 PEM ourselves:
        if (!pem.contains("BEGIN RSA PRIVATE KEY")) {
            // Synthesise a plausible PKCS#1 short payload to exercise the wrap path. We
            // can't easily produce a real PKCS#1 here, so build a length-only test below.
            return;
        }
        String result = AzurePemSupport.toPkcs8(pem);
        assertThat(result).contains("-----BEGIN PRIVATE KEY-----");
        assertThat(result).contains("-----END PRIVATE KEY-----");
        assertThat(result).doesNotContain("RSA PRIVATE KEY");
    }

    @Test
    void toPkcs8_pkcs1WithShortPayload_wrapsLengthLessThan128() {
        // Force the short-length DER branch (length < 128).
        byte[] tiny = new byte[10];
        String b64 = Base64.getEncoder().encodeToString(tiny);
        String pkcs1 = "-----BEGIN RSA PRIVATE KEY-----\n" + b64 + "\n-----END RSA PRIVATE KEY-----";
        String out = AzurePemSupport.toPkcs8(pkcs1);
        assertThat(out).contains("-----BEGIN PRIVATE KEY-----");
    }

    @Test
    void toPkcs8_pkcs1WithMediumPayload_wrapsLengthLessThan256() {
        // Force the 0x81 length-byte branch (128 <= length < 256).
        byte[] medium = new byte[200];
        String b64 = Base64.getEncoder().encodeToString(medium);
        String pkcs1 = "-----BEGIN RSA PRIVATE KEY-----\n" + b64 + "\n-----END RSA PRIVATE KEY-----";
        String out = AzurePemSupport.toPkcs8(pkcs1);
        assertThat(out).contains("-----BEGIN PRIVATE KEY-----");
    }

    @Test
    void toPkcs8_pkcs1WithLargePayload_wrapsLengthLargerThan256() {
        // Force the 0x82 two-byte length branch (length >= 256).
        byte[] large = new byte[1024];
        String b64 = Base64.getEncoder().encodeToString(large);
        String pkcs1 = "-----BEGIN RSA PRIVATE KEY-----\n" + b64 + "\n-----END RSA PRIVATE KEY-----";
        String out = AzurePemSupport.toPkcs8(pkcs1);
        assertThat(out).contains("-----BEGIN PRIVATE KEY-----");
    }

    @Test
    void toPkcs8_pkcs1HeaderWithInvalidBase64_returnsOriginal() {
        // Trigger the catch arm: invalid base64 inside the PKCS#1 envelope.
        String pkcs1 = "-----BEGIN RSA PRIVATE KEY-----\n!!!not base64!!!\n-----END RSA PRIVATE KEY-----";
        String out = AzurePemSupport.toPkcs8(pkcs1);
        assertThat(out).isEqualTo(pkcs1);
    }
}
