// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;

/**
 * A parsed inbound SCEP pkiMessage: its SCEP attributes, the decrypted PKCS#10 CSR, the challenge
 * password (first enrolment), and the device signer certificate (needed to envelope the reply back).
 */
public record ScepRequest(
        int messageType,
        String transactionId,
        byte[] senderNonce,
        PKCS10CertificationRequest csr,
        byte[] csrDer,
        X509Certificate deviceCertificate,
        String challengePassword) {

    public String csrDerBase64() {
        return Base64.getEncoder().encodeToString(csrDer);
    }

    /** Stable SHA-256 over the CSR DER — retry idempotency and same-transaction conflict detection. */
    public String csrFingerprint() {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(csrDer));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
