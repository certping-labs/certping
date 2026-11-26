// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import com.certmanagement.exception.CertExportException;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.HexFormat;
import java.util.Locale;

/**
 * Proves the material read from the secret store is the certificate the database describes before
 * any of it leaves the platform: the leaf's SHA-256 fingerprint must equal the recorded one, and the
 * private key, when present, must belong to the leaf.
 */
final class CertificateMaterialVerifier {

    private static final int CHALLENGE_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String EC_SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private static final String RSA_SIGNATURE_ALGORITHM = "SHA256withRSA";

    private CertificateMaterialVerifier() {
    }

    /**
     * @param expectedFingerprintSha256 hex, any case, optionally ':'-delimited (the agent writes
     *                                  upper-case with ':')
     * @throws CertExportException 502 CERT_MATERIAL_MISMATCH on any disagreement
     */
    static void verify(AgentCertificateBundle bundle, String expectedFingerprintSha256) {
        if (!leafMatchesFingerprint(bundle.leaf(), expectedFingerprintSha256)) {
            throw CertExportException.materialMismatch(
                    "The stored certificate does not match this certificate's fingerprint.");
        }
        if (bundle.hasPrivateKey() && !keyBelongsToCertificate(bundle.privateKey(), bundle.leaf().getPublicKey())) {
            throw CertExportException.materialMismatch(
                    "The stored private key does not belong to this certificate.");
        }
    }

    private static boolean leafMatchesFingerprint(X509Certificate leaf, String expected) {
        try {
            byte[] expectedDigest = HexFormat.of().parseHex(
                    expected.replace(":", "").strip().toLowerCase(Locale.ROOT));
            byte[] actualDigest = MessageDigest.getInstance("SHA-256").digest(leaf.getEncoded());
            return MessageDigest.isEqual(expectedDigest, actualDigest);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Signs a random challenge with the private key and verifies it with the certificate's public
     * key: only the matching key pair passes, whatever provider created either object. The key type
     * picks the signature algorithm; a private and public key of different types cannot match.
     */
    private static boolean keyBelongsToCertificate(PrivateKey privateKey, PublicKey publicKey) {
        String algorithm = signatureAlgorithmFor(privateKey);
        if (algorithm == null || !algorithm.equals(signatureAlgorithmFor(publicKey))) {
            return false;
        }
        try {
            byte[] challenge = new byte[CHALLENGE_BYTES];
            RANDOM.nextBytes(challenge);
            Signature signer = Signature.getInstance(algorithm, ExportCryptoProvider.BOUNCY_CASTLE);
            signer.initSign(privateKey);
            signer.update(challenge);
            byte[] signature = signer.sign();
            Signature verifier = Signature.getInstance(algorithm, ExportCryptoProvider.BOUNCY_CASTLE);
            verifier.initVerify(publicKey);
            verifier.update(challenge);
            return verifier.verify(signature);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * By key type, never by {@link Key#getAlgorithm()}: BouncyCastle names an EC key {@code "ECDSA"}
     * where the JDK says {@code "EC"}. Let's Encrypt issues only RSA and ECDSA certificates.
     *
     * @return the signature algorithm, or {@code null} for a key type the export does not handle
     */
    private static String signatureAlgorithmFor(Key key) {
        if (key instanceof ECKey) {
            return EC_SIGNATURE_ALGORITHM;
        }
        return key instanceof RSAKey ? RSA_SIGNATURE_ALGORITHM : null;
    }
}
