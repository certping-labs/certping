// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import com.certmanagement.exception.CertExportException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.StringReader;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads the agent's certificate secret: the chain PEM (leaf first) followed by the private key PEM.
 *
 * <p>The agent writes the key with acme4j's {@code KeyPairUtils.writeKeyPair}, so it arrives in the
 * traditional OpenSSL form ({@code RSA PRIVATE KEY} / {@code EC PRIVATE KEY}, possibly with an
 * {@code EC PARAMETERS} or public key block); PKCS#8 {@code PRIVATE KEY} is accepted too. Every key is
 * converted to a JCA {@link PrivateKey}, whose encoding is PKCS#8. Encrypted keys and any other PEM
 * object are rejected rather than skipped, so a malformed secret never exports partially.
 *
 * <p>Certificates and keys are built by {@link ExportCryptoProvider#BOUNCY_CASTLE}, never by whichever
 * provider the JVM lists first, so the key type and encoding do not depend on application start-up.
 */
final class AgentCertificateBundleParser {

    /** Key Vault caps a secret at 25k characters; anything beyond is not an agent bundle. */
    static final int MAX_BUNDLE_CHARS = 64 * 1024;
    static final int MAX_CHAIN_LENGTH = 10;

    private static final JcaX509CertificateConverter CERT_CONVERTER =
            new JcaX509CertificateConverter().setProvider(ExportCryptoProvider.BOUNCY_CASTLE);
    private static final JcaPEMKeyConverter KEY_CONVERTER =
            new JcaPEMKeyConverter().setProvider(ExportCryptoProvider.BOUNCY_CASTLE);

    private AgentCertificateBundleParser() {
    }

    /**
     * Parses {@code bundlePem}.
     *
     * @throws CertExportException 502 CERT_MATERIAL_MISMATCH when the secret is empty, oversized,
     *                             unreadable, has no certificate, or holds more than one key
     */
    static AgentCertificateBundle parse(String bundlePem) {
        if (bundlePem == null || bundlePem.isBlank() || bundlePem.length() > MAX_BUNDLE_CHARS) {
            throw unreadable();
        }
        List<X509Certificate> chain = new ArrayList<>();
        PrivateKeyInfo keyInfo = null;
        try (PEMParser parser = new PEMParser(new StringReader(bundlePem))) {
            Object pemObject;
            while ((pemObject = parser.readObject()) != null) {
                PrivateKeyInfo parsedKey = toPrivateKeyInfo(pemObject);
                if (parsedKey != null) {
                    keyInfo = requireSingleKey(keyInfo, parsedKey);
                } else if (pemObject instanceof X509CertificateHolder holder) {
                    addCertificate(chain, holder);
                } else if (!isIgnorableKeyCompanion(pemObject)) {
                    throw unreadable();
                }
            }
            if (chain.isEmpty()) {
                throw unreadable();
            }
            PrivateKey privateKey = keyInfo == null ? null
                    : KEY_CONVERTER.getPrivateKey(withCurveFromLeaf(keyInfo, chain.get(0)));
            return new AgentCertificateBundle(chain, privateKey);
        } catch (CertExportException e) {
            throw e;
        } catch (IOException | CertificateException | RuntimeException e) {
            throw unreadable();
        }
    }

    private static PrivateKeyInfo toPrivateKeyInfo(Object pemObject) {
        if (pemObject instanceof PEMKeyPair keyPair) {
            return keyPair.getPrivateKeyInfo();
        }
        return pemObject instanceof PrivateKeyInfo keyInfo ? keyInfo : null;
    }

    /**
     * A traditional {@code EC PRIVATE KEY} may omit its curve (OpenSSL then puts it in a separate
     * {@code EC PARAMETERS} block), which the JDK cannot load. The leaf's public key names the curve
     * the key must be on; a key on any other curve fails the later key-to-certificate check anyway.
     */
    private static PrivateKeyInfo withCurveFromLeaf(PrivateKeyInfo keyInfo, X509Certificate leaf) throws IOException {
        AlgorithmIdentifier keyAlgorithm = keyInfo.getPrivateKeyAlgorithm();
        boolean curveMissing = keyAlgorithm.getParameters() == null
                || DERNull.INSTANCE.equals(keyAlgorithm.getParameters());
        if (!X9ObjectIdentifiers.id_ecPublicKey.equals(keyAlgorithm.getAlgorithm()) || !curveMissing) {
            return keyInfo;
        }
        AlgorithmIdentifier leafAlgorithm = SubjectPublicKeyInfo.getInstance(leaf.getPublicKey().getEncoded())
                .getAlgorithm();
        if (!X9ObjectIdentifiers.id_ecPublicKey.equals(leafAlgorithm.getAlgorithm())) {
            throw CertExportException.materialMismatch("The stored private key does not belong to this certificate.");
        }
        return new PrivateKeyInfo(leafAlgorithm, keyInfo.parsePrivateKey());
    }

    private static PrivateKeyInfo requireSingleKey(PrivateKeyInfo existing, PrivateKeyInfo parsed) {
        if (existing != null) {
            throw unreadable();
        }
        return parsed;
    }

    private static void addCertificate(List<X509Certificate> chain, X509CertificateHolder holder)
            throws CertificateException {
        if (chain.size() >= MAX_CHAIN_LENGTH) {
            throw unreadable();
        }
        chain.add(CERT_CONVERTER.getCertificate(holder));
    }

    /** {@code EC PARAMETERS} and {@code PUBLIC KEY} blocks accompany a key and carry nothing secret. */
    private static boolean isIgnorableKeyCompanion(Object pemObject) {
        return pemObject instanceof ASN1ObjectIdentifier || pemObject instanceof SubjectPublicKeyInfo;
    }

    private static CertExportException unreadable() {
        return CertExportException.materialMismatch("The stored certificate material could not be read.");
    }
}
