// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Builds a password-protected PKCS#12 (.pfx) holding the private key and the full chain.
 *
 * <p>Algorithms are chosen per file, never from JVM-wide security properties, so a legacy export
 * cannot leak into a concurrent modern one:
 * <ul>
 *   <li><b>Default</b> (the JDK 21 / OpenSSL 3 defaults): key and certificates encrypted with PBES2
 *       (PBKDF2 with HMAC-SHA256, AES-256-CBC, the JDK's PBEWithHmacSHA256AndAES_256); integrity by a
 *       PKCS#12 HMAC-SHA256 MAC (the JDK's HmacPBESHA256).</li>
 *   <li><b>Legacy</b> for Windows Server 2016 and older and OpenSSL 1.0: key and certificates under
 *       pbeWithSHAAnd3-KeyTripleDES-CBC (PBEWithSHA1AndDESede); MAC HMAC-SHA1 (HmacPBESHA1).</li>
 * </ul>
 * Both use {@value #ITERATIONS} iterations, the JDK 21 default.
 *
 * <p>The leaf certificate and key bags carry the same friendlyName (the alias) and localKeyId, so
 * Windows, OpenSSL and {@code KeyStore("PKCS12")} pair them.
 */
final class Pkcs12FileBuilder {

    static final int ITERATIONS = 10_000;

    private static final AlgorithmIdentifier HMAC_SHA256_PRF =
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE);

    private Pkcs12FileBuilder() {
    }

    static byte[] build(AgentCertificateBundle bundle, String alias, char[] password, boolean legacy)
            throws GeneralSecurityException, IOException {
        try {
            SubjectKeyIdentifier localKeyId =
                    new JcaX509ExtensionUtils().createSubjectKeyIdentifier(bundle.leaf().getPublicKey());
            PKCS12SafeBag[] certificateBags = certificateBags(bundle.chain(), alias, localKeyId);
            PKCS12SafeBagBuilder keyBag =
                    new JcaPKCS12SafeBagBuilder(bundle.privateKey(), encryptor(password, legacy));
            labelBag(keyBag, alias, localKeyId);

            PKCS12PfxPduBuilder pfx = new PKCS12PfxPduBuilder();
            pfx.addEncryptedData(encryptor(password, legacy), certificateBags);
            pfx.addData(keyBag.build());
            return pfx.build(macCalculator(legacy), password).getEncoded(ASN1Encoding.DER);
        } catch (PKCSException | OperatorCreationException e) {
            throw new GeneralSecurityException("PKCS#12 assembly failed", e);
        }
    }

    private static PKCS12SafeBag[] certificateBags(List<X509Certificate> chain, String alias,
                                                   SubjectKeyIdentifier localKeyId) throws IOException {
        PKCS12SafeBag[] bags = new PKCS12SafeBag[chain.size()];
        for (int i = 0; i < chain.size(); i++) {
            PKCS12SafeBagBuilder bag = new JcaPKCS12SafeBagBuilder(chain.get(i));
            if (i == 0) {
                labelBag(bag, alias, localKeyId);
            }
            bags[i] = bag.build();
        }
        return bags;
    }

    private static void labelBag(PKCS12SafeBagBuilder bag, String alias, SubjectKeyIdentifier localKeyId) {
        bag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(alias));
        bag.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, localKeyId);
    }

    /** A fresh encryptor per bag set: each draws its own salt. */
    private static OutputEncryptor encryptor(char[] password, boolean legacy)
            throws OperatorCreationException {
        JcePKCSPBEOutputEncryptorBuilder builder = legacy
                ? new JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC)
                : new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC).setPRF(HMAC_SHA256_PRF);
        return builder.setProvider(ExportCryptoProvider.BOUNCY_CASTLE).setIterationCount(ITERATIONS).build(password);
    }

    private static PKCS12MacCalculatorBuilder macCalculator(boolean legacy) {
        return new JcePKCS12MacCalculatorBuilder(legacy ? OIWObjectIdentifiers.idSHA1 : NISTObjectIdentifiers.id_sha256)
                .setProvider(ExportCryptoProvider.BOUNCY_CASTLE)
                .setIterationCount(ITERATIONS);
    }
}
