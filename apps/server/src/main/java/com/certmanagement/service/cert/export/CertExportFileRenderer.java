// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/** Renders verified certificate material in the requested export format. */
final class CertExportFileRenderer {

    private CertExportFileRenderer() {
    }

    /**
     * @param bundle  verified material; must hold a private key when {@code options.format()} needs one
     * @param alias   the PKCS#12 friendlyName (the sanitised common name)
     */
    static byte[] render(AgentCertificateBundle bundle, CertExportOptions options, String alias)
            throws GeneralSecurityException, IOException {
        return switch (options.format()) {
            case FULLCHAIN_PEM -> certificatesPem(bundle.chain());
            case CERTIFICATE_PEM -> certificatesPem(List.of(bundle.leaf()));
            case CERTIFICATE_DER -> bundle.leaf().getEncoded();
            case PKCS7 -> pkcs7(bundle.chain());
            case PRIVATE_KEY_PEM -> privateKeyPem(bundle);
            case PKCS12 -> Pkcs12FileBuilder.build(bundle, alias, options.password(), options.legacyPkcs12());
        };
    }

    private static byte[] certificatesPem(List<X509Certificate> certificates) throws CertificateEncodingException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (X509Certificate certificate : certificates) {
            out.writeBytes(PemBlockEncoder.encode("CERTIFICATE", certificate.getEncoded()));
        }
        return out.toByteArray();
    }

    /** A degenerate CMS SignedData: the certificates and no signature, which is what a .p7b holds. */
    private static byte[] pkcs7(List<X509Certificate> certificates) throws GeneralSecurityException, IOException {
        try {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addCertificates(new JcaCertStore(certificates));
            return generator.generate(new CMSAbsentContent()).getEncoded();
        } catch (CMSException e) {
            throw new GeneralSecurityException("PKCS#7 bundle could not be built", e);
        }
    }

    /** JCA private keys encode as PKCS#8, so this emits {@code BEGIN PRIVATE KEY} whatever the stored form. */
    private static byte[] privateKeyPem(AgentCertificateBundle bundle) {
        byte[] pkcs8 = bundle.privateKey().getEncoded();
        try {
            return PemBlockEncoder.encode("PRIVATE KEY", pkcs8);
        } finally {
            Arrays.fill(pkcs8, (byte) 0);
        }
    }
}
