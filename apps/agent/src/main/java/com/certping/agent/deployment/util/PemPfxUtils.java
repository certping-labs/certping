// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.util;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.exception.PermanentAgentException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public final class PemPfxUtils {

    private PemPfxUtils() {}

    public static byte[] toPkcs12Bytes(CertificateBundle bundle, String password) {
        try {
            PrivateKey privateKey = parsePrivateKey(bundle.privateKey());
            List<X509Certificate> chain = parseCertificateChain(bundle.fullChain());

            if (chain.isEmpty()) {
                throw new PermanentAgentException("CERT_FORMAT_INVALID",
                        "No certificates found in PEM bundle for PKCS12 creation");
            }

            char[] pwd = password == null ? new char[0] : password.toCharArray();

            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("certping", privateKey, pwd, chain.toArray(new Certificate[0]));

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ks.store(out, pwd);
            return out.toByteArray();

        } catch (PermanentAgentException e) {
            throw e;
        } catch (Exception e) {
            throw new PermanentAgentException("CERT_PFX_BUILD_FAILED",
                    "Failed to create PKCS12 from PEM bundle: " + e.getMessage(), e);
        }
    }

    private static PrivateKey parsePrivateKey(String keyPem) throws Exception {
        if (keyPem == null || keyPem.isBlank()) {
            throw new PermanentAgentException("CERT_FORMAT_INVALID",
                    "Private key PEM is blank");
        }

        try (PEMParser parser = new PEMParser(new StringReader(keyPem))) {
            Object obj = parser.readObject();
            if (obj == null) {
                throw new PermanentAgentException("CERT_FORMAT_INVALID",
                        "Private key PEM is empty or malformed");
            }
            if (obj instanceof PEMEncryptedKeyPair) {
                throw new PermanentAgentException("CERT_FORMAT_INVALID",
                        "Encrypted private keys are not supported for PKCS12 creation");
            }

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            if (obj instanceof PEMKeyPair keyPair) {
                return converter.getKeyPair(keyPair).getPrivate();
            }
            if (obj instanceof PrivateKeyInfo keyInfo) {
                return converter.getPrivateKey(keyInfo);
            }
        }

        throw new PermanentAgentException("CERT_FORMAT_INVALID",
                "Unsupported private key format for PKCS12 creation");
    }

    private static List<X509Certificate> parseCertificateChain(String pemChain) throws CertificateException {
        if (pemChain == null || pemChain.isBlank()) {
            return List.of();
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (ByteArrayInputStream in = new ByteArrayInputStream(pemChain.getBytes(StandardCharsets.US_ASCII))) {
            List<X509Certificate> certs = new ArrayList<>();
            for (Certificate cert : cf.generateCertificates(in)) {
                certs.add((X509Certificate) cert);
            }
            return certs;
        } catch (Exception e) {
            throw new CertificateException("Failed to parse certificate chain: " + e.getMessage(), e);
        }
    }
}
