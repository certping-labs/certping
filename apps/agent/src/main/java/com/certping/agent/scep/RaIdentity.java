// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

/**
 * The RA identity: the certificate devices encrypt their request {@code EnvelopedData} to, and whose
 * private key decrypts inbound requests and signs the {@code CertRep} reply. Separate from the device
 * leaf the CA signs — provision it once under the issuing CA and store the PKCS#12 in the secret store.
 */
public record RaIdentity(PrivateKey key, X509Certificate cert, List<X509Certificate> chain) {

    /**
     * The issuing CA chain — the keystore chain with the RA leaf ({@link #cert}) removed if it is the
     * first entry. A PKCS#12 stores the chain leaf-first ({@code [RA, CA, ...]}), so publishing
     * {@code chain} verbatim as the CA would wrongly expose the RA cert as the issuer.
     */
    public List<X509Certificate> caChain() {
        if (!chain.isEmpty() && chain.get(0).equals(cert)) {
            return List.copyOf(chain.subList(1, chain.size()));
        }
        return chain;
    }

    /** Read a SecretStore handle holding JSON {@code {"p12":"<base64 PKCS#12>","password":"..."}}. */
    public static RaIdentity fromSecret(SecretStore store, ObjectMapper mapper, String handle) throws Exception {
        if (handle == null || handle.isBlank()) {
            throw new IllegalStateException(
                    "agent.scep.ca.ra-keystore-handle is required when SCEP is enabled");
        }
        JsonNode node = mapper.readTree(store.read(handle));
        JsonNode p12 = node.get("p12");
        JsonNode password = node.get("password");
        if (p12 == null || password == null) {
            throw new IllegalStateException(
                    "RA keystore secret must be JSON {\"p12\":\"<base64>\",\"password\":\"...\"}");
        }
        return fromPkcs12(Base64.getDecoder().decode(p12.asString()), password.asString().toCharArray());
    }

    public static RaIdentity fromPkcs12(byte[] p12, char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(p12), password);
        String alias = firstKeyAlias(ks);
        PrivateKey key = (PrivateKey) ks.getKey(alias, password);
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        List<X509Certificate> chain = new ArrayList<>();
        java.security.cert.Certificate[] certs = ks.getCertificateChain(alias);
        if (certs != null) {
            for (java.security.cert.Certificate c : certs) {
                chain.add((X509Certificate) c);
            }
        } else {
            chain.add(cert);
        }
        requireRsaKeyTransportIdentity(key, cert);
        requireChainEndsAtRoot(chain);
        return new RaIdentity(key, cert, chain);
    }

    // Windows (Intune) looks for the profile's trusted root by thumbprint in the GetCACert reply and
    // fails with "The hash value is not correct" when it is missing.
    private static void requireChainEndsAtRoot(List<X509Certificate> chain) {
        X509Certificate last = chain.get(chain.size() - 1);
        boolean selfSigned = last.getSubjectX500Principal().equals(last.getIssuerX500Principal());
        if (selfSigned) {
            try {
                last.verify(last.getPublicKey());
            } catch (Exception e) {
                selfSigned = false;
            }
        }
        if (!selfSigned) {
            throw new IllegalStateException("SCEP RA keystore chain must include every CA up to and "
                    + "including the root; it ends at " + last.getSubjectX500Principal().getName()
                    + ". Rebuild the PKCS#12 with the root CA certificate added");
        }
    }

    private static void requireRsaKeyTransportIdentity(PrivateKey key, X509Certificate cert) {
        if (key == null || cert == null) {
            throw new IllegalStateException("RA keystore private key or certificate is missing");
        }
        if (!"RSA".equalsIgnoreCase(key.getAlgorithm())
                || !"RSA".equalsIgnoreCase(cert.getPublicKey().getAlgorithm())) {
            throw new IllegalStateException(
                    "SCEP RA identity must use RSA (minimum 2048 bits) for CMS key transport; "
                            + "Smallstep defaults new leaf keys to EC, so provision the RA with "
                            + "--kty RSA --size 2048");
        }
        if (cert.getPublicKey() instanceof java.security.interfaces.RSAPublicKey rsa
                && rsa.getModulus().bitLength() < 2048) {
            throw new IllegalStateException("SCEP RA RSA key must be at least 2048 bits");
        }
    }

    private static String firstKeyAlias(KeyStore ks) throws Exception {
        for (Enumeration<String> e = ks.aliases(); e.hasMoreElements(); ) {
            String alias = e.nextElement();
            if (ks.isKeyEntry(alias)) {
                return alias;
            }
        }
        throw new IllegalStateException("RA keystore has no private-key entry");
    }
}
