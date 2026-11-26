// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

/**
 * Utility methods to extract strongly-typed certificate metadata from the issued leaf cert.
 */
public final class CertificateMetadataExtractor {

    private static final String PEM_CERTIFICATE_BEGIN = "-----BEGIN CERTIFICATE-----";
    private static final String PEM_CERTIFICATE_END = "-----END CERTIFICATE-----";

    private CertificateMetadataExtractor() {
    }

    /** The first certificate of a PEM bundle (a chain, optionally followed by its private key). */
    public static X509Certificate firstCertificate(String pemBundle) throws CertificateException {
        int start = pemBundle.indexOf(PEM_CERTIFICATE_BEGIN);
        int end = pemBundle.indexOf(PEM_CERTIFICATE_END, Math.max(start, 0));
        if (start < 0 || end < 0) {
            throw new CertificateException("no PEM certificate in the bundle");
        }
        byte[] pem = pemBundle.substring(start, end + PEM_CERTIFICATE_END.length()).getBytes(StandardCharsets.US_ASCII);
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem));
    }

    /** The SHA-256 fingerprint of {@code cert}'s DER encoding, as colon-separated upper-case hex. */
    public static String sha256Fingerprint(X509Certificate cert) throws CertificateEncodingException {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            return HexFormat.of().withUpperCase().withDelimiter(":").formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    public static CertificateMetadata fromLeaf(X509Certificate leaf) {
        if (leaf == null) {
            return new CertificateMetadata(
                    null, null, null, null, null, null, null, null, null, null, null, List.of(), null);
        }

        PublicKey publicKey = leaf.getPublicKey();

        return new CertificateMetadata(
                leaf.getSigAlgName(),
                getSignatureAlgorithmOid(leaf),
                getSubjectDn(leaf),
                getCommonName(leaf),
                publicKey != null ? publicKey.getAlgorithm() : null,
                resolveKeySize(publicKey),
                getPublicKeyCurve(leaf),
                getKeyUsage(leaf),
                getExtendedKeyUsage(leaf),
                getSubjectKeyIdentifier(leaf),
                getAuthorityKeyIdentifier(leaf),
                getCertificatePolicyOids(leaf),
                leaf.getBasicConstraints() >= 0
        );
    }

    public static String getSignatureAlgorithmOid(X509Certificate cert) {
        if (cert == null) {
            return null;
        }
        return cert.getSigAlgOID();
    }

    public static String getSubjectDn(X509Certificate cert) {
        if (cert == null) {
            return null;
        }
        return cert.getSubjectX500Principal().getName();
    }

    public static String getCommonName(X509Certificate cert) {
        if (cert == null) {
            return null;
        }
        String subjectDn = getSubjectDn(cert);
        if (subjectDn == null) {
            return null;
        }
        // Extract CN from subject DN (e.g., "CN=example.com,O=Acme,C=US" -> "example.com")
        for (String part : subjectDn.split(",")) {
            part = part.trim();
            if (part.startsWith("CN=")) {
                return part.substring(3);
            }
        }
        return null;
    }

    public static String getKeyUsage(X509Certificate cert) {
        if (cert == null) {
            return null;
        }
        boolean[] keyUsageBits = cert.getKeyUsage();
        if (keyUsageBits == null) {
            return null;
        }
        return formatKeyUsage(keyUsageBits);
    }

    public static String getPublicKeyCurve(X509Certificate cert) {
        if (cert == null) {
            return null;
        }
        PublicKey publicKey = cert.getPublicKey();
        if (!(publicKey instanceof ECKey)) {
            return null;
        }
        try {
            SubjectPublicKeyInfo subjectPublicKeyInfo =
                    SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            ASN1ObjectIdentifier curveOid = ASN1ObjectIdentifier.getInstance(
                    subjectPublicKeyInfo.getAlgorithm().getParameters());
            return curveOid.getId();
        } catch (Exception exception) {
            return null;
        }
    }

    public static String getExtendedKeyUsage(X509Certificate cert) {
        if (cert == null) {
            return null;
        }
        try {
            List<String> extendedKeyUsage = cert.getExtendedKeyUsage();
            if (extendedKeyUsage == null || extendedKeyUsage.isEmpty()) {
                return null;
            }
            return String.join(",", extendedKeyUsage);
        } catch (java.security.cert.CertificateParsingException e) {
            return null;
        }
    }

    public static String getSubjectKeyIdentifier(X509Certificate cert) {
        if (cert == null) {
            return null;
        }
        try {
            byte[] extValue = cert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
            if (extValue == null) {
                return null;
            }
            SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(X509ExtensionUtil.fromExtensionValue(extValue));
            return toHexString(ski.getKeyIdentifier());
        } catch (Exception e) {
            return null;
        }
    }

    public static String getAuthorityKeyIdentifier(X509Certificate cert) {
        if (cert == null) {
            return null;
        }
        try {
            byte[] extValue = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
            if (extValue == null) {
                return null;
            }
            AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(X509ExtensionUtil.fromExtensionValue(extValue));
            byte[] keyId = aki.getKeyIdentifier();
            if (keyId == null) {
                return null;
            }
            return toHexString(keyId);
        } catch (Exception e) {
            return null;
        }
    }

    public static List<String> getCertificatePolicyOids(X509Certificate cert) {
        if (cert == null) {
            return List.of();
        }
        try {
            byte[] extValue = cert.getExtensionValue(Extension.certificatePolicies.getId());
            if (extValue == null) {
                return List.of();
            }
            CertificatePolicies policies = CertificatePolicies.getInstance(
                    X509ExtensionUtil.fromExtensionValue(extValue));
            return java.util.Arrays.stream(policies.getPolicyInformation())
                    .map(policy -> policy.getPolicyIdentifier().getId())
                    .toList();
        } catch (Exception exception) {
            return List.of();
        }
    }

    private static String formatKeyUsage(boolean[] keyUsage) {
        List<String> usages = new ArrayList<>();
        // RFC 5280: Key Usage bit indices (0-8)
        if (keyUsage.length > 0 && keyUsage[0]) usages.add("digitalSignature");
        if (keyUsage.length > 1 && keyUsage[1]) usages.add("nonRepudiation");
        if (keyUsage.length > 2 && keyUsage[2]) usages.add("keyEncipherment");
        if (keyUsage.length > 3 && keyUsage[3]) usages.add("dataEncipherment");
        if (keyUsage.length > 4 && keyUsage[4]) usages.add("keyAgreement");
        if (keyUsage.length > 5 && keyUsage[5]) usages.add("keyCertSign");
        if (keyUsage.length > 6 && keyUsage[6]) usages.add("cRLSign");
        if (keyUsage.length > 7 && keyUsage[7]) usages.add("encipherOnly");
        if (keyUsage.length > 8 && keyUsage[8]) usages.add("decipherOnly");

        return usages.isEmpty() ? null : String.join(",", usages);
    }

    private static String toHexString(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x:", b));
        }
        if (sb.length() > 0) {
            sb.setLength(sb.length() - 1);  // Remove trailing colon
        }
        return sb.toString();
    }

    private static Integer resolveKeySize(PublicKey key) {
        if (key == null) {
            return null;
        }
        if (key instanceof RSAKey rsa) {
            return rsa.getModulus() != null ? rsa.getModulus().bitLength() : null;
        }
        if (key instanceof ECKey ec) {
            return ec.getParams() != null && ec.getParams().getOrder() != null
                    ? ec.getParams().getOrder().bitLength()
                    : null;
        }
        if (key instanceof DSAKey dsa) {
            return dsa.getParams() != null && dsa.getParams().getP() != null
                    ? dsa.getParams().getP().bitLength()
                    : null;
        }
        return null;
    }
}
