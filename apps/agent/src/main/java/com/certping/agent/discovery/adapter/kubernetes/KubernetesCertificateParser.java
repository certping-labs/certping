// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import io.kubernetes.client.openapi.models.V1Secret;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.naming.ldap.LdapName;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
class KubernetesCertificateParser {

    private static final String TLS_SECRET_TYPE = "kubernetes.io/tls";
    private static final String TLS_CRT_KEY = "tls.crt";
    private static final int MAX_CERTIFICATE_INPUT_BYTES = 1024 * 1024;
    private static final int MAX_CERTIFICATES_PER_BUNDLE = 20;

    List<KubernetesParsedCertificate> parseTlsSecrets(String clusterName, List<V1Secret> secrets) {
        List<KubernetesParsedCertificate> parsed = new ArrayList<>();
        for (V1Secret secret : secrets) {
            if (!TLS_SECRET_TYPE.equals(secret.getType())) {
                continue;
            }
            String namespace = secret.getMetadata() != null ? secret.getMetadata().getNamespace() : "<unknown>";
            String name = secret.getMetadata() != null ? secret.getMetadata().getName() : "<unknown>";
            List<String> warnings = new ArrayList<>();
            byte[] certBytes = tlsCertificateBytes(secret);
            if (certBytes == null || certBytes.length == 0) {
                warnings.add("TLS Secret " + namespace + "/" + name + " is missing tls.crt");
                log.warn("Skipping Kubernetes TLS Secret with missing tls.crt namespace={} secretName={}", namespace, name);
                continue;
            }
            try {
                X509Certificate certificate = parseLeafCertificate(certBytes);
                String fingerprint = fingerprintSha256(certificate);
                parsed.add(KubernetesParsedCertificate.fromSecret(clusterName, secret, certificate, fingerprint, warnings));
            } catch (Exception e) {
                log.warn("Skipping Kubernetes TLS Secret with unparsable certificate namespace={} secretName={} failureType={}",
                        namespace, name, e.getClass().getSimpleName());
            }
        }
        parsed.sort(Comparator.comparing(KubernetesParsedCertificate::namespace)
                .thenComparing(KubernetesParsedCertificate::name));
        return parsed;
    }

    KubernetesCertificateMetadata metadataFor(X509Certificate certificate) {
        List<String> sans = dnsSans(certificate);
        String commonName = commonName(certificate);
        String domain = !sans.isEmpty() ? sans.get(0) : commonName;
        return new KubernetesCertificateMetadata(
                domain,
                keyAlgorithm(certificate),
                certificate.getSigAlgName(),
                certificate.getNotBefore().toInstant().toString(),
                certificate.getNotAfter().toInstant().toString(),
                certificate.getIssuerX500Principal().getName(),
                serialNumber(certificate.getSerialNumber()),
                status(certificate),
                certificate.getSubjectX500Principal().getName(),
                sans,
                keyUsage(certificate),
                extendedKeyUsage(certificate));
    }

    KubernetesParsedCertificate parseInlineCustomResourceCertificate(String clusterName,
            String apiVersion,
            String kind,
            String namespace,
            String name,
            String uid,
            String resourceVersion,
            String fieldPath,
            String certificatePem) {
        if (certificatePem == null || certificatePem.isBlank()) {
            return null;
        }
        try {
            X509Certificate certificate = parseLeafCertificate(certificatePem.getBytes(StandardCharsets.UTF_8));
            return KubernetesParsedCertificate.fromInlineCustomResource(
                    clusterName,
                    apiVersion,
                    kind,
                    namespace,
                    name,
                    uid,
                    resourceVersion,
                    fieldPath,
                    certificate,
                    fingerprintSha256(certificate),
                    List.of());
        } catch (Exception e) {
            log.warn("Skipping Kubernetes inline certificate with unparsable certificate apiVersion={} kind={} namespace={} name={} fieldPath={} failureType={}",
                    apiVersion, kind, namespace, name, fieldPath, e.getClass().getSimpleName());
            return null;
        }
    }

    private byte[] tlsCertificateBytes(V1Secret secret) {
        Map<String, byte[]> data = secret.getData();
        if (data == null || !data.containsKey(TLS_CRT_KEY)) {
            return null;
        }
        return data.get(TLS_CRT_KEY);
    }

    private X509Certificate parseLeafCertificate(byte[] certBytes) throws Exception {
        if (certBytes.length > MAX_CERTIFICATE_INPUT_BYTES) {
            throw new IllegalArgumentException("certificate input exceeds size limit");
        }
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> parsed;
        try {
            parsed = factory.generateCertificates(new ByteArrayInputStream(certBytes));
        } catch (CertificateException directParseFailure) {
            byte[] decoded = Base64.getMimeDecoder().decode(certBytes);
            if (decoded.length > MAX_CERTIFICATE_INPUT_BYTES) {
                throw new IllegalArgumentException("decoded certificate input exceeds size limit");
            }
            parsed = factory.generateCertificates(new ByteArrayInputStream(decoded));
        }
        List<X509Certificate> certificates = parsed.stream()
                .filter(X509Certificate.class::isInstance)
                .map(X509Certificate.class::cast)
                .toList();
        if (certificates.isEmpty()) {
            throw new IllegalArgumentException("no X.509 certificates found");
        }
        if (certificates.size() > MAX_CERTIFICATES_PER_BUNDLE) {
            throw new IllegalArgumentException("certificate bundle exceeds certificate count limit");
        }
        return selectLeafCertificate(certificates);
    }

    private X509Certificate selectLeafCertificate(List<X509Certificate> certificates) {
        for (X509Certificate candidate : certificates) {
            boolean issuesAnotherCertificate = certificates.stream()
                    .filter(other -> other != candidate)
                    .anyMatch(other -> candidate.getSubjectX500Principal().equals(other.getIssuerX500Principal()));
            if (!issuesAnotherCertificate) {
                return candidate;
            }
        }
        return certificates.stream()
                .filter(certificate -> certificate.getBasicConstraints() < 0)
                .findFirst()
                .orElse(certificates.get(0));
    }

    private String fingerprintSha256(X509Certificate certificate) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
        return colonHex(digest).toUpperCase(java.util.Locale.ROOT);
    }

    private String keyAlgorithm(X509Certificate certificate) {
        PublicKey publicKey = certificate.getPublicKey();
        if (publicKey == null) {
            return null;
        }
        String algorithm = publicKey.getAlgorithm();
        Integer size = null;
        if (publicKey instanceof RSAKey rsa && rsa.getModulus() != null) {
            size = rsa.getModulus().bitLength();
        } else if (publicKey instanceof ECKey ec && ec.getParams() != null && ec.getParams().getOrder() != null) {
            size = ec.getParams().getOrder().bitLength();
        }
        return size == null ? algorithm : algorithm + "-" + size;
    }

    private String status(X509Certificate certificate) {
        Instant now = Instant.now();
        if (certificate.getNotAfter().toInstant().isBefore(now)) {
            return "EXPIRED";
        }
        if (certificate.getNotBefore().toInstant().isAfter(now)) {
            return "NOT_YET_VALID";
        }
        return "ISSUED";
    }

    private String serialNumber(BigInteger serial) {
        if (serial == null) {
            return null;
        }
        String hex = serial.toString(16);
        if (hex.length() % 2 != 0) {
            hex = "0" + hex;
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            if (out.length() > 0) {
                out.append(':');
            }
            out.append(hex, i, i + 2);
        }
        return out.toString().toUpperCase(java.util.Locale.ROOT);
    }

    private List<String> dnsSans(X509Certificate certificate) {
        try {
            Collection<List<?>> names = certificate.getSubjectAlternativeNames();
            if (names == null) {
                return List.of();
            }
            List<String> out = new ArrayList<>();
            for (List<?> name : names) {
                if (name != null && name.size() >= 2 && Integer.valueOf(2).equals(name.get(0)) && name.get(1) instanceof String dns) {
                    out.add(dns.toLowerCase(java.util.Locale.ROOT));
                }
            }
            return out.stream().distinct().sorted().toList();
        } catch (Exception e) {
            return List.of();
        }
    }

    private String commonName(X509Certificate certificate) {
        try {
            LdapName ldapName = new LdapName(certificate.getSubjectX500Principal().getName());
            return ldapName.getRdns().stream()
                    .filter(rdn -> "CN".equalsIgnoreCase(rdn.getType()))
                    .map(rdn -> rdn.getValue() == null ? null : rdn.getValue().toString())
                    .filter(value -> value != null && !value.isBlank())
                    .findFirst()
                    .orElse(null);
        } catch (Exception e) {
            return null;
        }
    }

    private String keyUsage(X509Certificate certificate) {
        boolean[] usage = certificate.getKeyUsage();
        if (usage == null) {
            return null;
        }
        List<String> values = new ArrayList<>();
        if (usage.length > 0 && usage[0]) values.add("digitalSignature");
        if (usage.length > 1 && usage[1]) values.add("nonRepudiation");
        if (usage.length > 2 && usage[2]) values.add("keyEncipherment");
        if (usage.length > 3 && usage[3]) values.add("dataEncipherment");
        if (usage.length > 4 && usage[4]) values.add("keyAgreement");
        if (usage.length > 5 && usage[5]) values.add("keyCertSign");
        if (usage.length > 6 && usage[6]) values.add("cRLSign");
        if (usage.length > 7 && usage[7]) values.add("encipherOnly");
        if (usage.length > 8 && usage[8]) values.add("decipherOnly");
        return values.isEmpty() ? null : String.join(",", values);
    }

    private String extendedKeyUsage(X509Certificate certificate) {
        try {
            List<String> usage = certificate.getExtendedKeyUsage();
            return usage == null || usage.isEmpty() ? null : String.join(",", usage);
        } catch (Exception e) {
            return null;
        }
    }

    private String colonHex(byte[] bytes) {
        StringBuilder out = new StringBuilder();
        for (byte b : bytes) {
            if (out.length() > 0) {
                out.append(':');
            }
            out.append(String.format("%02x", b));
        }
        return out.toString();
    }
}
