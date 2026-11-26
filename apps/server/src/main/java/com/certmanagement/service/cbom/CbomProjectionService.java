// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cbom;

import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CertificateRepository.CbomCertificateRow;
import lombok.RequiredArgsConstructor;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CertificateProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.CryptoFunction;
import org.cyclonedx.model.component.crypto.enums.Primitive;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.OutputStream;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
public class CbomProjectionService {

    private final CertificateRepository certificateRepository;

    /**
     * Streams the organisation's CBOM (CycloneDX 1.6) to {@code out}: one certificate component
     * per row as it is scrolled, then one deduplicated algorithm component per distinct
     * signature algorithm, key size and curve. Memory is bounded by the fetch size plus the
     * distinct algorithms; nothing per certificate is retained.
     */
    @Transactional(readOnly = true)
    public void writeCbom(Long organizationId, OutputStream out) throws IOException {
        Bom envelope = new Bom();
        envelope.setVersion(1);
        Metadata metadata = new Metadata();
        metadata.setTimestamp(Date.from(OffsetDateTime.now(ZoneOffset.UTC).toInstant()));
        envelope.setMetadata(metadata);

        Map<String, Component> algorithms = new LinkedHashMap<>();
        try (Stream<CbomCertificateRow> rows = certificateRepository.streamCbomRowsByOrganizationId(organizationId);
             CycloneDxJsonWriter writer = new CycloneDxJsonWriter(envelope, out)) {
            for (Iterator<CbomCertificateRow> it = rows.iterator(); it.hasNext(); ) {
                CbomCertificateRow row = it.next();
                String algoRef = null;
                if (row.getSignatureAlgorithm() != null) {
                    algoRef = algorithms
                            .computeIfAbsent(algoKey(row), key -> buildAlgorithmComponent(key, row))
                            .getBomRef();
                }
                writer.write(buildCertificateComponent(row, algoRef));
            }
            for (Component algorithm : algorithms.values()) {
                writer.write(algorithm);
            }
            writer.finish();
        }
    }

    /** Deduplication key for an algorithm: algorithm name + key size + curve. */
    private String algoKey(CbomCertificateRow row) {
        String size  = row.getKeySize() != null ? row.getKeySize().toString() : "";
        String curve = row.getPublicKeyCurve() != null ? row.getPublicKeyCurve() : "";
        return row.getSignatureAlgorithm() + "|" + size + "|" + curve;
    }

    /**
     * Builds a CycloneDX 1.6 CERTIFICATE cryptographic asset component.
     * Uses CertificateProperties for structured cert metadata and keeps
     * extended fields (key usage, SKI, AKI) in custom properties.
     */
    private Component buildCertificateComponent(CbomCertificateRow cert, String algoRef) {
        Component component = new Component();
        component.setType(Component.Type.CRYPTOGRAPHIC_ASSET);
        component.setBomRef(cert.getCertificateXref());

        String domain = cert.getDomain() != null ? cert.getDomain() : "unknown-domain";
        component.setName(cert.getCommonName() != null ? cert.getCommonName() : domain);

        component.setPurl("pkg:x509/" + domain + "@" + cert.getCertificateXref());

        if (cert.getFingerprintSha256() != null) {
            component.setHashes(List.of(new Hash(Hash.Algorithm.SHA_256, cert.getFingerprintSha256())));
        }

        // Structured CycloneDX cryptoProperties for certificates
        CryptoProperties cryptoProps = new CryptoProperties();
        cryptoProps.setAssetType(AssetType.CERTIFICATE);

        CertificateProperties certProps = new CertificateProperties();
        certProps.setCertificateFormat("X.509");

        if (cert.getSubjectDn() != null) {
            certProps.setSubjectName(cert.getSubjectDn());
        }
        if (cert.getIssuer() != null) {
            certProps.setIssuerName(cert.getIssuer());
        }
        if (cert.getValidFrom() != null) {
            certProps.setNotValidBefore(cert.getValidFrom().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
        }
        if (cert.getValidTo() != null) {
            certProps.setNotValidAfter(cert.getValidTo().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
        }
        // Link to sibling algorithm component — omitted when no crypto metadata exists yet
        if (algoRef != null) {
            certProps.setSignatureAlgorithmRef(algoRef);
        }

        cryptoProps.setCertificateProperties(certProps);
        component.setCryptoProperties(cryptoProps);

        // Extended fields that don't have a dedicated spot in CertificateProperties go in custom properties
        List<Property> properties = new ArrayList<>();
        addProp(properties, "certping:certificateXref", cert.getCertificateXref());
        addProp(properties, "certping:caProvider",
                cert.getCaProvider() != null ? cert.getCaProvider().name() : null);
        addProp(properties, "certping:serialNumber", cert.getSerialNumber());
        addProp(properties, "certping:keyUsage", cert.getKeyUsage());
        addProp(properties, "certping:extendedKeyUsage", cert.getExtendedKeyUsage());
        addProp(properties, "certping:subjectKeyIdentifier", cert.getSubjectKeyIdentifier());
        addProp(properties, "certping:authorityKeyIdentifier", cert.getAuthorityKeyIdentifier());
        if (!properties.isEmpty()) {
            component.setProperties(properties);
        }

        return component;
    }

    /**
     * Builds a CycloneDX 1.6 ALGORITHM cryptographic asset component linked to the certificate.
     * Includes nistQuantumSecurityLevel — the key field for PQC readiness assessment.
     */
    private Component buildAlgorithmComponent(String algoKey, CbomCertificateRow cert) {
        Component component = new Component();
        component.setType(Component.Type.CRYPTOGRAPHIC_ASSET);
        // bom-ref is derived from the algo key so all certs sharing this algorithm ref the same component
        component.setBomRef("algo-" + algoKey.replace("|", "-").replaceAll("-+$", ""));
        component.setName(cert.getSignatureAlgorithm());

        CryptoProperties cryptoProps = new CryptoProperties();
        cryptoProps.setAssetType(AssetType.ALGORITHM);

        if (cert.getSignatureAlgorithmOid() != null) {
            cryptoProps.setOid(cert.getSignatureAlgorithmOid());
        }

        AlgorithmProperties algoProps = new AlgorithmProperties();
        algoProps.setPrimitive(resolvePrimitive(cert.getPublicKeyAlgorithm()));
        algoProps.setCryptoFunctions(List.of(CryptoFunction.SIGN, CryptoFunction.VERIFY));

        if (cert.getKeySize() != null) {
            algoProps.setParameterSetIdentifier(cert.getKeySize().toString());
        }
        if (cert.getPublicKeyCurve() != null) {
            algoProps.setCurve(cert.getPublicKeyCurve());
        }

        algoProps.setNistQuantumSecurityLevel(resolveNistQuantumLevel(
                cert.getPublicKeyAlgorithm(),
                cert.getSignatureAlgorithm(),
                cert.getKeySize()));

        cryptoProps.setAlgorithmProperties(algoProps);
        component.setCryptoProperties(cryptoProps);

        return component;
    }

    /**
     * Maps a public key algorithm name to a CycloneDX Primitive.
     * RSA and EC are classical signature primitives. PQC algorithms map to their own primitives.
     */
    private Primitive resolvePrimitive(String publicKeyAlgorithm) {
        if (publicKeyAlgorithm == null) return Primitive.UNKNOWN;
        return switch (publicKeyAlgorithm.toUpperCase()) {
            case "RSA"   -> Primitive.SIGNATURE;
            case "EC",
                 "ECDSA" -> Primitive.SIGNATURE;
            case "DSA"   -> Primitive.SIGNATURE;
            case "ED25519",
                 "ED448" -> Primitive.SIGNATURE;
            // NIST PQC winners
            case "DILITHIUM",
                 "ML-DSA"  -> Primitive.SIGNATURE;
            case "FALCON"  -> Primitive.SIGNATURE;
            case "SPHINCS+",
                 "SLH-DSA" -> Primitive.SIGNATURE;
            default      -> Primitive.UNKNOWN;
        };
    }

    /**
     * Returns the NIST Quantum Security Level (0–5) for the given algorithm.
     * Level 0 = no quantum security (classical). Levels 1–5 = NIST PQC security levels.
     * This is the source value for PQC readiness scoring.
     *
     * Classical algorithms (RSA, EC, DSA) always return 0 — they offer no quantum resistance.
     * NIST PQC algorithms return their certified security level.
     */
    private int resolveNistQuantumLevel(String publicKeyAlgorithm,
                                        String signatureAlgorithm,
                                        Integer keySize) {
        if (publicKeyAlgorithm == null) return 0;

        String algo = publicKeyAlgorithm.toUpperCase();

        // NIST PQC standards (FIPS 204 / 205 / 206)
        if (algo.contains("DILITHIUM") || algo.contains("ML-DSA")) {
            return resolveMLDSALevel(signatureAlgorithm);
        }
        if (algo.contains("FALCON") || algo.contains("FN-DSA")) {
            return resolveFalconLevel(signatureAlgorithm);
        }
        if (algo.contains("SPHINCS") || algo.contains("SLH-DSA")) {
            return resolveSlhDsaLevel(signatureAlgorithm);
        }

        // All classical algorithms offer zero quantum security
        return 0;
    }

    private int resolveMLDSALevel(String sigAlg) {
        if (sigAlg == null) return 0;
        String s = sigAlg.toUpperCase();
        if (s.contains("44") || s.contains("2"))  return 2;  // ML-DSA-44 → Level 2
        if (s.contains("65") || s.contains("3"))  return 3;  // ML-DSA-65 → Level 3
        if (s.contains("87") || s.contains("5"))  return 5;  // ML-DSA-87 → Level 5
        return 2; // default for any Dilithium/ML-DSA
    }

    private int resolveFalconLevel(String sigAlg) {
        if (sigAlg == null) return 0;
        String s = sigAlg.toUpperCase();
        if (s.contains("512"))  return 1; // Falcon-512  → Level 1
        if (s.contains("1024")) return 5; // Falcon-1024 → Level 5
        return 1;
    }

    private int resolveSlhDsaLevel(String sigAlg) {
        if (sigAlg == null) return 0;
        String s = sigAlg.toUpperCase();
        // SLH-DSA-128 variants → Level 1, 192 → Level 3, 256 → Level 5
        if (s.contains("128")) return 1;
        if (s.contains("192")) return 3;
        if (s.contains("256")) return 5;
        return 1;
    }

    private void addProp(List<Property> properties, String name, String value) {
        if (value == null || value.isBlank()) return;
        Property prop = new Property();
        prop.setName(name);
        prop.setValue(value);
        properties.add(prop);
    }
}
