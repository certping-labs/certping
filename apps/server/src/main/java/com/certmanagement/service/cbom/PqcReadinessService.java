// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cbom;

import com.certmanagement.dto.pqc.PqcReadinessReport;
import com.certmanagement.dto.pqc.PqcReadinessReport.AlgorithmGroup;
import com.certmanagement.dto.pqc.PqcReadinessReport.CertDetail;
import com.certmanagement.dto.pqc.PqcReadinessReport.HndlRisk;
import com.certmanagement.dto.pqc.PqcReadinessReport.QuantumStatus;
import com.certmanagement.dto.pqc.PqcReadinessReport.Summary;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CertificateRepository.PqcAlgorithmCount;
import com.certmanagement.repository.CertificateRepository.PqcCertificateRow;
import com.certmanagement.repository.DiscoveredCertRepository;
import com.certmanagement.repository.DiscoveredCertRepository.PqcDiscoveredAlgorithmCount;
import com.certmanagement.repository.DiscoveredCertRepository.PqcDiscoveredRow;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.event.TransactionalEventListener;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.certmanagement.config.CacheConfig.PQC_SUMMARY;

/**
 * Generates a PQC readiness report for an organisation's certificate inventory.
 *
 * Classification follows NIST IR 8547 (Nov 2024) terminology and deprecation timelines:
 *   - Quantum-vulnerable algorithms are deprecated after 2030 (112-bit) or disallowed after 2035 (≥128-bit).
 *   - NIST-approved PQC algorithms (FIPS 203/204/205) are classified as PQC_COMPLIANT.
 *
 * HNDL (Harvest Now Decrypt Later) risk is derived from the keyUsage extension per
 * CISA Quantum Readiness guidance and OMB M-23-02 inventory requirements.
 *
 * References:
 *   NIST IR 8547: https://csrc.nist.gov/pubs/ir/8547/ipd
 *   CISA Quantum Readiness: https://www.cisa.gov/sites/default/files/2023-08/Quantum%20Readiness_Final_CLEAR_508c%20(3).pdf
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PqcReadinessService {

    private static final String COMPLIANCE_REF = "NIST IR 8547 (Nov 2024)";

    static final String SOURCE_MANAGED = "MANAGED";
    static final String SOURCE_DISCOVERED = "DISCOVERED";
    private static final Sort DISCOVERED_ORDER = Sort.by(Sort.Direction.DESC, "createdAt").and(Sort.by("id"));
    /** Discovery reports keys as EC-256 (Kubernetes), RSA_2048 or EC_prime256v1 (ACM), RSA-HSM (Key Vault). */
    private static final Pattern DISCOVERED_KEY =
            Pattern.compile("^(RSA|EC|ECDSA)(?:[-_ ](.+))?$", Pattern.CASE_INSENSITIVE);

    private final CertificateRepository certificateRepository;
    private final DiscoveredCertRepository discoveredCertRepository;

    public record KeyParts(String algorithm, Integer keySize, String curve) {}

    /**
     * Counters and per-algorithm groups over the org's current managed certificates and the discovered ones
     * CertPing does not manage; cached per organization and cleared whenever either inventory changes.
     */
    @Cacheable(cacheNames = PQC_SUMMARY, key = "#organizationId")
    public PqcReadinessReport summary(Long organizationId) {
        long[] counters = new long[6];
        Map<String, AlgorithmGroup> groups = new LinkedHashMap<>();

        for (PqcAlgorithmCount row : certificateRepository.countPqcAlgorithmsByOrganizationId(organizationId)) {
            tally(new KeyParts(row.getPublicKeyAlgorithm(), row.getKeySize(), row.getCurve()),
                    row.getKeyUsage(), row.getCount(), counters, groups);
        }
        for (PqcDiscoveredAlgorithmCount row
                : discoveredCertRepository.countPqcAlgorithmsByOrganizationId(organizationId)) {
            tally(parseDiscoveredKey(row.getKeyAlgorithm()), row.getKeyUsage(), row.getCount(), counters, groups);
        }

        Summary summary = new Summary((int) counters[0], (int) counters[1], (int) counters[2],
                (int) counters[3], (int) counters[4], (int) counters[5]);
        return new PqcReadinessReport(summary, List.copyOf(groups.values()));
    }

    private void tally(KeyParts key, String keyUsage, long count, long[] counters, Map<String, AlgorithmGroup> groups) {
        QuantumStatus status = classify(key);
        counters[0] += count;
        switch (status) {
            case PQC_COMPLIANT   -> counters[1] += count;
            case DEPRECATED_2030 -> counters[2] += count;
            case DISALLOWED_2035 -> counters[3] += count;
            case UNKNOWN         -> counters[4] += count;
        }
        if (resolveHndlRisk(keyUsage) == HndlRisk.HIGH) counters[5] += count;

        groups.merge(
                algorithmKey(key.algorithm(), key.keySize(), key.curve()),
                new AlgorithmGroup(key.algorithm(), key.keySize(), key.curve(),
                        status, deprecationYearFor(status), disallowedYearFor(status), count),
                (a, b) -> a.plus(b.certificates()));
    }

    /** Managed certificates first, then discovered ones, as one paged list. */
    public Page<CertDetail> certificates(Long organizationId, QuantumStatus status, Pageable pageable) {
        List<String> algorithmKeys = null;
        List<String> discoveredKeys = null;
        if (status != null) {
            algorithmKeys = certificateRepository.countPqcAlgorithmsByOrganizationId(organizationId).stream()
                    .filter(row -> classify(row.getPublicKeyAlgorithm(), row.getKeySize(), row.getCurve()) == status)
                    .map(row -> algorithmKey(row.getPublicKeyAlgorithm(), row.getKeySize(), row.getCurve()))
                    .distinct()
                    .toList();
            discoveredKeys = discoveredCertRepository.countPqcAlgorithmsByOrganizationId(organizationId).stream()
                    .filter(row -> classify(parseDiscoveredKey(row.getKeyAlgorithm())) == status)
                    .map(row -> Objects.toString(row.getKeyAlgorithm(), ""))
                    .distinct()
                    .toList();
            if (algorithmKeys.isEmpty() && discoveredKeys.isEmpty()) return Page.empty(pageable);
        }

        Page<CertDetail> managed = algorithmKeys != null && algorithmKeys.isEmpty()
                ? Page.empty(pageable)
                : certificateRepository.findPqcRowsByOrganizationId(organizationId, algorithmKeys, pageable)
                        .map(this::toDetail);
        long discoveredTotal = discoveredKeys != null && discoveredKeys.isEmpty()
                ? 0 : discoveredCertRepository.countPqcRowsByOrganizationId(organizationId, discoveredKeys);

        List<CertDetail> content = new ArrayList<>(managed.getContent());
        int missing = pageable.getPageSize() - content.size();
        if (missing > 0 && discoveredTotal > 0) {
            long start = Math.max(0, pageable.getOffset() - managed.getTotalElements());
            content.addAll(discoveredDetails(organizationId, discoveredKeys, start, missing));
        }
        return new PageImpl<>(content, pageable, managed.getTotalElements() + discoveredTotal);
    }

    /** {@code count} discovered rows from offset {@code start}, in at most two page-aligned reads. */
    private List<CertDetail> discoveredDetails(Long organizationId, Collection<String> keys, long start, int count) {
        List<CertDetail> details = new ArrayList<>(count);
        int pageIndex = (int) (start / count);
        long skip = start % count;
        while (details.size() < count) {
            List<PqcDiscoveredRow> rows = discoveredCertRepository.findPqcRowsByOrganizationId(
                    organizationId, keys, PageRequest.of(pageIndex++, count, DISCOVERED_ORDER));
            rows.stream().skip(skip).limit(count - details.size()).map(this::toDetail).forEach(details::add);
            if (rows.size() < count) break;
            skip = 0;
        }
        return details;
    }

    @CacheEvict(cacheNames = PQC_SUMMARY, allEntries = true)
    @TransactionalEventListener(fallbackExecution = true)
    public void onCertificateInventoryChanged(CertificateInventoryChangedEvent event) {
        log.debug("Cleared PQC summary cache after certificate inventory change");
    }

    private CertDetail toDetail(PqcCertificateRow row) {
        return detail(row.getCertificateXref(), resolveDisplayName(row), row.getSignatureAlgorithm(),
                new KeyParts(row.getPublicKeyAlgorithm(), row.getKeySize(), row.getCurve()),
                row.getKeyUsage(), SOURCE_MANAGED);
    }

    private CertDetail toDetail(PqcDiscoveredRow row) {
        String name = row.getDomain() != null ? row.getDomain() : commonNameOf(row.getSubjectDn());
        return detail(row.getResourceId(), name != null ? name : row.getResourceId(), row.getSignatureAlgorithm(),
                parseDiscoveredKey(row.getKeyAlgorithm()), row.getKeyUsage(), SOURCE_DISCOVERED);
    }

    private CertDetail detail(String reference, String name, String signatureAlgorithm, KeyParts key,
                              String keyUsage, String source) {
        QuantumStatus status = classify(key);
        HndlRisk hndlRisk = resolveHndlRisk(keyUsage);
        return new CertDetail(
                reference,
                name,
                signatureAlgorithm,
                key.algorithm(),
                key.keySize(),
                key.curve(),
                status,
                hndlRisk,
                deprecationYearFor(status),
                disallowedYearFor(status),
                complianceRefFor(status),
                remediationAdvice(status, hndlRisk),
                source);
    }

    public static KeyParts parseDiscoveredKey(String raw) {
        if (raw == null || raw.isBlank()) return new KeyParts(null, null, null);
        Matcher matcher = DISCOVERED_KEY.matcher(raw.trim());
        if (!matcher.matches()) return new KeyParts(raw.trim(), null, null);
        String algorithm = matcher.group(1).toUpperCase(Locale.ROOT);
        String rest = matcher.group(2);
        if (rest == null || rest.equalsIgnoreCase("HSM")) return new KeyParts(algorithm, null, null);
        if (rest.chars().allMatch(Character::isDigit)) return new KeyParts(algorithm, Integer.valueOf(rest), null);
        return new KeyParts(algorithm, null, rest);
    }

    private static String commonNameOf(String subjectDn) {
        if (subjectDn == null) return null;
        for (String part : subjectDn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.regionMatches(true, 0, "CN=", 0, 3)) return trimmed.substring(3);
        }
        return null;
    }

    private QuantumStatus classify(KeyParts key) {
        return classify(key.algorithm(), key.keySize(), key.curve());
    }

    /** Mirrors the {@code algorithm|keySize|curve} expression in the repository's key filter. */
    private static String algorithmKey(String publicKeyAlgorithm, Integer keySize, String curve) {
        return Objects.toString(publicKeyAlgorithm, "") + "|"
                + (keySize == null ? "" : keySize) + "|"
                + Objects.toString(curve, "");
    }

    /**
     * Classifies a certificate's public key algorithm into a NIST IR 8547 aligned quantum status.
     *
     * NIST IR 8547 Table 2/3 deprecation schedule:
     *   - RSA / ECDSA at 112-bit security (RSA-2048, ECDSA P-224): Deprecated after 2030, Disallowed after 2035
     *   - RSA / ECDSA / EdDSA at ≥128-bit security (RSA-3072+, ECDSA P-256/P-384/P-521, Ed25519, Ed448): Disallowed after 2035
     *   - NIST PQC (ML-DSA, SLH-DSA, ML-KEM, FN-DSA): PQC_COMPLIANT
     */
    public QuantumStatus classify(String publicKeyAlgorithm, Integer keySize, String curve) {
        if (publicKeyAlgorithm == null) return QuantumStatus.UNKNOWN;

        String algo = publicKeyAlgorithm.toUpperCase();

        // NIST-approved PQC algorithms (FIPS 203/204/205 and derivatives)
        if (algo.contains("ML-DSA") || algo.contains("DILITHIUM")
                || algo.contains("ML-KEM") || algo.contains("KYBER")
                || algo.contains("SLH-DSA") || algo.contains("SLHDSA") || algo.contains("SPHINCS")
                || algo.contains("FALCON") || algo.contains("FN-DSA")
                || algo.contains("LMS") || algo.contains("XMSS")) {
            return QuantumStatus.PQC_COMPLIANT;
        }

        // RSA: 112-bit security = RSA-2048 (deprecated after 2030); ≥128-bit = RSA-3072+ (disallowed after 2035)
        if (algo.equals("RSA")) {
            if (keySize != null && keySize >= 3072) return QuantumStatus.DISALLOWED_2035;
            return QuantumStatus.DEPRECATED_2030;
        }

        // EC/ECDSA: P-224 is 112-bit (deprecated after 2030); P-256/384/521 are ≥128-bit (disallowed after 2035)
        if (algo.equals("EC") || algo.equals("ECDSA")) {
            int ecSize = resolveEcKeySize(keySize, curve);
            if (ecSize > 0 && ecSize <= 224) return QuantumStatus.DEPRECATED_2030;
            return QuantumStatus.DISALLOWED_2035;
        }

        // EdDSA — Ed25519 (128-bit) and Ed448 (224-bit) are both disallowed after 2035 per NIST IR 8547
        if (algo.equals("ED25519") || algo.equals("ED448") || algo.equals("EDDSA")) {
            return QuantumStatus.DISALLOWED_2035;
        }

        // DSA — deprecated in SP 800-131A, disallowed after 2030
        if (algo.equals("DSA")) return QuantumStatus.DEPRECATED_2030;

        return QuantumStatus.UNKNOWN;
    }

    /**
     * Determines HNDL risk from the keyUsage extension.
     *
     * Per CISA / OMB M-23-02: cryptographic systems must report their service type:
     * (a) creation and exchange of encryption keys, (b) encrypted connections,
     * or (c) creation and validation of digital signatures.
     *
     * Key-exchange certs (keyEncipherment, keyAgreement) are vulnerable to
     * Harvest Now Decrypt Later attacks today, regardless of deprecation timeline.
     */
    public HndlRisk resolveHndlRisk(String keyUsage) {
        if (keyUsage == null || keyUsage.isBlank()) return HndlRisk.UNKNOWN;
        String ku = keyUsage.toUpperCase();
        if (ku.contains("KEYENCIPHERMENT") || ku.contains("KEY_ENCIPHERMENT")
                || ku.contains("KEYAGREEMENT") || ku.contains("KEY_AGREEMENT")) {
            return HndlRisk.HIGH;
        }
        return HndlRisk.LOW;
    }

    private String remediationAdvice(QuantumStatus status, HndlRisk hndlRisk) {
        String hndlNote = hndlRisk == HndlRisk.HIGH
                ? " This certificate is used for key exchange and is vulnerable to Harvest Now Decrypt Later (HNDL) attacks today — treat as high priority."
                : "";

        return switch (status) {
            case PQC_COMPLIANT ->
                    "No action required. Certificate uses a NIST-approved post-quantum algorithm (FIPS 203/204/205).";
            case DEPRECATED_2030 ->
                    "Algorithm is deprecated by NIST after 2030 and disallowed after 2035 (NIST IR 8547). "
                    + "Plan migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) before 2030." + hndlNote;
            case DISALLOWED_2035 ->
                    "Algorithm is disallowed by NIST after 2035 (NIST IR 8547). "
                    + "Plan migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) before 2035." + hndlNote;
            case UNKNOWN ->
                    "Algorithm data not available — certificate was likely issued before cryptographic metadata collection was enabled. "
                    + "Reissue the certificate to populate algorithm details.";
        };
    }

    private Integer deprecationYearFor(QuantumStatus status) {
        return status == QuantumStatus.DEPRECATED_2030 ? 2030 : null;
    }

    private Integer disallowedYearFor(QuantumStatus status) {
        return switch (status) {
            case DEPRECATED_2030 -> 2035;
            case DISALLOWED_2035 -> 2035;
            default -> null;
        };
    }

    private String complianceRefFor(QuantumStatus status) {
        return (status == QuantumStatus.PQC_COMPLIANT || status == QuantumStatus.UNKNOWN)
                ? null : COMPLIANCE_REF;
    }

    private String resolveDisplayName(PqcCertificateRow row) {
        if (row.getCommonName() != null) return row.getCommonName();
        return row.getDomain() != null ? row.getDomain() : row.getCertificateXref();
    }

    private int resolveEcKeySize(Integer keySize, String curve) {
        if (keySize != null) return keySize;
        if (curve == null)   return 0;
        String c = curve.toLowerCase();
        if (c.contains("521") || c.contains("p-521")) return 521;
        if (c.contains("384") || c.contains("p-384")) return 384;
        if (c.contains("256") || c.contains("p-256")) return 256;
        if (c.contains("224") || c.contains("p-224")) return 224;
        return 0;
    }
}
