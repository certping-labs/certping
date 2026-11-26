// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.dto.pqc.PqcReadinessReport;
import com.certmanagement.dto.pqc.PqcReadinessReport.CertDetail;
import com.certmanagement.dto.pqc.PqcReadinessReport.HndlRisk;
import com.certmanagement.dto.pqc.PqcReadinessReport.QuantumStatus;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CertificateRepository.PqcAlgorithmCount;
import com.certmanagement.repository.CertificateRepository.PqcCertificateRow;
import com.certmanagement.repository.DiscoveredCertRepository;
import com.certmanagement.repository.DiscoveredCertRepository.PqcDiscoveredAlgorithmCount;
import com.certmanagement.repository.DiscoveredCertRepository.PqcDiscoveredRow;
import com.certmanagement.service.cbom.PqcReadinessService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PqcReadinessServiceTest {

    @Mock
    private CertificateRepository certificateRepository;

    @Mock
    private DiscoveredCertRepository discoveredCertRepository;

    @InjectMocks
    private PqcReadinessService pqcReadinessService;

    // -------------------------------------------------------------------------
    // classify() — NIST IR 8547 aligned quantum status
    // -------------------------------------------------------------------------

    @ParameterizedTest(name = "RSA keySize={0} → {1}")
    @CsvSource({
        "1024, DEPRECATED_2030",
        "2048, DEPRECATED_2030",
        "3072, DISALLOWED_2035",
        "4096, DISALLOWED_2035",
    })
    void classify_rsa_byKeySize(int keySize, QuantumStatus expected) {
        assertThat(pqcReadinessService.classify("RSA", keySize, null)).isEqualTo(expected);
    }

    @Test
    void classify_rsa_nullKeySize_isDeprecated2030() {
        // null keySize defaults to < 3072 path → DEPRECATED_2030
        assertThat(pqcReadinessService.classify("RSA", null, null)).isEqualTo(QuantumStatus.DEPRECATED_2030);
    }

    @ParameterizedTest(name = "EC keySize={0} curve={1} → {2}")
    @CsvSource({
        "256,  prime256v1, DISALLOWED_2035",
        "384,  secp384r1,  DISALLOWED_2035",
        "521,  secp521r1,  DISALLOWED_2035",
        "224,  secp224r1,  DEPRECATED_2030",
        ",     secp384r1,  DISALLOWED_2035",
        ",     prime256v1, DISALLOWED_2035",
        ",     secp224r1,  DEPRECATED_2030",
        ",     ,           DISALLOWED_2035",
    })
    void classify_ec_byCurve(Integer keySize, String curve, QuantumStatus expected) {
        assertThat(pqcReadinessService.classify("EC", keySize, curve)).isEqualTo(expected);
    }

    @ParameterizedTest(name = "PQC algo={0} → PQC_COMPLIANT")
    @CsvSource({
        "ML-DSA",
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "DILITHIUM",
        "ML-KEM",
        "KYBER",
        "SLH-DSA",
        "SLHDSA",
        "SPHINCS+",
        "FALCON",
        "FN-DSA",
        "LMS",
        "XMSS",
    })
    void classify_pqcAlgorithms_arePqcCompliant(String algo) {
        assertThat(pqcReadinessService.classify(algo, null, null)).isEqualTo(QuantumStatus.PQC_COMPLIANT);
    }

    @Test
    void classify_nullAlgorithm_isUnknown() {
        assertThat(pqcReadinessService.classify(null, 2048, null)).isEqualTo(QuantumStatus.UNKNOWN);
    }

    @Test
    void classify_ed25519_isDisallowed2035() {
        assertThat(pqcReadinessService.classify("ED25519", null, null)).isEqualTo(QuantumStatus.DISALLOWED_2035);
    }

    @Test
    void classify_ed448_isDisallowed2035() {
        assertThat(pqcReadinessService.classify("ED448", null, null)).isEqualTo(QuantumStatus.DISALLOWED_2035);
    }

    @Test
    void classify_dsa_isDeprecated2030() {
        assertThat(pqcReadinessService.classify("DSA", 1024, null)).isEqualTo(QuantumStatus.DEPRECATED_2030);
    }

    // -------------------------------------------------------------------------
    // resolveHndlRisk() — Harvest Now Decrypt Later risk from keyUsage
    // -------------------------------------------------------------------------

    @ParameterizedTest(name = "keyUsage={0} → {1}")
    @CsvSource({
        "keyEncipherment,              HIGH",
        "Key_Encipherment,             HIGH",
        "KEYENCIPHERMENT,              HIGH",
        "keyAgreement,                 HIGH",
        "KEY_AGREEMENT,                HIGH",
        "digitalSignature,             LOW",
        "contentCommitment,            LOW",
        "digitalSignature keyEncipherment, HIGH",
    })
    void resolveHndlRisk_fromKeyUsageString(String keyUsage, HndlRisk expected) {
        assertThat(pqcReadinessService.resolveHndlRisk(keyUsage)).isEqualTo(expected);
    }

    @Test
    void resolveHndlRisk_nullKeyUsage_isUnknown() {
        assertThat(pqcReadinessService.resolveHndlRisk(null)).isEqualTo(HndlRisk.UNKNOWN);
    }

    @Test
    void resolveHndlRisk_blankKeyUsage_isUnknown() {
        assertThat(pqcReadinessService.resolveHndlRisk("  ")).isEqualTo(HndlRisk.UNKNOWN);
    }

    // -------------------------------------------------------------------------
    // summary() — counters and algorithm groups from the aggregate rows
    // -------------------------------------------------------------------------

    @Test
    void summary_mixedAlgorithms_countsEveryRowByItsClassification() {
        when(certificateRepository.countPqcAlgorithmsByOrganizationId(1L)).thenReturn(List.of(
                count("RSA", 2048, null, null, 3),
                count("EC", 384, "secp384r1", null, 2),
                count("ML-DSA", null, null, null, 1),
                count(null, null, null, null, 4)));

        PqcReadinessReport report = pqcReadinessService.summary(1L);

        assertThat(report.summary().total()).isEqualTo(10);
        assertThat(report.summary().deprecated2030()).isEqualTo(3);
        assertThat(report.summary().disallowed2035()).isEqualTo(2);
        assertThat(report.summary().pqcCompliant()).isEqualTo(1);
        assertThat(report.summary().unknown()).isEqualTo(4);
        assertThat(report.summary().highHndlRisk()).isZero();
    }

    @Test
    void summary_highHndlRisk_countsKeyExchangeRows() {
        when(certificateRepository.countPqcAlgorithmsByOrganizationId(1L)).thenReturn(List.of(
                count("RSA", 2048, null, "keyEncipherment", 5),
                count("RSA", 2048, null, "digitalSignature", 2)));

        PqcReadinessReport report = pqcReadinessService.summary(1L);

        assertThat(report.summary().total()).isEqualTo(7);
        assertThat(report.summary().highHndlRisk()).isEqualTo(5);
    }

    @Test
    void summary_mergesRowsThatDifferOnlyByKeyUsageIntoOneAlgorithmGroup() {
        when(certificateRepository.countPqcAlgorithmsByOrganizationId(1L)).thenReturn(List.of(
                count("RSA", 2048, null, "keyEncipherment", 5),
                count("RSA", 2048, null, "digitalSignature", 2),
                count("EC", 256, "prime256v1", null, 1)));

        List<PqcReadinessReport.AlgorithmGroup> groups = pqcReadinessService.summary(1L).algorithms();

        assertThat(groups).hasSize(2);
        assertThat(groups.get(0).publicKeyAlgorithm()).isEqualTo("RSA");
        assertThat(groups.get(0).keySize()).isEqualTo(2048);
        assertThat(groups.get(0).certificates()).isEqualTo(7);
        assertThat(groups.get(0).quantumStatus()).isEqualTo(QuantumStatus.DEPRECATED_2030);
        assertThat(groups.get(0).deprecationYear()).isEqualTo(2030);
        assertThat(groups.get(0).disallowedYear()).isEqualTo(2035);
        assertThat(groups.get(1).curve()).isEqualTo("prime256v1");
        assertThat(groups.get(1).quantumStatus()).isEqualTo(QuantumStatus.DISALLOWED_2035);
        assertThat(groups.get(1).deprecationYear()).isNull();
    }

    @Test
    void summary_noCertificates_isEmpty() {
        when(certificateRepository.countPqcAlgorithmsByOrganizationId(1L)).thenReturn(List.of());

        PqcReadinessReport report = pqcReadinessService.summary(1L);

        assertThat(report.summary().total()).isZero();
        assertThat(report.algorithms()).isEmpty();
    }

    // -------------------------------------------------------------------------
    // certificates() — paged details
    // -------------------------------------------------------------------------

    @Test
    void certificates_withoutStatusFilter_pagesEveryRow() {
        Pageable page = PageRequest.of(0, 2);
        when(certificateRepository.findPqcRowsByOrganizationId(1L, null, page)).thenReturn(new PageImpl<>(
                List.of(row("cert-1", "my.domain.com", "cert-1.example.com", "SHA256withRSA", "RSA", 2048, null, "keyEncipherment"),
                        row("cert-2", null, "cert-2.example.com", "ML-DSA-65", "ML-DSA", null, null, null)),
                page, 5));

        Page<CertDetail> details = pqcReadinessService.certificates(1L, null, page);

        assertThat(details.getTotalElements()).isEqualTo(5);
        CertDetail rsa = details.getContent().get(0);
        assertThat(rsa.commonName()).isEqualTo("my.domain.com");
        assertThat(rsa.publicKeyAlgorithm()).isEqualTo("RSA");
        assertThat(rsa.quantumStatus()).isEqualTo(QuantumStatus.DEPRECATED_2030);
        assertThat(rsa.hndlRisk()).isEqualTo(HndlRisk.HIGH);
        assertThat(rsa.deprecationYear()).isEqualTo(2030);
        assertThat(rsa.disallowedYear()).isEqualTo(2035);
        assertThat(rsa.complianceRef()).contains("NIST IR 8547");
        assertThat(rsa.remediationAdvice()).containsIgnoringCase("Harvest Now Decrypt Later");
        CertDetail pqc = details.getContent().get(1);
        assertThat(pqc.commonName()).isEqualTo("cert-2.example.com");
        assertThat(pqc.quantumStatus()).isEqualTo(QuantumStatus.PQC_COMPLIANT);
        assertThat(pqc.hndlRisk()).isEqualTo(HndlRisk.UNKNOWN);
        assertThat(pqc.deprecationYear()).isNull();
        assertThat(pqc.disallowedYear()).isNull();
        assertThat(pqc.complianceRef()).isNull();
        assertThat(pqc.remediationAdvice()).isNotBlank();
    }

    @Test
    void certificates_displayNameFallsBackToXref() {
        Pageable page = PageRequest.of(0, 1);
        when(certificateRepository.findPqcRowsByOrganizationId(1L, null, page)).thenReturn(new PageImpl<>(
                List.of(row("cert-1", null, null, null, null, null, null, null))));

        CertDetail detail = pqcReadinessService.certificates(1L, null, page).getContent().get(0);

        assertThat(detail.commonName()).isEqualTo("cert-1");
        assertThat(detail.quantumStatus()).isEqualTo(QuantumStatus.UNKNOWN);
    }

    @Test
    void certificates_withStatusFilter_restrictsToMatchingAlgorithmKeys() {
        Pageable page = PageRequest.of(0, 15);
        when(certificateRepository.countPqcAlgorithmsByOrganizationId(1L)).thenReturn(List.of(
                count("RSA", 2048, null, "keyEncipherment", 5),
                count("RSA", 2048, null, "digitalSignature", 2),
                count("EC", 224, "secp224r1", null, 1),
                count("EC", 384, "secp384r1", null, 1),
                count(null, null, null, null, 1)));
        when(certificateRepository.findPqcRowsByOrganizationId(1L, List.of("RSA|2048|", "EC|224|secp224r1"), page))
                .thenReturn(new PageImpl<>(List.of(
                        row("cert-1", null, "a.example.com", "SHA256withRSA", "RSA", 2048, null, null))));

        Page<CertDetail> details = pqcReadinessService.certificates(1L, QuantumStatus.DEPRECATED_2030, page);

        assertThat(details.getContent()).extracting(CertDetail::certificateXref).containsExactly("cert-1");
    }

    @Test
    void certificates_withStatusFilter_unknownMatchesTheNullAlgorithmKey() {
        Pageable page = PageRequest.of(0, 15);
        when(certificateRepository.countPqcAlgorithmsByOrganizationId(1L)).thenReturn(List.of(
                count("RSA", 2048, null, null, 5),
                count(null, null, null, null, 1)));
        when(certificateRepository.findPqcRowsByOrganizationId(1L, List.of("||"), page)).thenReturn(Page.empty(page));

        pqcReadinessService.certificates(1L, QuantumStatus.UNKNOWN, page);

        verify(certificateRepository).findPqcRowsByOrganizationId(1L, List.of("||"), page);
    }

    @Test
    void certificates_withStatusFilterNothingMatches_returnsEmptyPageWithoutQuerying() {
        Pageable page = PageRequest.of(0, 15);
        when(certificateRepository.countPqcAlgorithmsByOrganizationId(1L)).thenReturn(List.of(
                count("RSA", 2048, null, null, 5)));

        Page<CertDetail> details = pqcReadinessService.certificates(1L, QuantumStatus.PQC_COMPLIANT, page);

        assertThat(details).isEmpty();
        verify(certificateRepository, never()).findPqcRowsByOrganizationId(any(), any(), any());
    }

    // -------------------------------------------------------------------------
    // Discovered certificates
    // -------------------------------------------------------------------------

    @ParameterizedTest(name = "{0} -> {1} {2} {3}")
    @CsvSource({
        "EC-256,        EC,      256,  ",
        "RSA-2048,      RSA,     2048, ",
        "RSA_4096,      RSA,     4096, ",
        "EC_prime256v1, EC,      ,     prime256v1",
        "RSA-HSM,       RSA,     ,     ",
        "Ed25519,       Ed25519, ,     ",
    })
    void parseDiscoveredKey_readsEveryDiscoveryFormat(String raw, String algorithm, Integer keySize, String curve) {
        assertThat(PqcReadinessService.parseDiscoveredKey(raw))
                .isEqualTo(new PqcReadinessService.KeyParts(algorithm, keySize, curve));
    }

    @Test
    void summary_addsDiscoveredCertsToTheManagedOnes() {
        when(certificateRepository.countPqcAlgorithmsByOrganizationId(1L)).thenReturn(List.of(
                count("EC", 256, null, null, 2)));
        when(discoveredCertRepository.countPqcAlgorithmsByOrganizationId(1L)).thenReturn(List.of(
                discoveredCount("EC-256", "keyAgreement", 1),
                discoveredCount("RSA_2048", null, 3),
                discoveredCount(null, null, 1)));

        PqcReadinessReport report = pqcReadinessService.summary(1L);

        assertThat(report.summary().total()).isEqualTo(7);
        assertThat(report.summary().disallowed2035()).isEqualTo(3);
        assertThat(report.summary().deprecated2030()).isEqualTo(3);
        assertThat(report.summary().unknown()).isEqualTo(1);
        assertThat(report.summary().highHndlRisk()).isEqualTo(1);
        assertThat(report.algorithms()).extracting(PqcReadinessReport.AlgorithmGroup::certificates)
                .containsExactly(3L, 3L, 1L);
    }

    @Test
    void certificates_fillsThePageAfterTheManagedRowsWithDiscoveredOnes() {
        Pageable page = PageRequest.of(1, 2);
        when(certificateRepository.findPqcRowsByOrganizationId(1L, null, page)).thenReturn(new PageImpl<>(
                List.of(row("m3", null, "m3.example.com", null, "RSA", 2048, null, null)), page, 3));
        when(discoveredCertRepository.countPqcRowsByOrganizationId(1L, null)).thenReturn(4L);
        when(discoveredCertRepository.findPqcRowsByOrganizationId(eq(1L), isNull(), any()))
                .thenReturn(List.of(discoveredRow("k8s/d1", null, "CN=d1.example.com, O=Lab", "EC-256")));

        Page<CertDetail> details = pqcReadinessService.certificates(1L, null, page);

        assertThat(details.getTotalElements()).isEqualTo(7);
        assertThat(details.getContent()).extracting(CertDetail::certificateXref, CertDetail::commonName,
                        CertDetail::source)
                .containsExactly(tuple("m3", "m3.example.com", "MANAGED"),
                        tuple("k8s/d1", "d1.example.com", "DISCOVERED"));
        CertDetail discovered = details.getContent().get(1);
        assertThat(discovered.publicKeyAlgorithm()).isEqualTo("EC");
        assertThat(discovered.keySize()).isEqualTo(256);
        assertThat(discovered.quantumStatus()).isEqualTo(QuantumStatus.DISALLOWED_2035);
        verify(discoveredCertRepository).findPqcRowsByOrganizationId(1L, null,
                PageRequest.of(0, 1, Sort.by(Sort.Direction.DESC, "createdAt").and(Sort.by("id"))));
    }

    @Test
    void certificates_pastTheManagedRowsReadsDiscoveredFromTheRightOffset() {
        Pageable page = PageRequest.of(2, 2);
        Sort order = Sort.by(Sort.Direction.DESC, "createdAt").and(Sort.by("id"));
        when(certificateRepository.findPqcRowsByOrganizationId(1L, null, page))
                .thenReturn(new PageImpl<>(List.of(), page, 3));
        when(discoveredCertRepository.countPqcRowsByOrganizationId(1L, null)).thenReturn(4L);
        when(discoveredCertRepository.findPqcRowsByOrganizationId(1L, null, PageRequest.of(0, 2, order)))
                .thenReturn(List.of(discoveredRow("d1", "d1", null, null), discoveredRow("d2", "d2", null, null)));
        when(discoveredCertRepository.findPqcRowsByOrganizationId(1L, null, PageRequest.of(1, 2, order)))
                .thenReturn(List.of(discoveredRow("d3", "d3", null, null), discoveredRow("d4", "d4", null, null)));

        Page<CertDetail> details = pqcReadinessService.certificates(1L, null, page);

        assertThat(details.getContent()).extracting(CertDetail::certificateXref).containsExactly("d2", "d3");
        assertThat(details.getTotalElements()).isEqualTo(7);
    }

    @Test
    void certificates_withStatusFilter_matchesDiscoveredRawKeyAlgorithms() {
        Pageable page = PageRequest.of(0, 15);
        when(certificateRepository.countPqcAlgorithmsByOrganizationId(1L)).thenReturn(List.of());
        when(discoveredCertRepository.countPqcAlgorithmsByOrganizationId(1L)).thenReturn(List.of(
                discoveredCount("EC-256", null, 1),
                discoveredCount("RSA_2048", null, 1),
                discoveredCount(null, null, 1)));
        when(discoveredCertRepository.countPqcRowsByOrganizationId(1L, List.of(""))).thenReturn(1L);
        when(discoveredCertRepository.findPqcRowsByOrganizationId(eq(1L), eq(List.of("")), any()))
                .thenReturn(List.of(discoveredRow("kv/x", "x.example.com", null, null)));

        Page<CertDetail> details = pqcReadinessService.certificates(1L, QuantumStatus.UNKNOWN, page);

        assertThat(details.getContent()).extracting(CertDetail::certificateXref).containsExactly("kv/x");
        verify(certificateRepository, never()).findPqcRowsByOrganizationId(any(), any(), any());
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static PqcDiscoveredAlgorithmCount discoveredCount(String keyAlgorithm, String keyUsage, long count) {
        return new PqcDiscoveredAlgorithmCount() {
            @Override public String getKeyAlgorithm() { return keyAlgorithm; }
            @Override public String getKeyUsage() { return keyUsage; }
            @Override public long getCount() { return count; }
        };
    }

    private static PqcDiscoveredRow discoveredRow(String resourceId, String domain, String subjectDn,
                                                  String keyAlgorithm) {
        return new PqcDiscoveredRow() {
            @Override public String getResourceId() { return resourceId; }
            @Override public String getDomain() { return domain; }
            @Override public String getSubjectDn() { return subjectDn; }
            @Override public String getSignatureAlgorithm() { return null; }
            @Override public String getKeyAlgorithm() { return keyAlgorithm; }
            @Override public String getKeyUsage() { return null; }
        };
    }

    private static PqcAlgorithmCount count(String algorithm, Integer keySize, String curve, String keyUsage, long count) {
        return new PqcAlgorithmCount() {
            @Override public String getPublicKeyAlgorithm() { return algorithm; }
            @Override public Integer getKeySize() { return keySize; }
            @Override public String getCurve() { return curve; }
            @Override public String getKeyUsage() { return keyUsage; }
            @Override public long getCount() { return count; }
        };
    }

    private static PqcCertificateRow row(String xref, String commonName, String domain, String sigAlg,
                                         String pubKeyAlg, Integer keySize, String curve, String keyUsage) {
        return new PqcCertificateRow() {
            @Override public String getCertificateXref() { return xref; }
            @Override public String getCommonName() { return commonName; }
            @Override public String getDomain() { return domain; }
            @Override public String getSignatureAlgorithm() { return sigAlg; }
            @Override public String getPublicKeyAlgorithm() { return pubKeyAlg; }
            @Override public Integer getKeySize() { return keySize; }
            @Override public String getCurve() { return curve; }
            @Override public String getKeyUsage() { return keyUsage; }
        };
    }
}
