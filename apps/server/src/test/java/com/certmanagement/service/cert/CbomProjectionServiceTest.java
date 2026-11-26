// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.enums.CaProvider;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CertificateRepository.CbomCertificateRow;
import com.certmanagement.service.cbom.CbomProjectionService;
import org.cyclonedx.Version;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CbomProjectionServiceTest {

    @Mock
    private CertificateRepository certificateRepository;

    @InjectMocks
    private CbomProjectionService cbomProjectionService;

    private static final Long ORG_ID = 1L;

    // -------------------------------------------------------------------------
    // writeCbom — document structure
    // -------------------------------------------------------------------------

    @Test
    void writeCbom_emptyOrg_writesValidBomWithNoComponents() throws IOException {
        byte[] json = writeCbom();

        assertThat(validate(json)).isEmpty();
        Bom bom = parse(json);
        assertThat(bom.getComponents()).isNullOrEmpty();
        assertThat(bom.getSpecVersion()).isEqualTo("1.6");
        assertThat(bom.getVersion()).isEqualTo(1);
        assertThat(bom.getMetadata().getTimestamp()).isNotNull();
    }

    @Test
    void writeCbom_singleCertWithCryptoMetadata_producesCertAndAlgoComponent() throws IOException {
        Bom bom = parse(writeCbom(rsaCert("cert-1", 2048, "CN=example.com", "secp256r1")));

        assertThat(bom.getComponents()).hasSize(2);

        Component certComp = bom.getComponents().get(0);
        assertThat(certComp.getCryptoProperties().getAssetType()).isEqualTo(AssetType.CERTIFICATE);
        assertThat(certComp.getBomRef()).isEqualTo("cert-1");

        Component algoComp = bom.getComponents().get(1);
        assertThat(algoComp.getCryptoProperties().getAssetType()).isEqualTo(AssetType.ALGORITHM);
        assertThat(algoComp.getBomRef()).startsWith("algo-");
    }

    @Test
    void writeCbom_outputValidatesAgainstCycloneDx16Schema() throws IOException {
        CbomCertificateRow full = rsaCert("cert-1", 2048, "CN=example.com", null);
        when(full.getFingerprintSha256()).thenReturn("aa".repeat(32));
        when(full.getValidFrom()).thenReturn(OffsetDateTime.parse("2026-01-01T00:00:00Z"));
        when(full.getValidTo()).thenReturn(OffsetDateTime.parse("2027-01-01T00:00:00Z"));
        when(full.getSignatureAlgorithmOid()).thenReturn("1.2.840.113549.1.1.11");
        when(full.getKeyUsage()).thenReturn("digitalSignature, keyEncipherment");
        when(full.getExtendedKeyUsage()).thenReturn("serverAuth");
        when(full.getSubjectKeyIdentifier()).thenReturn("SKI");
        when(full.getAuthorityKeyIdentifier()).thenReturn("AKI");
        when(full.getSerialNumber()).thenReturn("01AB");

        byte[] json = writeCbom(full, ecCert("cert-2", 256), certNoAlgo("cert-old"));

        assertThat(validate(json)).isEmpty();
        assertThat(new String(json, StandardCharsets.UTF_8)).contains("\"bomFormat\" : \"CycloneDX\"");
    }

    @Test
    void writeCbom_twoCertsWithSameAlgo_deduplicatesAlgorithmComponent() throws IOException {
        Bom bom = parse(writeCbom(rsaCert("cert-1", 2048), rsaCert("cert-2", 2048)));

        assertThat(bom.getComponents()).hasSize(3);
        assertThat(bom.getComponents().stream()
                .filter(c -> c.getCryptoProperties().getAssetType() == AssetType.ALGORITHM))
                .hasSize(1);
    }

    @Test
    void writeCbom_twoCertsWithDifferentAlgos_createsTwoAlgorithmComponents() throws IOException {
        Bom bom = parse(writeCbom(rsaCert("cert-1", 2048), ecCert("cert-2", 256)));

        assertThat(bom.getComponents()).hasSize(4);
        assertThat(bom.getComponents().stream()
                .filter(c -> c.getCryptoProperties().getAssetType() == AssetType.ALGORITHM))
                .hasSize(2);
    }

    @Test
    void writeCbom_repositoryThrows_propagatesInsteadOfWritingAHalfEmptyBom() {
        when(certificateRepository.streamCbomRowsByOrganizationId(ORG_ID))
                .thenThrow(new RuntimeException("DB unavailable"));

        assertThatThrownBy(() -> cbomProjectionService.writeCbom(ORG_ID, new ByteArrayOutputStream()))
                .hasMessage("DB unavailable");
    }

    @Test
    void writeCbom_failureMidStream_leavesTheDocumentVisiblyTruncated() {
        CbomCertificateRow first = rsaCert("cert-1", 2048);
        CbomCertificateRow poisoned = rsaCert("cert-2", 2048);
        when(poisoned.getCertificateXref()).thenThrow(new IllegalStateException("row read failed"));
        when(certificateRepository.streamCbomRowsByOrganizationId(ORG_ID)).thenReturn(Stream.of(first, poisoned));
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        assertThatThrownBy(() -> cbomProjectionService.writeCbom(ORG_ID, out))
                .hasMessage("row read failed");

        String partial = out.toString(StandardCharsets.UTF_8);
        assertThat(partial).contains("\"cert-1\"");
        assertThatThrownBy(() -> new JsonParser().parse(partial.getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(ParseException.class);
    }

    @Test
    void writeCbom_closesTheRowStream() throws IOException {
        @SuppressWarnings("unchecked")
        Stream<CbomCertificateRow> rows = mock(Stream.class);
        when(rows.iterator()).thenReturn(List.<CbomCertificateRow>of().iterator());
        when(certificateRepository.streamCbomRowsByOrganizationId(ORG_ID)).thenReturn(rows);

        cbomProjectionService.writeCbom(ORG_ID, new ByteArrayOutputStream());

        verify(rows).close();
    }

    // -------------------------------------------------------------------------
    // Certificate component correctness
    // -------------------------------------------------------------------------

    @Test
    void writeCbom_certBomRefIsXrefWithoutDoublePrefix() throws IOException {
        Component certComp = certComponent(parse(writeCbom(rsaCert("cert-abc123", 2048))));

        assertThat(certComp.getBomRef()).isEqualTo("cert-abc123");
        assertThat(certComp.getBomRef()).doesNotStartWith("cert-cert-");
    }

    @Test
    void writeCbom_certWithCryptoMetadata_setsNameAndSubjectName() throws IOException {
        Component certComp = certComponent(parse(writeCbom(rsaCert("cert-1", 2048, "CN=my.domain.com", null))));

        assertThat(certComp.getName()).isEqualTo("my.domain.com");
        assertThat(certComp.getCryptoProperties().getCertificateProperties().getSubjectName())
                .isEqualTo("CN=my.domain.com");
    }

    @Test
    void writeCbom_certWithNoMetadata_nameFallsBackToDomainAndSubjectNameIsNull() throws IOException {
        Component certComp = certComponent(parse(writeCbom(rsaCert("cert-1", 2048))));

        assertThat(certComp.getName()).isEqualTo("cert-1.example.com");
        assertThat(certComp.getPurl()).isEqualTo("pkg:x509/cert-1.example.com@cert-1");
        assertThat(certComp.getCryptoProperties().getCertificateProperties().getSubjectName()).isNull();
    }

    @Test
    void writeCbom_certHasFingerprintSha256_hashIsIncluded() throws IOException {
        CbomCertificateRow cert = rsaCert("cert-1", 2048);
        when(cert.getFingerprintSha256()).thenReturn("AA:BB:CC");

        Component certComp = certComponent(parse(writeCbom(cert)));

        assertThat(certComp.getHashes()).hasSize(1);
        assertThat(certComp.getHashes().get(0).getValue()).isEqualTo("AA:BB:CC");
    }

    @Test
    void writeCbom_certWithValidityDates_notValidBeforeAndAfterAreSet() throws IOException {
        CbomCertificateRow cert = rsaCert("cert-1", 2048);
        when(cert.getValidFrom()).thenReturn(OffsetDateTime.parse("2026-01-01T00:00:00Z"));
        when(cert.getValidTo()).thenReturn(OffsetDateTime.parse("2027-01-01T00:00:00Z"));

        Component certComp = certComponent(parse(writeCbom(cert)));

        assertThat(certComp.getCryptoProperties().getCertificateProperties().getNotValidBefore())
                .contains("2026-01-01");
        assertThat(certComp.getCryptoProperties().getCertificateProperties().getNotValidAfter())
                .contains("2027-01-01");
    }

    @Test
    void writeCbom_certWithSignatureAlgorithm_signatureAlgorithmRefLinksToAlgoComponent() throws IOException {
        Bom bom = parse(writeCbom(rsaCert("cert-1", 2048)));

        assertThat(certComponent(bom).getCryptoProperties().getCertificateProperties().getSignatureAlgorithmRef())
                .isEqualTo(algoComponent(bom).getBomRef());
    }

    @Test
    void writeCbom_extendedFieldsLandInCustomProperties() throws IOException {
        CbomCertificateRow cert = rsaCert("cert-1", 2048);
        when(cert.getSerialNumber()).thenReturn("01AB");
        when(cert.getKeyUsage()).thenReturn("keyEncipherment");
        when(cert.getExtendedKeyUsage()).thenReturn("serverAuth");
        when(cert.getSubjectKeyIdentifier()).thenReturn("SKI");
        when(cert.getAuthorityKeyIdentifier()).thenReturn("AKI");

        Component certComp = certComponent(parse(writeCbom(cert)));

        assertThat(certComp.getProperties())
                .extracting(p -> p.getName() + "=" + p.getValue())
                .containsExactly(
                        "certping:certificateXref=cert-1",
                        "certping:caProvider=LETS_ENCRYPT",
                        "certping:serialNumber=01AB",
                        "certping:keyUsage=keyEncipherment",
                        "certping:extendedKeyUsage=serverAuth",
                        "certping:subjectKeyIdentifier=SKI",
                        "certping:authorityKeyIdentifier=AKI");
    }

    // -------------------------------------------------------------------------
    // Certs with no algorithm (no crypto metadata yet from old agent)
    // -------------------------------------------------------------------------

    @Test
    void writeCbom_certWithNoSignatureAlgorithm_noAlgoComponentAndNoRef() throws IOException {
        Bom bom = parse(writeCbom(certNoAlgo("cert-old")));

        assertThat(bom.getComponents()).hasSize(1);
        Component certComp = bom.getComponents().get(0);
        assertThat(certComp.getCryptoProperties().getAssetType()).isEqualTo(AssetType.CERTIFICATE);
        assertThat(certComp.getCryptoProperties().getCertificateProperties().getSignatureAlgorithmRef()).isNull();
    }

    // -------------------------------------------------------------------------
    // Algorithm component correctness
    // -------------------------------------------------------------------------

    @Test
    void writeCbom_algorithmComponent_hasNameParameterSetAndClassicalQuantumLevel() throws IOException {
        Component algoComp = algoComponent(parse(writeCbom(rsaCert("cert-1", 4096))));

        assertThat(algoComp.getName()).isEqualTo("SHA256withRSA");
        assertThat(algoComp.getBomRef()).isEqualTo("algo-SHA256withRSA-4096");
        assertThat(algoComp.getCryptoProperties().getAlgorithmProperties().getParameterSetIdentifier())
                .isEqualTo("4096");
        assertThat(algoComp.getCryptoProperties().getAlgorithmProperties().getNistQuantumSecurityLevel())
                .isEqualTo(0);
    }

    @Test
    void writeCbom_algorithmComponent_oidAndCurveFromCryptoMetadata() throws IOException {
        CbomCertificateRow cert = ecCert("cert-1", 256);
        when(cert.getSignatureAlgorithmOid()).thenReturn("1.2.840.10045.4.3.2");
        when(cert.getPublicKeyCurve()).thenReturn("prime256v1");

        Component algoComp = algoComponent(parse(writeCbom(cert)));

        assertThat(algoComp.getCryptoProperties().getOid()).isEqualTo("1.2.840.10045.4.3.2");
        assertThat(algoComp.getCryptoProperties().getAlgorithmProperties().getCurve()).isEqualTo("prime256v1");
        assertThat(algoComp.getBomRef()).isEqualTo("algo-SHA384withECDSA-256-prime256v1");
    }

    @Test
    void writeCbom_pqcAlgorithms_reportTheirNistQuantumLevel() throws IOException {
        Bom bom = parse(writeCbom(
                pqcCert("cert-1", "ML-DSA-65", "ML-DSA"),
                pqcCert("cert-2", "Falcon-1024", "FALCON"),
                pqcCert("cert-3", "SLH-DSA-SHA2-192s", "SLH-DSA")));

        assertThat(bom.getComponents().stream()
                .filter(c -> c.getCryptoProperties().getAssetType() == AssetType.ALGORITHM)
                .map(c -> c.getCryptoProperties().getAlgorithmProperties().getNistQuantumSecurityLevel()))
                .containsExactly(3, 5, 3);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private byte[] writeCbom(CbomCertificateRow... rows) throws IOException {
        when(certificateRepository.streamCbomRowsByOrganizationId(ORG_ID)).thenReturn(Stream.of(rows));
        OutputStream out = new ByteArrayOutputStream();
        cbomProjectionService.writeCbom(ORG_ID, out);
        return ((ByteArrayOutputStream) out).toByteArray();
    }

    private static Bom parse(byte[] json) {
        try {
            return new JsonParser().parse(json);
        } catch (ParseException e) {
            throw new AssertionError(e);
        }
    }

    private static List<ParseException> validate(byte[] json) throws IOException {
        return new JsonParser().validate(json, Version.VERSION_16);
    }

    private CbomCertificateRow rsaCert(String xref, int keySize) {
        return rsaCert(xref, keySize, null, null);
    }

    private CbomCertificateRow rsaCert(String xref, int keySize, String subjectDn, String curve) {
        CbomCertificateRow cert = row(xref, "SHA256withRSA", "RSA");
        when(cert.getKeySize()).thenReturn(keySize);
        when(cert.getCaProvider()).thenReturn(CaProvider.LETS_ENCRYPT);
        when(cert.getIssuer()).thenReturn("CN=Let's Encrypt Authority");
        when(cert.getSubjectDn()).thenReturn(subjectDn);
        when(cert.getCommonName()).thenReturn(subjectDn != null ? subjectDn.replace("CN=", "") : null);
        when(cert.getPublicKeyCurve()).thenReturn(curve);
        return cert;
    }

    private CbomCertificateRow ecCert(String xref, int keySize) {
        CbomCertificateRow cert = row(xref, "SHA384withECDSA", "EC");
        when(cert.getKeySize()).thenReturn(keySize);
        return cert;
    }

    private CbomCertificateRow pqcCert(String xref, String sigAlg, String pubKeyAlg) {
        return row(xref, sigAlg, pubKeyAlg);
    }

    private CbomCertificateRow certNoAlgo(String xref) {
        return row(xref, null, null);
    }

    private CbomCertificateRow row(String xref, String sigAlg, String pubKeyAlg) {
        CbomCertificateRow cert = mock(CbomCertificateRow.class, org.mockito.Mockito.withSettings().lenient());
        when(cert.getCertificateXref()).thenReturn(xref);
        when(cert.getDomain()).thenReturn(xref + ".example.com");
        when(cert.getSignatureAlgorithm()).thenReturn(sigAlg);
        when(cert.getPublicKeyAlgorithm()).thenReturn(pubKeyAlg);
        return cert;
    }

    private Component algoComponent(Bom bom) {
        return bom.getComponents().stream()
                .filter(c -> c.getCryptoProperties().getAssetType() == AssetType.ALGORITHM)
                .findFirst()
                .orElseThrow(() -> new AssertionError("No ALGORITHM component found in BOM"));
    }

    private Component certComponent(Bom bom) {
        return bom.getComponents().stream()
                .filter(c -> c.getCryptoProperties().getAssetType() == AssetType.CERTIFICATE)
                .findFirst()
                .orElseThrow(() -> new AssertionError("No CERTIFICATE component found in BOM"));
    }
}
