// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("EjbcaSigningService")
class EjbcaSigningServiceTest {

    private static KeyPair keyPair;
    private static String signedCertBase64;

    private EjbcaClient client;
    private AgentProperties properties;
    private EjbcaSigningService service;

    @BeforeAll
    static void generateFixtures() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        signedCertBase64 = selfSignedBase64(keyPair);
    }

    @BeforeEach
    void setUp() {
        client = mock(EjbcaClient.class);
        properties = new AgentProperties();
        AgentProperties.EjbcaProperties cfg = properties.getEjbca();
        cfg.setEnabled(true);
        cfg.setCredentialPath("kv://ejbca");
        cfg.setCaName("ManagementCA");
        cfg.setCertificateProfileName("ENDUSER");
        cfg.setEndEntityProfileName("EMPTY");
        service = new EjbcaSigningService(client, new EndEntityNameResolver(), properties);
    }

    private void stubEnrollResponse() {
        try {
            when(client.pkcs10Enroll(anyMap())).thenReturn(JsonMapper.builderWithJackson2Defaults().build().readTree("""
                    {"certificate":"%s","serial_number":"ABC123","response_format":"DER",
                     "certificate_chain":["%s"]}""".formatted(signedCertBase64, signedCertBase64)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ── request shape ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("sends every field pkcs10enroll requires")
    void sendsRequiredFields() throws Exception {
        stubEnrollResponse();
        String csr = csr("device-42");

        service.sign(csr, "device-42");

        Map<String, Object> body = captureBody();
        assertThat(body)
                .containsEntry("certificate_request", csr)
                .containsEntry("certificate_profile_name", "ENDUSER")
                .containsEntry("end_entity_profile_name", "EMPTY")
                .containsEntry("certificate_authority_name", "ManagementCA")
                .containsEntry("username", "device-42")
                .containsEntry("include_chain", true)
                // PEM is rejected with "Response format can only be DER or PKCS7".
                .containsEntry("response_format", "DER");
        assertThat(body.get("password")).asString().isNotBlank();
    }

    @Test
    @DisplayName("generates a fresh password per request")
    void passwordIsRandomPerRequest() throws Exception {
        stubEnrollResponse();

        service.sign(csr("device-a"), "device-a");
        service.sign(csr("device-b"), "device-b");

        ArgumentCaptor<Map<String, Object>> captor = bodyCaptor();
        verify(client, org.mockito.Mockito.times(2)).pkcs10Enroll(captor.capture());
        assertThat(captor.getAllValues().get(0).get("password"))
                .isNotEqualTo(captor.getAllValues().get(1).get("password"));
    }

    // ── end entity naming ─────────────────────────────────────────────────────

    @Test
    @DisplayName("prefers an explicit device id over anything in the CSR")
    void explicitDeviceIdWins() throws Exception {
        stubEnrollResponse();

        service.sign(csr("cn-from-csr"), "device-id-from-mdm");

        assertThat(captureBody()).containsEntry("username", "device-id-from-mdm");
    }

    @Test
    @DisplayName("falls back to the CSR common name when no device id is given")
    void fallsBackToCommonName() throws Exception {
        stubEnrollResponse();

        service.sign(csr("cn-from-csr"), null);

        assertThat(captureBody()).containsEntry("username", "cn-from-csr");
    }

    @Test
    @DisplayName("falls back to the first DNS SAN when the CSR has no common name")
    void fallsBackToDnsSan() throws Exception {
        stubEnrollResponse();
        String csr = csrWithSans(new GeneralName(GeneralName.dNSName, "sensor.example.com"));

        service.sign(csr, null);

        assertThat(captureBody()).containsEntry("username", "sensor.example.com");
    }

    @Test
    @DisplayName("applies the configured prefix, which is what keeps tenants from colliding")
    void appliesPrefix() throws Exception {
        stubEnrollResponse();
        properties.getEjbca().setEndEntityNamePrefix("acme-corp-");

        service.sign(csr("device-42"), "device-42");

        assertThat(captureBody()).containsEntry("username", "acme-corp-device-42");
    }

    @Test
    @DisplayName("pins the name to one source when configured, rather than falling through")
    void pinnedSourceDoesNotFallThrough() throws Exception {
        properties.getEjbca().setEndEntityNameSource("dns");

        // CN is present but the source is pinned to dns, and there is no DNS SAN.
        assertThatThrownBy(() -> service.sign(csr("cn-present"), null))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("end entity name");
    }

    @Test
    @DisplayName("rejects an unknown name source")
    void unknownSourceRejected() throws Exception {
        properties.getEjbca().setEndEntityNameSource("serialnumber");

        assertThatThrownBy(() -> service.sign(csr("device-42"), null))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("cn, dns, uri, ip");
    }

    @Test
    @DisplayName("rejects an over-long name instead of truncating two devices onto one identity")
    void rejectsOverLongName() throws Exception {
        String longId = "d".repeat(400);

        // Truncating would merge any two device ids sharing a long prefix onto one end entity,
        // resetting the first device's record. That is an identity collision, not a formatting bug.
        assertThatThrownBy(() -> service.sign(csr("device-42"), longId))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("400 characters");
    }

    @Test
    @DisplayName("derives a readable address from an IP SAN, not a hex octet string")
    void derivesReadableIpFromIpSan() throws Exception {
        stubEnrollResponse();
        properties.getEjbca().setEndEntityNameSource("ip");
        String csr = csrWithSans(new GeneralName(GeneralName.iPAddress, "10.42.0.7"));

        service.sign(csr, null);

        // BouncyCastle renders an iPAddress GeneralName as "#0a2a0007"; an end entity named that
        // is unsearchable in the EJBCA admin UI and meaningless in the audit trail.
        assertThat(captureBody()).containsEntry("username", "10.42.0.7");
    }

    @Test
    @DisplayName("rejects a CSR carrying a malformed extensionRequest as a bad request")
    void malformedExtensionRequestIsABadRequest() throws Exception {
        // The CSR is device-supplied, so a junk attribute must not escape as an unclassified
        // internal error into the listener's "should never happen" path.
        String csr = csrWithMalformedExtensionRequest();

        assertThatThrownBy(() -> service.sign(csr, null))
                .isInstanceOfSatisfying(PermanentAgentException.class, e ->
                        assertThat(e.getErrorCode()).isEqualTo("EJBCA_CSR_INVALID"));
    }

    // ── response handling ─────────────────────────────────────────────────────

    @Test
    @DisplayName("decodes the DER response into PEM and exposes the chain")
    void decodesDerResponse() throws Exception {
        stubEnrollResponse();

        EjbcaSignResult result = service.sign(csr("device-42"), "device-42");

        assertThat(result.certificatePem())
                .startsWith("-----BEGIN CERTIFICATE-----")
                .endsWith("-----END CERTIFICATE-----");
        assertThat(result.chainPem()).hasSize(1);
        assertThat(result.fullChainPem()).contains(result.certificatePem());
        assertThat(result.serialNumber()).isEqualTo("ABC123");
        assertThat(result.endEntityName()).isEqualTo("device-42");
        assertThat(result.leaf().getPublicKey()).isEqualTo(keyPair.getPublic());
    }

    @Test
    @DisplayName("fails when EJBCA returns no certificate")
    void missingCertificateIsRejected() throws Exception {
        when(client.pkcs10Enroll(anyMap()))
                .thenReturn(JsonMapper.builderWithJackson2Defaults().build().readTree("{\"serial_number\":\"ABC\"}"));

        assertThatThrownBy(() -> service.sign(csr("device-42"), "device-42"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("no certificate");
    }

    // ── configuration guards ──────────────────────────────────────────────────

    @Test
    @DisplayName("refuses to run when disabled")
    void disabledIsRejected() throws Exception {
        properties.getEjbca().setEnabled(false);

        assertThatThrownBy(() -> service.sign(csr("device-42"), "device-42"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("disabled");
    }

    @Test
    @DisplayName("fails fast when a required profile name is blank")
    void blankProfileIsRejected() throws Exception {
        properties.getEjbca().setCertificateProfileName("  ");

        assertThatThrownBy(() -> service.sign(csr("device-42"), "device-42"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("certificate-profile-name");
    }

    @Test
    @DisplayName("rejects a blank CSR before any network call")
    void blankCsrIsRejected() {
        assertThatThrownBy(() -> service.sign("   ", "device-42"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("No CSR");
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private ArgumentCaptor<Map<String, Object>> bodyCaptor() {
        return ArgumentCaptor.forClass(Map.class);
    }

    private Map<String, Object> captureBody() {
        ArgumentCaptor<Map<String, Object>> captor = bodyCaptor();
        verify(client).pkcs10Enroll(captor.capture());
        return captor.getValue();
    }

    private static String csr(String commonName) throws Exception {
        X500NameBuilder subject = new X500NameBuilder(BCStyle.INSTANCE);
        subject.addRDN(BCStyle.CN, commonName);
        return pem(new JcaPKCS10CertificationRequestBuilder(subject.build(), keyPair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
                        .build(keyPair.getPrivate())).getEncoded());
    }

    private static String csrWithMalformedExtensionRequest() throws Exception {
        return pem(new JcaPKCS10CertificationRequestBuilder(
                new X500NameBuilder(BCStyle.INSTANCE).build(), keyPair.getPublic())
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                        new org.bouncycastle.asn1.DERUTF8String("not-an-extensions-structure"))
                .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
                        .build(keyPair.getPrivate())).getEncoded());
    }

    private static String csrWithSans(GeneralName... sans) throws Exception {
        ExtensionsGenerator extensions = new ExtensionsGenerator();
        extensions.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans));
        return pem(new JcaPKCS10CertificationRequestBuilder(
                new X500NameBuilder(BCStyle.INSTANCE).build(), keyPair.getPublic())
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate())
                .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
                        .build(keyPair.getPrivate())).getEncoded());
    }

    private static String pem(byte[] der) {
        return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END CERTIFICATE REQUEST-----";
    }

    /** Stands in for whatever EJBCA would return; only the encoding matters to these tests. */
    private static String selfSignedBase64(KeyPair keyPair) throws Exception {
        var name = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, "fixture").build();
        var builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
                name, BigInteger.ONE,
                new Date(System.currentTimeMillis() - 3600_000),
                new Date(System.currentTimeMillis() + 3600_000),
                name, keyPair.getPublic());
        var holder = builder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
                .build(keyPair.getPrivate()));
        return Base64.getEncoder().encodeToString(holder.getEncoded());
    }
}
