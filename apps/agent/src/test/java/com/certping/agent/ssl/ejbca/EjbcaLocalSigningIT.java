// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.secrets.SecretStoreProvider;
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
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * End-to-end signing against the local EJBCA container.
 *
 * <p>Skips itself when {@code local/ejbca/generated/credential.json} is absent, so it is inert
 * on any machine that has not run {@code local/ejbca/bootstrap.sh}. That file is gitignored —
 * it holds a real (if local-only) client key.
 *
 * <p>These tests are the point of the exercise: unit tests with a mocked client prove our
 * request shape, but only a real CA proves the profile actually accepts what we send.
 *
 * <p><b>Verified against EJBCA 9.3.7 Community, stock ENDUSER + EMPTY profiles:</b> that profile
 * pair enforces <em>no</em> key-size floor — an RSA-512 CSR is signed without complaint. Key
 * algorithm and size limits are certificate-profile configuration on the customer's CA, not
 * something this driver imposes, so a production deployment must restrict the profile itself.
 * The EMPTY end entity profile does, however, mandate a subject common name.
 */
@DisplayName("EJBCA local signing (integration)")
class EjbcaLocalSigningIT {

    private static final Path CREDENTIAL_FILE =
            Path.of("local", "ejbca", "generated", "credential.json");

    private static EjbcaSigningService service;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        assumeTrue(Files.exists(CREDENTIAL_FILE),
                "local EJBCA credential not found — run local/ejbca/bootstrap.sh first");

        String credentialJson = Files.readString(CREDENTIAL_FILE);

        AgentProperties properties = new AgentProperties();
        AgentProperties.EjbcaProperties cfg = properties.getEjbca();
        cfg.setEnabled(true);
        cfg.setCredentialPath("local://ejbca-credential");
        cfg.setCaName("ManagementCA");
        cfg.setCertificateProfileName("ENDUSER");
        cfg.setEndEntityProfileName("EMPTY");
        cfg.setRequestTimeoutSeconds(30);

        EjbcaClient client = new EjbcaClient(
                properties, new FixedSecretStore(credentialJson), JsonMapper.builderWithJackson2Defaults().build());
        service = new EjbcaSigningService(client, new EndEntityNameResolver(), properties);
    }

    // ── connectivity ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("status probe reports version and edition without a credential")
    void probeVersion_reportsVersionAndEdition() {
        String version = service.probeVersion();
        assertThat(version).contains("EJBCA");
        // The whole reason edition/version are not stored in the credential JSON.
        assertThat(version).containsAnyOf("Community", "Enterprise");
    }

    // ── algorithms and key sizes ──────────────────────────────────────────────

    @ParameterizedTest(name = "{0} {1} signs successfully")
    @CsvSource({
            "RSA,   2048",
            "RSA,   3072",
            "RSA,   4096",
            "EC,    256",
            "EC,    384",
    })
    @DisplayName("signs CSRs across key algorithms and sizes")
    void sign_acrossAlgorithmsAndKeySizes(String algorithm, int keySize) throws Exception {
        String deviceId = "dev-" + algorithm.toLowerCase() + keySize + "-" + shortId();
        KeyPair keyPair = generateKeyPair(algorithm, keySize);
        String csr = csrFor(keyPair, deviceId, algorithm);

        EjbcaSignResult result = service.sign(csr, deviceId);

        assertThat(result.serialNumber()).isNotBlank();
        assertThat(result.endEntityName()).isEqualTo(deviceId);
        assertThat(result.certificatePem()).startsWith("-----BEGIN CERTIFICATE-----");
        assertThat(result.leaf().getSubjectX500Principal().getName()).contains("CN=" + deviceId);
        // The only proof the device's key was signed rather than a fresh one generated for it.
        assertThat(result.leaf().getPublicKey().getEncoded())
                .isEqualTo(keyPair.getPublic().getEncoded());
        result.leaf().checkValidity();
    }

    // ── SANs ──────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("carries multiple DNS SANs from the CSR into the certificate")
    void sign_withMultipleDnsSans() throws Exception {
        String deviceId = "dev-multisan-" + shortId();
        KeyPair keyPair = generateKeyPair("RSA", 2048);
        String csr = csrFor(keyPair, deviceId, "RSA",
                new GeneralName(GeneralName.dNSName, "device.iot.example.com"),
                new GeneralName(GeneralName.dNSName, "alt.iot.example.com"));

        EjbcaSignResult result = service.sign(csr, deviceId);

        assertThat(sanValues(result)).contains("device.iot.example.com", "alt.iot.example.com");
    }

    @Test
    @DisplayName("carries an IP SAN from the CSR into the certificate")
    void sign_withIpSan() throws Exception {
        String deviceId = "dev-ipsan-" + shortId();
        KeyPair keyPair = generateKeyPair("RSA", 2048);
        String csr = csrFor(keyPair, deviceId, "RSA",
                new GeneralName(GeneralName.iPAddress, "10.42.0.7"));

        EjbcaSignResult result = service.sign(csr, deviceId);

        assertThat(sanValues(result)).contains("10.42.0.7");
    }

    // ── end entity naming ─────────────────────────────────────────────────────

    @Test
    @DisplayName("derives the end entity name from the CSR common name when no device id is given")
    void sign_derivesEndEntityNameFromCommonName() throws Exception {
        String cn = "derived-" + shortId();
        KeyPair keyPair = generateKeyPair("RSA", 2048);

        EjbcaSignResult result = service.sign(csrFor(keyPair, cn, "RSA"), null);

        assertThat(result.endEntityName()).isEqualTo(cn);
    }

    @Test
    @DisplayName("a CSR with no common name is rejected by the end entity profile, with EJBCA's wording preserved")
    void sign_csrWithoutCommonName_isRejectedByProfile() throws Exception {
        String dns = "sanonly-" + shortId() + ".iot.example.com";
        KeyPair keyPair = generateKeyPair("RSA", 2048);
        String csr = csrWithoutSubject(keyPair, new GeneralName(GeneralName.dNSName, dns));

        // The driver resolves the end entity name from the DNS SAN just fine (unit-tested),
        // but the stock EMPTY end entity profile mandates a subject CN and rejects the CSR.
        // Directly relevant to the SCEP path: the Intune SCEP profile must set a subject name,
        // or the customer's end entity profile must stop requiring one.
        assertThatThrownBy(() -> service.sign(csr, null))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("COMMONNAME");
    }

    // ── renewal ───────────────────────────────────────────────────────────────

    @Test
    @DisplayName("re-enrolling the same device id issues a second certificate")
    void sign_sameDeviceTwice_reEnrolls() throws Exception {
        String deviceId = "dev-renew-" + shortId();

        EjbcaSignResult first = service.sign(
                csrFor(generateKeyPair("RSA", 2048), deviceId, "RSA"), deviceId);
        // A real renewal re-keys, so the second CSR carries a different public key.
        EjbcaSignResult second = service.sign(
                csrFor(generateKeyPair("RSA", 2048), deviceId, "RSA"), deviceId);

        // pkcs10enroll resets the end entity from GENERATED back to NEW rather than failing
        // with "username already exists", which is what makes renewal work at all.
        assertThat(second.serialNumber()).isNotEqualTo(first.serialNumber());
        assertThat(second.endEntityName()).isEqualTo(deviceId);
    }

    // ── rejection paths ───────────────────────────────────────────────────────

    @Test
    @DisplayName("rejects a malformed CSR before any network call")
    void sign_malformedCsr_isRejectedLocally() {
        assertThatThrownBy(() -> service.sign("""
                -----BEGIN CERTIFICATE REQUEST-----
                nope
                -----END CERTIFICATE REQUEST-----""", null))
                .isInstanceOf(PermanentAgentException.class);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /** Flattens {@code getSubjectAlternativeNames()} (a Collection&lt;List&lt;?&gt;&gt;) to plain values. */
    private static java.util.List<String> sanValues(EjbcaSignResult result) throws Exception {
        var sans = result.leaf().getSubjectAlternativeNames();
        assertThat(sans).as("certificate has SANs").isNotNull();
        return sans.stream()
                .filter(entry -> entry.size() > 1)
                .map(entry -> String.valueOf(entry.get(1)))
                .toList();
    }

    private static String shortId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }

    private static KeyPair generateKeyPair(String algorithm, int keySize) throws Exception {
        if ("EC".equals(algorithm)) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
            generator.initialize(new ECGenParameterSpec("P-" + keySize));
            return generator.generateKeyPair();
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

    private static String csrFor(KeyPair keyPair, String commonName, String algorithm,
                                 GeneralName... sans) throws Exception {
        X500NameBuilder subject = new X500NameBuilder(BCStyle.INSTANCE);
        subject.addRDN(BCStyle.CN, commonName);
        return buildCsr(keyPair, subject, algorithm, sans);
    }

    private static String csrWithoutSubject(KeyPair keyPair, GeneralName... sans) throws Exception {
        return buildCsr(keyPair, new X500NameBuilder(BCStyle.INSTANCE), "RSA", sans);
    }

    private static String buildCsr(KeyPair keyPair, X500NameBuilder subject, String algorithm,
                                   GeneralName... sans) throws Exception {
        JcaPKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(subject.build(), keyPair.getPublic());

        if (sans.length > 0) {
            ExtensionsGenerator extensions = new ExtensionsGenerator();
            extensions.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans));
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                    extensions.generate());
        }

        String signatureAlgorithm = "EC".equals(algorithm) ? "SHA256withECDSA" : "SHA256withRSA";
        PKCS10CertificationRequest csr = builder.build(
                new JcaContentSignerBuilder(signatureAlgorithm).setProvider("BC")
                        .build(keyPair.getPrivate()));
        return toPem(csr.getEncoded());
    }

    private static String toPem(byte[] der) {
        String body = Base64.getEncoder().encodeToString(der);
        StringWriter out = new StringWriter();
        out.write("-----BEGIN CERTIFICATE REQUEST-----\n");
        for (int i = 0; i < body.length(); i += 64) {
            out.write(body.substring(i, Math.min(i + 64, body.length())));
            out.write('\n');
        }
        out.write("-----END CERTIFICATE REQUEST-----");
        return out.toString();
    }

    /** Stands in for the customer's secret manager: one credential, read straight from disk. */
    private record FixedSecretStore(String value) implements SecretStore {
        @Override public String read(String handle) { return value; }
        @Override public String create(String name, String v) { throw new UnsupportedOperationException(); }
        @Override public String update(String handle, String v) { throw new UnsupportedOperationException(); }
        @Override public void delete(String handle) { throw new UnsupportedOperationException(); }
        @Override public boolean isOwnedByThisAgent(String handle) { return false; }
        @Override public String handleFor(String name) { return name; }
        @Override public SecretStoreProvider provider() { return null; }
    }
}
