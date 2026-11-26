// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.smallstep;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.secrets.SecretStoreProvider;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
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

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.time.Clock;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Live contract test for the JWK provisioner flow supported by open-source step-ca. */
@DisplayName("Smallstep local signing (integration)")
class SmallstepLocalSigningIT {
    private static final Path CREDENTIAL_FILE =
            Path.of("local", "smallstep", "generated", "credential.json");
    private static SmallstepSigningService service;

    @BeforeAll
    static void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        assumeTrue(Files.exists(CREDENTIAL_FILE),
                "local Smallstep credential not found - run local/smallstep/bootstrap.sh first");

        AgentProperties properties = new AgentProperties();
        properties.getSmallstep().setEnabled(true);
        properties.getSmallstep().setCredentialPath("local://smallstep-credential");
        properties.getSmallstep().setRequestTimeoutSeconds(15);
        SmallstepClient client = new SmallstepClient(properties,
                new FixedSecretStore(Files.readString(CREDENTIAL_FILE)),
                JsonMapper.builderWithJackson2Defaults().build(), Clock.systemUTC());
        service = new SmallstepSigningService(client, properties);
    }

    @Test
    @DisplayName("probes the real authority version")
    void probeVersion_reportsRealAuthorityVersion() {
        assertThat(service.probeVersion()).matches("\\d+\\.\\d+\\.\\d+.*");
    }

    @Test
    @DisplayName("signs the CSR public key and preserves device SANs")
    void sign_preservesPublicKeyAndSans() throws Exception {
        String deviceName = "device-" + UUID.randomUUID().toString().substring(0, 8);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        PKCS10CertificationRequest csr = csr(keyPair, deviceName,
                new GeneralName(GeneralName.uniformResourceIdentifier, "urn:certping:device:" + deviceName),
                new GeneralName(GeneralName.iPAddress, "10.20.30.40"));

        SmallstepSignResult result = service.sign(csr, null);

        assertThat(result.leaf().getPublicKey().getEncoded()).isEqualTo(keyPair.getPublic().getEncoded());
        assertThat(result.leaf().getSubjectX500Principal().getName()).contains("CN=" + deviceName);
        assertThat(sans(result.leaf().getSubjectAlternativeNames()))
                .contains("urn:certping:device:" + deviceName, "10.20.30.40");
        assertThat(result.chain()).hasSizeGreaterThanOrEqualTo(2);
        result.leaf().checkValidity();
    }

    private static PKCS10CertificationRequest csr(
            KeyPair keyPair, String commonName, GeneralName... names) throws Exception {
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=" + commonName), keyPair.getPublic());
        ExtensionsGenerator extensions = new ExtensionsGenerator();
        extensions.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(keyPair.getPrivate()));
    }

    private static List<String> sans(Collection<List<?>> values) {
        return values.stream().map(value -> String.valueOf(value.get(1))).toList();
    }

    private record FixedSecretStore(String value) implements SecretStore {
        @Override public String read(String handle) { return value; }
        @Override public String create(String name, String newValue) { throw new UnsupportedOperationException(); }
        @Override public String update(String handle, String newValue) { throw new UnsupportedOperationException(); }
        @Override public void delete(String handle) { throw new UnsupportedOperationException(); }
        @Override public boolean isOwnedByThisAgent(String handle) { return false; }
        @Override public String handleFor(String name) { return name; }
        @Override public SecretStoreProvider provider() { return SecretStoreProvider.AZURE_KV; }
    }
}
