// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.StringReader;
import java.security.KeyPair;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CsrKeyPairServiceTest {

    private final CsrKeyPairService service = new CsrKeyPairService();

    @Test
    void generateKeyPair_returnsRsa2048KeyPair() {
        KeyPair kp = service.generateKeyPair();
        assertThat(kp).isNotNull();
        assertThat(kp.getPrivate().getAlgorithm()).isEqualTo("RSA");
        assertThat(kp.getPublic().getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    void buildCsr_singleDomain_signedWithKeyPair() throws Exception {
        KeyPair kp = service.generateKeyPair();
        CSRBuilder csr = service.buildCsr(List.of("example.com"), kp);
        assertThat(csr).isNotNull();
        assertThat(csr.getEncoded()).isNotEmpty();
    }

    @Test
    void buildCsr_putsTheFirstNameInTheCommonName() throws Exception {
        CSRBuilder csr = service.buildCsr(List.of("*.example.com", "example.com"), service.generateKeyPair());

        assertThat(csr.getCSR().getSubject().toString()).isEqualTo("CN=*.example.com");
    }

    @Test
    void buildCsr_aNameTooLongForACommonName_staysInTheSanOnly() throws Exception {
        String longName = "a".repeat(60) + ".example.com";

        CSRBuilder csr = service.buildCsr(List.of(longName), service.generateKeyPair());

        assertThat(csr.getCSR().getSubject().toString()).isEmpty();
    }

    @Test
    void buildCsr_withSans_includesAllDomains() throws Exception {
        KeyPair kp = service.generateKeyPair();
        CSRBuilder csr = service.buildCsr(List.of("example.com", "www.example.com"), kp);
        assertThat(csr).isNotNull();
        assertThat(csr.getEncoded()).isNotEmpty();
    }

    @Test
    void generateCsrAndKeyPair_returnsPemStrings() {
        CsrKeyPairService.CsrKeyPairResult result =
                service.generateCsrAndKeyPair("example.com", List.of("www.example.com"));

        assertThat(result.csrPem()).contains("BEGIN CERTIFICATE REQUEST");
        assertThat(result.privateKeyPem()).contains("BEGIN");
        assertThat(result.csrDer()).isNotEmpty();
    }

    @Test
    void generateCsrAndKeyPair_nullSans_doesNotFail() {
        CsrKeyPairService.CsrKeyPairResult result =
                service.generateCsrAndKeyPair("example.com", null);

        assertThat(result.csrPem()).contains("CERTIFICATE REQUEST");
        assertThat(result.privateKeyPem()).isNotBlank();
    }

    @Test
    void generateCsrAndKeyPair_privateKeyIsValid() throws Exception {
        CsrKeyPairService.CsrKeyPairResult result =
                service.generateCsrAndKeyPair("test.example.com", null);

        // Round-trip: PEM can be parsed back to a KeyPair
        KeyPair restored = KeyPairUtils.readKeyPair(new StringReader(result.privateKeyPem()));
        assertThat(restored.getPrivate()).isNotNull();
        assertThat(restored.getPublic()).isNotNull();
    }
}
