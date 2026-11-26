// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import com.certmanagement.dto.cert.CertExportRequest;
import com.certmanagement.exception.CertExportException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertExportOptionsTest {

    @Test
    void pemFormats_ignorePasswordAndLegacyFlag() {
        try (CertExportOptions options = CertExportOptions.from(new CertExportRequest("FULLCHAIN_PEM", "x", true))) {
            assertThat(options.format()).isEqualTo(CertExportFormat.FULLCHAIN_PEM);
            assertThat(options.password()).isNull();
            assertThat(options.legacyPkcs12()).isFalse();
        }
    }

    @Test
    void derAndPkcs7_needNoPassword() {
        for (String format : new String[] {"CERTIFICATE_DER", "PKCS7"}) {
            try (CertExportOptions options = CertExportOptions.from(new CertExportRequest(format, null, null))) {
                assertThat(options.format().name()).isEqualTo(format);
                assertThat(options.format().includesPrivateKey()).isFalse();
                assertThat(options.password()).isNull();
            }
        }
    }

    @Test
    void pkcs12_acceptsPasswordAtBothLengthBounds() {
        try (CertExportOptions min = CertExportOptions.from(new CertExportRequest("PKCS12", "a".repeat(8), null));
             CertExportOptions max = CertExportOptions.from(new CertExportRequest("PKCS12", "b".repeat(128), true))) {
            assertThat(min.legacyPkcs12()).isFalse();
            assertThat(max.legacyPkcs12()).isTrue();
            assertThat(max.password()).hasSize(128);
        }
    }

    @Test
    void pkcs12_rejectsMissingShortLongOrControlCharacterPasswords() {
        assertInvalid(new CertExportRequest("PKCS12", null, null));
        assertInvalid(new CertExportRequest("PKCS12", "a".repeat(7), null));
        assertInvalid(new CertExportRequest("PKCS12", "a".repeat(129), null));
        assertInvalid(new CertExportRequest("PKCS12", "abcdefgh\n", null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"pässwordx", "€€€€€€€€", "abcdefg\uD83D\uDE00", "abcdefgh\u00A0", "abcdefgh\u007F"})
    void pkcs12_rejectsCharactersOutsidePrintableAscii_withAPlainExplanation(String password) {
        assertThatThrownBy(() -> CertExportOptions.from(new CertExportRequest("PKCS12", password, null)))
                .isInstanceOfSatisfying(CertExportException.class, e -> {
                    assertThat(e.getCode()).isEqualTo(CertExportException.INVALID_EXPORT_REQUEST);
                    assertThat(e.getMessage()).isEqualTo("Use letters, numbers and standard symbols only "
                            + "(no accents or emoji) — some servers can't open files protected with other characters.");
                });
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void pkcs12_passwordUsingTheWholePrintableRange_opensWithTheJdkKeyStore(boolean legacy) throws Exception {
        StringBuilder everyPrintable = new StringBuilder();
        for (char c = 0x20; c <= 0x7E; c++) {
            everyPrintable.append(c);
        }
        String password = everyPrintable.toString();
        CertExportTestMaterial.Chain chain = CertExportTestMaterial.chainFor("example.com",
                CertExportTestMaterial.RSA_LEAF_KEYS);
        AgentCertificateBundle bundle = AgentCertificateBundleParser.parse(CertExportTestMaterial.agentBundle(chain, true));

        byte[] pfx;
        try (CertExportOptions options = CertExportOptions.from(new CertExportRequest("PKCS12", password, legacy))) {
            pfx = CertExportFileRenderer.render(bundle, options, "example.com");
        }

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new ByteArrayInputStream(pfx), password.toCharArray());
        assertThat(keyStore.getKey("example.com", password.toCharArray())).isNotNull();
    }

    @Test
    void rejectsMissingOrUnknownFormat() {
        assertInvalid(null);
        assertInvalid(new CertExportRequest(null, null, null));
        assertInvalid(new CertExportRequest("pkcs12", "abcdefgh", null));
        assertInvalid(new CertExportRequest("DER", null, null));
    }

    @Test
    void close_wipesThePassword() {
        CertExportOptions options = CertExportOptions.from(new CertExportRequest("PKCS12", "s3cret-pass", false));
        char[] password = options.password();

        options.close();

        assertThat(password).containsOnly('\0');
    }

    @Test
    void validationMessagesAndRequestToString_neverEchoThePassword() {
        String password = "hunter2\u0007-secret";
        assertThatThrownBy(() -> CertExportOptions.from(new CertExportRequest("PKCS12", password, null)))
                .isInstanceOf(CertExportException.class)
                .message().doesNotContain(password);
        assertThat(new CertExportRequest("PKCS12", password, null).toString()).doesNotContain(password);
    }

    private static void assertInvalid(CertExportRequest request) {
        assertThatThrownBy(() -> CertExportOptions.from(request))
                .isInstanceOfSatisfying(CertExportException.class, e -> {
                    assertThat(e.getCode()).isEqualTo(CertExportException.INVALID_EXPORT_REQUEST);
                    assertThat(e.getStatus().value()).isEqualTo(400);
                });
    }
}
