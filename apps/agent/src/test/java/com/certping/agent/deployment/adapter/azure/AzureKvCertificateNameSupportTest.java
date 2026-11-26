// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AzureKvCertificateNameSupportTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    // ---- resolveCertificateName ----

    @Test
    void resolveCertificateName_configJsonWithCertificateName_returnsThatName() {
        String result = AzureKvCertificateNameSupport.resolveCertificateName(
                objectMapper, "api.example.com", "xref-1", "{\"certificateName\":\"my-cert\"}");
        assertThat(result).isEqualTo("my-cert");
    }

    @Test
    void resolveCertificateName_configJsonMissingCertificateName_throwsPermanent() {
        assertThatThrownBy(() -> AzureKvCertificateNameSupport.resolveCertificateName(
                objectMapper, "api.example.com", "xref-1", "{}"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CERT_NAME_INVALID"));
    }

    @Test
    void resolveCertificateName_configJsonWithBlankCertificateName_throwsPermanent() {
        assertThatThrownBy(() -> AzureKvCertificateNameSupport.resolveCertificateName(
                objectMapper, "api.example.com", "xref-1", "{\"certificateName\":\"\"}"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void resolveCertificateName_nullConfigJson_derivesFromDomain() {
        String result = AzureKvCertificateNameSupport.resolveCertificateName(
                objectMapper, "api.example.com", "xref-1", null);
        assertThat(result).isNotBlank();
    }

    @Test
    void resolveCertificateName_blankConfigJson_derivesFromDomain() {
        String result = AzureKvCertificateNameSupport.resolveCertificateName(
                objectMapper, "api.example.com", "xref-1", "   ");
        assertThat(result).isNotBlank();
    }

    @Test
    void resolveCertificateName_blankDomainAndNoConfig_throwsPermanent() {
        assertThatThrownBy(() -> AzureKvCertificateNameSupport.resolveCertificateName(
                objectMapper, "", "xref-1", null))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CERT_NAME_INVALID"));
    }

    @Test
    void resolveCertificateName_invalidConfigJson_throwsPermanent() {
        // parseCertificateName returns null for invalid JSON, then resolveCertificateName
        // sees null name and throws.
        assertThatThrownBy(() -> AzureKvCertificateNameSupport.resolveCertificateName(
                objectMapper, "api.example.com", "xref-1", "not-valid-json"))
                .isInstanceOf(PermanentAgentException.class);
    }

    // ---- parseCertificateName ----

    @Test
    void parseCertificateName_validJson_returnsName() {
        String result = AzureKvCertificateNameSupport.parseCertificateName(
                objectMapper, "{\"certificateName\":\"my-cert\"}");
        assertThat(result).isEqualTo("my-cert");
    }

    @Test
    void parseCertificateName_jsonWithoutField_returnsNull() {
        String result = AzureKvCertificateNameSupport.parseCertificateName(
                objectMapper, "{\"otherField\":\"value\"}");
        assertThat(result).isNull();
    }

    @Test
    void parseCertificateName_invalidJson_returnsNull() {
        // Falls through catch — logs warning and returns null
        String result = AzureKvCertificateNameSupport.parseCertificateName(
                objectMapper, "not-valid-json");
        assertThat(result).isNull();
    }

    // ---- toCertificateNameJson ----

    @Test
    void toCertificateNameJson_serializesCertName() {
        String result = AzureKvCertificateNameSupport.toCertificateNameJson(objectMapper, "my-cert");
        assertThat(result).isEqualTo("{\"certificateName\":\"my-cert\"}");
    }

    @Test
    void toCertificateNameJson_anotherName_serializesCorrectly() {
        String result = AzureKvCertificateNameSupport.toCertificateNameJson(objectMapper, "another-cert-name");
        assertThat(result).contains("\"certificateName\"").contains("another-cert-name");
    }
}
