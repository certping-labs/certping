// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GcpDeploymentAuthHelperTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private static final String CTX = "TEST_GCP";

    // ---- parseCredential ----

    @Test
    void parseCredential_validJson_returnsParsedObject() {
        SimplePojo result = GcpDeploymentAuthHelper.parseCredential(
                objectMapper, "{\"value\":\"abc\"}", SimplePojo.class, CTX);
        assertThat(result.getValue()).isEqualTo("abc");
    }

    @Test
    void parseCredential_invalidJson_throwsPermanentCredentialInvalid() {
        assertThatThrownBy(() -> GcpDeploymentAuthHelper.parseCredential(
                objectMapper, "not-valid-json", SimplePojo.class, CTX))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    // ---- requireField ----

    @Test
    void requireField_nonBlankValue_doesNotThrow() {
        assertThatNoException().isThrownBy(() ->
                GcpDeploymentAuthHelper.requireField("name", "value", CTX));
    }

    @Test
    void requireField_nullValue_throwsPermanent() {
        assertThatThrownBy(() -> GcpDeploymentAuthHelper.requireField("name", null, CTX))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("name");
    }

    @Test
    void requireField_blankValue_throwsPermanent() {
        assertThatThrownBy(() -> GcpDeploymentAuthHelper.requireField("name", "   ", CTX))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("name");
    }

    // ---- buildCredentials ----

    @Test
    void buildCredentials_invalidServiceAccountJson_throwsAuthFailed() {
        assertThatThrownBy(() -> GcpDeploymentAuthHelper.buildCredentials(
                "not-valid-google-service-account-json", null, CTX))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_GCP_AUTH_FAILED"));
    }

    @Test
    void buildCredentials_invalidBase64_throwsCredentialInvalid() {
        // "===" is not valid base64
        assertThatThrownBy(() -> GcpDeploymentAuthHelper.buildCredentials(
                null, "this is not @@valid base64!!!", CTX))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    @Test
    void buildCredentials_validBase64ButInvalidServiceAccountJson_throwsAuthFailed() {
        // Valid base64 but the decoded content isn't a service account JSON
        String validBase64InvalidJson = java.util.Base64.getEncoder().encodeToString("not-valid-sa-json".getBytes());
        assertThatThrownBy(() -> GcpDeploymentAuthHelper.buildCredentials(
                null, validBase64InvalidJson, CTX))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_GCP_AUTH_FAILED"));
    }

    // Note: behaviour with both inputs blank/null intentionally NOT tested here — it falls through to
    // GoogleCredentials.getApplicationDefault(), which is environment-dependent (succeeds on GCP/GCE
    // runners with ADC configured, throws on local dev machines without ADC). Asserting either outcome
    // would be flaky; the resolveServiceAccountBytes branch coverage is exercised by the explicit
    // serviceAccountJson and serviceAccountJsonBase64 tests above.

    // ---- CLOUD_PLATFORM_SCOPE constant ----

    @Test
    void cloudPlatformScopeConstant_isExpectedUrl() {
        assertThat(GcpDeploymentAuthHelper.CLOUD_PLATFORM_SCOPE)
                .isEqualTo("https://www.googleapis.com/auth/cloud-platform");
    }

    // POJO for parseCredential test
    public static class SimplePojo {
        private String value;
        public String getValue() { return value; }
        public void setValue(String value) { this.value = value; }
    }
}
