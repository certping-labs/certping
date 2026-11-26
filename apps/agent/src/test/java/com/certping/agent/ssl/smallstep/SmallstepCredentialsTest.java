// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.smallstep;

import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SmallstepCredentialsTest {
    private final ObjectMapper mapper = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void parsesObjectJwkAndNormalizesTrailingSlash() {
        SmallstepCredentials credential = SmallstepCredentials.parse("""
                {
                  "baseUrl": "https://step.internal/",
                  "authorityName": "Device CA",
                  "provisionerName": "certping-agent",
                  "provisionerPrivateJwk": {"kty":"EC","crv":"P-256","d":"secret"},
                  "rootCaPem": "-----BEGIN CERTIFICATE-----\\nroot\\n-----END CERTIFICATE-----"
                }
                """, mapper, null);

        assertThat(credential.baseUrl()).isEqualTo("https://step.internal");
        assertThat(credential.provisionerPrivateJwk()).contains("\"kty\":\"EC\"");
        assertThat(credential.toString()).doesNotContain("\"d\":\"secret\"", "BEGIN CERTIFICATE");
    }

    @Test
    void rejectsPlainHttpAndMissingSecretFields() {
        assertThatThrownBy(() -> SmallstepCredentials.parse("""
                {"baseUrl":"http://step.internal","provisionerName":"p",
                 "provisionerPrivateJwk":"{}","rootCaPem":"root"}
                """, mapper, null))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("HTTPS");

        assertThatThrownBy(() -> SmallstepCredentials.parse("{}", mapper, null))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("baseUrl");
    }
}
