// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.kubernetes;

import com.certping.agent.exception.PermanentAgentException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KubernetesAuthProviderTest {

    @Test
    void fromConfigValue_acceptsTrimmedCaseInsensitiveValue() {
        assertThat(KubernetesAuthProvider.fromConfigValue("  sa_token "))
                .isEqualTo(KubernetesAuthProvider.SA_TOKEN);
    }

    @Test
    void fromConfigValue_blank_throwsPermanent() {
        assertThatThrownBy(() -> KubernetesAuthProvider.fromConfigValue("  "))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void fromConfigValue_unsupported_throwsPermanent() {
        assertThatThrownBy(() -> KubernetesAuthProvider.fromConfigValue("AKS"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_K8S_CONFIG_INVALID"));
    }

    @Test
    void errorSanitizer_redactAndBound_truncatesLongStrings() {
        String huge = "a".repeat(2000);
        String result = invokeRedactAndBound(huge);
        assertThat(result).endsWith("...");
        assertThat(result.length()).isLessThanOrEqualTo(515);
    }

    @Test
    void errorSanitizer_redactAndBound_redactsTokenField() {
        String body = "{\"token\":\"super-secret\",\"message\":\"x\"}";
        String result = invokeRedactAndBound(body);
        assertThat(result).doesNotContain("super-secret");
        assertThat(result).contains("[REDACTED]");
    }

    @Test
    void errorSanitizer_redactAndBound_emptyReturnsPlaceholder() {
        assertThat(invokeRedactAndBound("")).isEqualTo("<empty>");
        assertThat(invokeRedactAndBound(null)).isEqualTo("<empty>");
        assertThat(invokeRedactAndBound("   ")).isEqualTo("<empty>");
    }

    private static String invokeRedactAndBound(String input) {
        try {
            var m = Class.forName("com.certping.agent.deployment.adapter.kubernetes.KubernetesErrorSanitizer")
                    .getDeclaredMethod("redactAndBound", String.class);
            m.setAccessible(true);
            return (String) m.invoke(null, input);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
