// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.exception.BadRequestException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Full-branch coverage for {@link KubernetesDeploymentConfigValidator}. */
class KubernetesDeploymentConfigValidatorTest {

    private final KubernetesDeploymentConfigValidator validator =
            new KubernetesDeploymentConfigValidator(JsonMapper.builderWithJackson2Defaults().build());

    private void validate(String json) {
        validator.validateForProvider("KUBERNETES_SECRETS", json);
    }

    @Test
    void nonKubernetesProvider_skipsValidation() {
        assertThatCode(() -> validator.validateForProvider("AZURE_KV", null)).doesNotThrowAnyException();
        assertThatCode(() -> validator.validateForProvider("AZURE_KV", "garbage")).doesNotThrowAnyException();
    }

    @Test
    void validConfig_withNamespaceArray_passes() {
        assertThatCode(() -> validate(
                "{\"authMethod\":\"AWS\",\"clusterName\":\"prod\",\"namespaces\":[\"dev\",\"prod\"]}"))
                .doesNotThrowAnyException();
    }

    @Test
    void validConfig_withAllNamespacesString_passes() {
        assertThatCode(() -> validate(
                "{\"authMethod\":\"AZURE\",\"clusterName\":\"prod\",\"namespaces\":\"all_namespaces\"}"))
                .doesNotThrowAnyException();
    }

    @Test
    void nullOrBlankConfig_throws() {
        assertThatThrownBy(() -> validate(null)).isInstanceOf(BadRequestException.class).hasMessageContaining("required");
        assertThatThrownBy(() -> validate("   ")).isInstanceOf(BadRequestException.class);
    }

    @Test
    void invalidJson_throws() {
        assertThatThrownBy(() -> validate("{not-json")).isInstanceOf(BadRequestException.class)
                .hasMessageContaining("valid JSON");
    }

    @Test
    void emptyObject_throws() {
        assertThatThrownBy(() -> validate("{}")).isInstanceOf(BadRequestException.class)
                .hasMessageContaining("non-empty");
    }

    @Test
    void unsupportedKey_throws() {
        assertThatThrownBy(() -> validate(
                "{\"authMethod\":\"AWS\",\"clusterName\":\"p\",\"namespaces\":[\"d\"],\"extra\":1}"))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("unsupported key");
    }

    @Test
    void missingOrNonStringAuthMethod_throws() {
        assertThatThrownBy(() -> validate("{\"clusterName\":\"p\",\"namespaces\":[\"d\"]}"))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("authMethod");
        assertThatThrownBy(() -> validate(
                "{\"authMethod\":123,\"clusterName\":\"p\",\"namespaces\":[\"d\"]}"))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("authMethod");
    }

    @Test
    void disallowedAuthMethod_throws() {
        assertThatThrownBy(() -> validate(
                "{\"authMethod\":\"VAULT\",\"clusterName\":\"p\",\"namespaces\":[\"d\"]}"))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("must be one of");
    }

    @Test
    void missingOrBlankClusterName_throws() {
        assertThatThrownBy(() -> validate(
                "{\"authMethod\":\"AWS\",\"clusterName\":\"  \",\"namespaces\":[\"d\"]}"))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("clusterName");
        assertThatThrownBy(() -> validate(
                "{\"authMethod\":\"AWS\",\"namespaces\":[\"d\"]}"))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("clusterName");
    }

    @Test
    void namespacesStringNotAllNamespaces_throws() {
        assertThatThrownBy(() -> validate(
                "{\"authMethod\":\"AWS\",\"clusterName\":\"p\",\"namespaces\":\"some\"}"))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("all_namespaces");
    }

    @Test
    void namespacesNotArrayOrEmpty_throws() {
        assertThatThrownBy(() -> validate(
                "{\"authMethod\":\"AWS\",\"clusterName\":\"p\",\"namespaces\":123}"))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("non-empty array");
        assertThatThrownBy(() -> validate(
                "{\"authMethod\":\"AWS\",\"clusterName\":\"p\",\"namespaces\":[]}"))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void namespacesArrayWithNonStringOrBlank_throws() {
        assertThatThrownBy(() -> validate(
                "{\"authMethod\":\"AWS\",\"clusterName\":\"p\",\"namespaces\":[\"dev\",\"\"]}"))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("non-empty strings");
        assertThatThrownBy(() -> validate(
                "{\"authMethod\":\"AWS\",\"clusterName\":\"p\",\"namespaces\":[1,2]}"))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void namespacesArrayWithDuplicates_throws() {
        assertThatThrownBy(() -> validate(
                "{\"authMethod\":\"AWS\",\"clusterName\":\"p\",\"namespaces\":[\"dev\",\"dev\"]}"))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("duplicates");
    }
}
