// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator.scope;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.certmanagement.exception.BadRequestException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.util.Set;
import org.junit.jupiter.api.Test;

class ScopeValidationUtilsTest {

    private static final ObjectMapper MAPPER = JsonMapper.builderWithJackson2Defaults().build();

    private JsonNode json(String raw) {
        try {
            return MAPPER.readTree(raw);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void requireObject_acceptsObject() {
        ScopeValidationUtils.requireObject(json("{\"a\":1}"), "AWS");
    }

    @Test
    void requireObject_nullNode_throws() {
        assertThatThrownBy(() -> ScopeValidationUtils.requireObject(null, "AWS"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("configJson is required");
    }

    @Test
    void requireObject_jsonNull_throws() {
        assertThatThrownBy(() -> ScopeValidationUtils.requireObject(json("null"), "AWS"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("is required");
    }

    @Test
    void requireObject_nonObject_throws() {
        assertThatThrownBy(() -> ScopeValidationUtils.requireObject(json("[1,2]"), "AWS"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("must be a JSON object");
    }

    @Test
    void requireString_returnsTrimmedValue() {
        assertThat(ScopeValidationUtils.requireString(json("{\"f\":\"  hi  \"}"), "f", "AWS"))
                .isEqualTo("hi");
    }

    @Test
    void requireString_missing_throws() {
        assertThatThrownBy(() -> ScopeValidationUtils.requireString(json("{}"), "f", "AWS"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("missing required string field: f");
    }

    @Test
    void requireString_blank_throws() {
        assertThatThrownBy(() -> ScopeValidationUtils.requireString(json("{\"f\":\"  \"}"), "f", "AWS"))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void requireString_nonTextual_throws() {
        assertThatThrownBy(() -> ScopeValidationUtils.requireString(json("{\"f\":123}"), "f", "AWS"))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void optionalString_variants() {
        assertThat(ScopeValidationUtils.optionalString(json("{\"f\":\" x \"}"), "f")).isEqualTo("x");
        assertThat(ScopeValidationUtils.optionalString(json("{}"), "f")).isNull();
        assertThat(ScopeValidationUtils.optionalString(json("{\"f\":null}"), "f")).isNull();
        assertThat(ScopeValidationUtils.optionalString(json("{\"f\":5}"), "f")).isNull();
        assertThat(ScopeValidationUtils.optionalString(json("{\"f\":\"  \"}"), "f")).isNull();
    }

    @Test
    void requireOneOf_acceptsAllowed_andRejectsOthers() {
        Set<String> allowed = Set.of("A", "B");
        assertThat(ScopeValidationUtils.requireOneOf(json("{\"f\":\"A\"}"), "f", allowed, "AWS"))
                .isEqualTo("A");
        assertThatThrownBy(() -> ScopeValidationUtils.requireOneOf(
                json("{\"f\":\"C\"}"), "f", allowed, "AWS"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("must be one of");
    }

    @Test
    void optionalOneOf_variants() {
        Set<String> allowed = Set.of("A", "B");
        assertThat(ScopeValidationUtils.optionalOneOf(json("{}"), "f", allowed, "AWS")).isNull();
        assertThat(ScopeValidationUtils.optionalOneOf(json("{\"f\":\"B\"}"), "f", allowed, "AWS"))
                .isEqualTo("B");
        assertThatThrownBy(() -> ScopeValidationUtils.optionalOneOf(
                json("{\"f\":\"C\"}"), "f", allowed, "AWS"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("when present");
    }

    @Test
    void requireNonEmptyArray_acceptsValid() {
        ScopeValidationUtils.requireNonEmptyArray(json("{\"f\":[\"a\",\"b\"]}"), "f", "AWS");
    }

    @Test
    void requireNonEmptyArray_missingOrEmpty_throws() {
        assertThatThrownBy(() -> ScopeValidationUtils.requireNonEmptyArray(json("{}"), "f", "AWS"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("non-empty array");
        assertThatThrownBy(() -> ScopeValidationUtils.requireNonEmptyArray(
                json("{\"f\":[]}"), "f", "AWS"))
                .isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> ScopeValidationUtils.requireNonEmptyArray(
                json("{\"f\":\"x\"}"), "f", "AWS"))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void requireNonEmptyArray_blankElement_throws() {
        assertThatThrownBy(() -> ScopeValidationUtils.requireNonEmptyArray(
                json("{\"f\":[\"a\",\"  \"]}"), "f", "AWS"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("[1] must be a non-blank string");
    }

    @Test
    void requireNonEmptyArray_nonTextualElement_throws() {
        assertThatThrownBy(() -> ScopeValidationUtils.requireNonEmptyArray(
                json("{\"f\":[1]}"), "f", "AWS"))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void optionalInt_variants() {
        assertThat(ScopeValidationUtils.optionalInt(json("{\"f\":7}"), "f", "AWS")).isEqualTo(7);
        assertThat(ScopeValidationUtils.optionalInt(json("{}"), "f", "AWS")).isNull();
        assertThat(ScopeValidationUtils.optionalInt(json("{\"f\":null}"), "f", "AWS")).isNull();
        assertThatThrownBy(() -> ScopeValidationUtils.optionalInt(
                json("{\"f\":\"x\"}"), "f", "AWS"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("must be an integer");
    }

    @Test
    void optionalBoolean_variants() {
        assertThat(ScopeValidationUtils.optionalBoolean(json("{\"f\":true}"), "f", "AWS")).isTrue();
        assertThat(ScopeValidationUtils.optionalBoolean(json("{}"), "f", "AWS")).isNull();
        assertThat(ScopeValidationUtils.optionalBoolean(json("{\"f\":null}"), "f", "AWS")).isNull();
        assertThatThrownBy(() -> ScopeValidationUtils.optionalBoolean(
                json("{\"f\":\"x\"}"), "f", "AWS"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("must be a boolean");
    }
}
