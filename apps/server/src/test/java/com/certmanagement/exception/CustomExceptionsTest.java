// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CustomExceptionsTest {

    @Test
    void badRequest_messageAndCause() {
        assertThat(new BadRequestException("b").getMessage()).isEqualTo("b");
        Throwable c = new RuntimeException();
        assertThat(new BadRequestException("b2", c).getCause()).isSameAs(c);
    }

    @Test
    void duplicateResource_messageAndCause() {
        assertThat(new DuplicateResourceException("d").getMessage()).isEqualTo("d");
        Throwable c = new RuntimeException();
        assertThat(new DuplicateResourceException("d2", c).getCause()).isSameAs(c);
    }

    @Test
    void featureDisabled_defaultCtorBuildsMessageAndCode() {
        FeatureDisabledException ex = new FeatureDisabledException("FEAT");
        assertThat(ex.getFeatureKey()).isEqualTo("FEAT");
        assertThat(ex.getCode()).isEqualTo("FEATURE_DISABLED");
        assertThat(ex.getMessage()).contains("FEAT").contains("disabled");
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', quoteCharacter = '"', value = {
            "CERTIFICATE_RENEWAL|Automatic renewal isn't available. Ask your CertPing administrator.",
            "DNS_CREDENTIALS|DNS credentials aren't available. Ask your CertPing administrator.",
            "INTEGRATIONS|Integrations aren't available. Ask your CertPing administrator.",
            "FEATURE_FLAGS_PAGE|Feature flags aren't available. Ask your CertPing administrator."})
    void featuresOnlyCertpingDecides_sayGenericallyThatTheyArentAvailable(String featureKey, String message) {
        FeatureDisabledException ex = new FeatureDisabledException(featureKey);

        assertThat(ex.getCode()).isEqualTo("FEATURE_DISABLED");
        assertThat(ex.getMessage()).isEqualTo(message).doesNotContain("workspace").doesNotContain("organization");
    }

    @Test
    void featureDisabled_customCtor() {
        FeatureDisabledException ex = new FeatureDisabledException("FEAT", "CODE", "msg");
        assertThat(ex.getFeatureKey()).isEqualTo("FEAT");
        assertThat(ex.getCode()).isEqualTo("CODE");
        assertThat(ex.getMessage()).isEqualTo("msg");
    }

    @Test
    void forbidden_messageAndCause() {
        assertThat(new ForbiddenException("f").getMessage()).isEqualTo("f");
        Throwable c = new RuntimeException();
        assertThat(new ForbiddenException("f2", c).getCause()).isSameAs(c);
    }

    @Test
    void resourceNotFound_messageAndCause() {
        assertThat(new ResourceNotFoundException("r").getMessage()).isEqualTo("r");
        Throwable c = new RuntimeException();
        assertThat(new ResourceNotFoundException("r2", c).getCause()).isSameAs(c);
    }

    @Test
    void serviceUnavailable_messageAndCause() {
        assertThat(new ServiceUnavailableException("s").getMessage()).isEqualTo("s");
        Throwable c = new RuntimeException();
        assertThat(new ServiceUnavailableException("s2", c).getCause()).isSameAs(c);
    }

    @Test
    void ssoAuthentication_messageAndCause() {
        assertThat(new SsoAuthenticationException("s").getMessage()).isEqualTo("s");
        Throwable c = new RuntimeException();
        assertThat(new SsoAuthenticationException("s2", c).getCause()).isSameAs(c);
    }

    @Test
    void ssoValidation_messageAndCause() {
        assertThat(new SsoValidationException("s").getMessage()).isEqualTo("s");
        Throwable c = new RuntimeException();
        assertThat(new SsoValidationException("s2", c).getCause()).isSameAs(c);
    }

    @Test
    void unauthorized_messageAndCause() {
        assertThat(new UnauthorizedException("u").getMessage()).isEqualTo("u");
        Throwable c = new RuntimeException();
        assertThat(new UnauthorizedException("u2", c).getCause()).isSameAs(c);
    }

    @Test
    void unknownOrgForHeartbeat_message() {
        UnknownOrganizationForHeartbeatException ex = new UnknownOrganizationForHeartbeatException(42L);
        assertThat(ex.getOrganizationId()).isEqualTo(42L);
        assertThat(ex.getMessage()).contains("42");
    }
}
