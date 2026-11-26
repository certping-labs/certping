// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.validation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class HttpsUrlValidatorTest {

    private final HttpsUrlValidator validator = new HttpsUrlValidator();

    @ParameterizedTest
    @ValueSource(strings = {
            "https://maps.example.com/place/Acme+Ltd",
            "HTTPS://cdn.example.com/logo.png",
            " https://www.example.org/people/jane-smith.html "
    })
    void acceptsHttpsUrlsWithAHost(String url) {
        assertThat(validator.isValid(url, null)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://example.com/logo.png",
            "javascript:alert(1)",
            "data:image/png;base64,AAAA",
            "//example.com/logo.png",
            "https:///no-host",
            "https://user:pass@example.com/",
            "https://exa mple.com/",
            "example.com"
    })
    void rejectsAnythingThatIsNotAnHttpsUrlWithAHost(String url) {
        assertThat(validator.isValid(url, null)).isFalse();
    }

    @Test
    void leavesNullAndBlankToOtherConstraints() {
        assertThat(validator.isValid(null, null)).isTrue();
        assertThat(validator.isValid("  ", null)).isTrue();
    }
}
