// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.audit.AuditReason;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

public class SignInFailureRedirectTest {

    private static final String FRONTEND = "https://certping.example.com/auth/callback";

    /** The query as the browser's URLSearchParams would read it: decoded, every value per key. */
    public static MultiValueMap<String, String> query(String url) {
        MultiValueMap<String, String> raw = UriComponentsBuilder.fromUriString(url).build().getQueryParams();
        MultiValueMap<String, String> decoded = new org.springframework.util.LinkedMultiValueMap<>();
        raw.forEach((key, values) -> values.forEach(value -> decoded.add(UriUtils.decode(key, StandardCharsets.UTF_8),
                value == null ? null : UriUtils.decode(value, StandardCharsets.UTF_8))));
        return decoded;
    }

    @Test
    void everySignInReasonIsPassedThroughWithTheRequestId() {
        for (AuditReason reason : SignInFailures.REASONS) {
            String url = SignInFailureRedirect.url(FRONTEND, "Sign-in failed.", reason, "req-http-1234");

            MultiValueMap<String, String> query = query(url);
            assertThat(url).startsWith(FRONTEND + "?");
            assertThat(query.get("error")).containsExactly("authentication_failed");
            assertThat(query.get("message")).containsExactly("Sign-in failed.");
            assertThat(query.get("reason")).containsExactly(reason.code());
            assertThat(query.get("ref")).containsExactly("req-http-1234");
        }
    }

    @Test
    void aReasonOutsideTheSignInListIsLeftOut() {
        assertThat(query(SignInFailureRedirect.url(FRONTEND, "m", AuditReason.INTERNAL_ERROR, "req-1")))
                .doesNotContainKey("reason").containsKey("ref");
        assertThat(query(SignInFailureRedirect.url(FRONTEND, "m", AuditReason.of("INVALID_INPUT"), "req-1")))
                .doesNotContainKey("reason");
        assertThat(query(SignInFailureRedirect.url(FRONTEND, "m", null, "req-1"))).doesNotContainKey("reason");
    }

    @ParameterizedTest
    @ValueSource(strings = {"unknown", "", " ", "<script>alert(1)</script>", "a&reason=SSO_MISCONFIGURED",
            "line\nbreak", "has space", "javascript:alert(1)//\"'"})
    void aRequestIdThatIsNotAPlainTokenIsLeftOut(String requestId) {
        assertThat(query(SignInFailureRedirect.url(FRONTEND, "m", SignInFailures.SSO_REJECTED, requestId)))
                .doesNotContainKey("ref");
    }

    @Test
    void anOverlongOrMissingRequestIdIsLeftOut() {
        assertThat(query(SignInFailureRedirect.url(FRONTEND, "m", SignInFailures.SSO_REJECTED, "r".repeat(129))))
                .doesNotContainKey("ref");
        assertThat(query(SignInFailureRedirect.url(FRONTEND, "m", SignInFailures.SSO_REJECTED, null)))
                .doesNotContainKey("ref");
    }

    @Test
    void aProvidersFreeTextMessageIsEncodedAndCannotAddOrOverrideParameters() {
        String hostile = "denied&reason=SSO_MISCONFIGURED&ref=evil&token=stolen#frag <b>x</b> 100% + {x}";

        String url = SignInFailureRedirect.url(FRONTEND, hostile, SignInFailures.SSO_REJECTED, "req-http-1");

        MultiValueMap<String, String> query = query(url);
        assertThat(query.get("message")).containsExactly(hostile);
        assertThat(query.get("reason")).containsExactly("SSO_REJECTED");
        assertThat(query.get("ref")).containsExactly("req-http-1");
        assertThat(query).doesNotContainKey("token");
        assertThat(url).doesNotContain("#").doesNotContain(" ").doesNotContain("<");
    }

    @Test
    void aNullMessageIsSentEmpty() {
        assertThat(query(SignInFailureRedirect.url(FRONTEND, null, null, null)).get("message")).containsExactly("");
    }
}
