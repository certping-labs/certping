// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SignInFailuresProviderRefusalTest {

    @Test
    void accessDeniedIsACancellationForEveryProvider() {
        for (String provider : new String[] {"google", "github", "microsoft", "linkedin"}) {
            assertThat(SignInFailures.providerRefusalReason(provider, "access_denied"))
                    .as(provider).isEqualTo(SignInFailures.SIGN_IN_CANCELLED);
        }
        assertThat(SignInFailures.providerRefusalReason("google", " ACCESS_DENIED "))
                .isEqualTo(SignInFailures.SIGN_IN_CANCELLED);
    }

    @Test
    void microsoftsConsentCodesAreACancellationOnlyForMicrosoft() {
        assertThat(SignInFailures.providerRefusalReason("microsoft", "consent_required"))
                .isEqualTo(SignInFailures.SIGN_IN_CANCELLED);
        assertThat(SignInFailures.providerRefusalReason("microsoft", "user_cancelled"))
                .isEqualTo(SignInFailures.SIGN_IN_CANCELLED);
        assertThat(SignInFailures.providerRefusalReason("google", "consent_required"))
                .isEqualTo(SignInFailures.SSO_REJECTED);
    }

    @Test
    void anythingElseIsTheProviderRejectingTheSignIn() {
        assertThat(SignInFailures.providerRefusalReason("google", "server_error")).isEqualTo(SignInFailures.SSO_REJECTED);
        assertThat(SignInFailures.providerRefusalReason("google", null)).isEqualTo(SignInFailures.SSO_REJECTED);
        assertThat(SignInFailures.providerRefusalReason("microsoft", "access_denied\nAUTH_EVENT forged"))
                .as("free text never matches").isEqualTo(SignInFailures.SSO_REJECTED);
    }

    @Test
    void cancelledIsASignInReasonWithItsOwnSentence() {
        assertThat(SignInFailures.REASONS).contains(SignInFailures.SIGN_IN_CANCELLED);
        assertThat(SignInFailures.SIGN_IN_CANCELLED.message(null)).isEqualTo("Sign-in was cancelled.");
    }
}
