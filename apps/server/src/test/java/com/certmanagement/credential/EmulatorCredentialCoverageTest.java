// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.credential;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenRequestContext;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;

class EmulatorCredentialCoverageTest {

    @Test
    void getTokenReturnsDummyJwt() {
        EmulatorCredential cred = new EmulatorCredential();
        AccessToken token = cred.getToken(new TokenRequestContext().addScopes("https://vault.azure.net/.default")).block();
        assertThat(token).isNotNull();
        assertThat(token.getToken()).contains(".");
        assertThat(token.getToken().split("\\.")).hasSize(3);
        assertThat(token.getExpiresAt()).isAfter(OffsetDateTime.now());
    }
}
