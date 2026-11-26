// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.credential;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import reactor.core.publisher.Mono;

import java.time.OffsetDateTime;

/**
 * Token credential for local Key Vault emulator usage.
 */
public class EmulatorCredential implements TokenCredential {

    @Override
    public Mono<AccessToken> getToken(TokenRequestContext request) {
        String header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        String payload = "eyJzdWIiOiJlbXVsYXRvciIsImlhdCI6MTUxNjIzOTAyMn0";
        String signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        String dummyJwt = header + "." + payload + "." + signature;

        return Mono.just(new AccessToken(dummyJwt, OffsetDateTime.now().plusYears(1)));
    }
}
